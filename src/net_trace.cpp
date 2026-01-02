#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <atomic>
#include <unordered_map>
#include <algorithm>
#include <vector>
#include <utility>
#include <cstdarg>
#include <cstdio>
#include <mutex>

#include "net_trace.h"

#pragma comment(lib, "Psapi.lib")

static void log_line(const char* s)
{
    OutputDebugStringA(s);
    OutputDebugStringA("\n");
}

static void logf(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    log_line(buf);
}

// ----------- callsite stats -----------

struct CallStat
{
    uint64_t hits = 0;
    uint64_t bytes = 0;
    uint32_t firstSeenFrame = 0;
};

static std::atomic<bool> gInited{ false };
static std::atomic<uint32_t> gFrameId{ 0 };

static std::unordered_map<uintptr_t, CallStat> gCallerStats;
static std::mutex gCallerMtx;

static std::atomic<uint32_t> gRecvCallsThisFrame{ 0 };
static std::atomic<uint32_t> gRecvBytesThisFrame{ 0 };

static uintptr_t gWowBase = 0;
static uintptr_t gWowEnd = 0;

static bool gKeyDownPrev[256] = {};

static bool EdgePressed(int vk)
{
    SHORT down = GetAsyncKeyState(vk);
    bool isDown = (down & 0x8000) != 0;
    bool wasDown = gKeyDownPrev[vk];
    gKeyDownPrev[vk] = isDown;
    return isDown && !wasDown;
}

static void RefreshWowImageRange()
{
    HMODULE wow = GetModuleHandleW(L"wow.exe");
    if (!wow)
        return;

    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), wow, &mi, sizeof(mi)))
        return;

    gWowBase = (uintptr_t)mi.lpBaseOfDll;
    gWowEnd = gWowBase + (uintptr_t)mi.SizeOfImage;
}

static uintptr_t GetGameCallerEip()
{
    // Capture a small stack and choose the first return address that falls within wow.exe
    void* stack[16] = {};
    USHORT frames = RtlCaptureStackBackTrace(0, (ULONG)(sizeof(stack) / sizeof(stack[0])), stack, nullptr);

    for (USHORT i = 0; i < frames; i++)
    {
        uintptr_t ip = (uintptr_t)stack[i];
        if (ip >= gWowBase && ip < gWowEnd)
            return ip;
    }
    return 0;
}

void NetTrace::Init()
{
    if (gInited.exchange(true))
        return;

    RefreshWowImageRange();
    logf("[ClientFix][NET] .text = %08X..%08X", (unsigned)gWowBase, (unsigned)gWowEnd);
}

void NetTrace::RecordRecv(int nbytes, int /*flags*/)
{
    if (!gInited.load())
        NetTrace::Init();

    gRecvCallsThisFrame.fetch_add(1, std::memory_order_relaxed);
    gRecvBytesThisFrame.fetch_add((uint32_t)((nbytes > 0) ? nbytes : 0), std::memory_order_relaxed);

    uintptr_t caller = GetGameCallerEip();
    if (!caller)
        return;

    std::lock_guard<std::mutex> lk(gCallerMtx);
    auto& s = gCallerStats[caller];
    if (s.hits == 0)
        s.firstSeenFrame = gFrameId.load(std::memory_order_relaxed);
    s.hits++;
    if (nbytes > 0)
        s.bytes += (uint64_t)nbytes;
}

// ----------- WoW packet decode (3.3.5 header) -----------

struct SockStream
{
    std::vector<uint8_t> buf;
    size_t off = 0;
};

static std::unordered_map<uint64_t, SockStream> gStreams;
static std::mutex gStreamsMtx;

// Frames remaining where we print all decoded opcodes.
static std::atomic<int> gVerboseOpcodeFrames{ 0 };

static inline uint16_t ReadU16LE(const uint8_t* p)
{
    return (uint16_t)p[0] | (uint16_t)(p[1] << 8);
}

static void StreamCompact(SockStream& s)
{
    if (s.off == 0)
        return;

    if (s.off > 4096 || s.off > (s.buf.size() / 2))
    {
        s.buf.erase(s.buf.begin(), s.buf.begin() + (ptrdiff_t)s.off);
        s.off = 0;
    }
}

static void ParseWoWPackets_NoThrow(uint64_t sock, SockStream& s)
{
    while (true)
    {
        size_t avail = (s.buf.size() >= s.off) ? (s.buf.size() - s.off) : 0;
        if (avail < 4)
            break;

        const uint8_t* p = s.buf.data() + s.off;
        uint16_t size = ReadU16LE(p + 0);

        // Basic sanity. If this desyncs, slide one byte and retry.
        if (size < 2 || size > 0x7FFF)
        {
            s.off += 1;
            StreamCompact(s);
            continue;
        }

        size_t total = 2 + (size_t)size;
        if (avail < total)
            break;

        uint16_t opcode = ReadU16LE(p + 2);
        uint16_t payloadLen = (uint16_t)(size - 2);

        const uint32_t frame = gFrameId.load(std::memory_order_relaxed);
        const bool verbose = (gVerboseOpcodeFrames.load(std::memory_order_relaxed) > 0);

        if (verbose || opcode == 0x014A)
        {
            logf("[ClientFix][NETPK] frame=%u sock=0x%llX opcode=0x%04X payload=%u",
                 frame, (unsigned long long)sock, (unsigned)opcode, (unsigned)payloadLen);
        }

        s.off += total;
        StreamCompact(s);
    }
}

void NetTrace::RecordRecv(uint64_t sock, const uint8_t* data, int len, int flags)
{
    NetTrace::RecordRecv(len, flags);

    if (!data || len <= 0)
        return;

    std::lock_guard<std::mutex> lk(gStreamsMtx);
    SockStream& s = gStreams[sock];

    if (s.buf.size() > (8u * 1024u * 1024u))
    {
        s.buf.clear();
        s.off = 0;
    }

    s.buf.insert(s.buf.end(), data, data + len);
    ParseWoWPackets_NoThrow(sock, s);
}

uint32_t NetTrace::GetFrame()
{
    return gFrameId.load(std::memory_order_relaxed);
}

// ----------- frame boundary + dumps -----------

static void DumpTopCallers_Impl(int maxCount)
{
    std::vector<std::pair<uintptr_t, CallStat>> items;
    {
        std::lock_guard<std::mutex> lk(gCallerMtx);
        items.reserve(gCallerStats.size());
        for (auto& kv : gCallerStats)
            items.emplace_back(kv.first, kv.second);
    }

    std::sort(items.begin(), items.end(), [](auto& a, auto& b) {
        return a.second.hits > b.second.hits;
    });

    log_line("[ClientFix][NET] ---- TOP CALLERS (press F8 to dump) ----");
    int shown = 0;
    for (auto& it : items)
    {
        if (shown >= maxCount)
            break;
        logf("[ClientFix][NET] caller=%08X hits=%llu bytes=%llu firstSeenFrame=%u",
             (unsigned)it.first,
             (unsigned long long)it.second.hits,
             (unsigned long long)it.second.bytes,
             (unsigned)it.second.firstSeenFrame);
        shown++;
    }
}

void NetTrace::DumpTopCallers(int maxCount)
{
    DumpTopCallers_Impl(maxCount);
}

void NetTrace::OnFrameBoundary()
{
    if (!gInited.load())
        NetTrace::Init();

    uint32_t frame = gFrameId.fetch_add(1, std::memory_order_relaxed) + 1;

    uint32_t calls = gRecvCallsThisFrame.exchange(0, std::memory_order_relaxed);
    uint32_t bytes = gRecvBytesThisFrame.exchange(0, std::memory_order_relaxed);

    if (calls || bytes)
        logf("[ClientFix][NET] frame=%u recvCalls=%u bytes=%u", frame, calls, bytes);

    int v = gVerboseOpcodeFrames.load(std::memory_order_relaxed);
    if (v > 0)
        gVerboseOpcodeFrames.store(v - 1, std::memory_order_relaxed);

    if (EdgePressed(VK_F8))
        DumpTopCallers_Impl(20);

    if (EdgePressed(VK_F9))
    {
        std::lock_guard<std::mutex> lk(gCallerMtx);
        gCallerStats.clear();
        log_line("[ClientFix][NET] cleared caller stats");
    }

    if (EdgePressed(VK_F7))
    {
        gVerboseOpcodeFrames.store(600, std::memory_order_relaxed);
        log_line("[ClientFix][NET] verbose opcode logging enabled (~10s)");
    }
}
