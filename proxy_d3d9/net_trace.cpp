#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <atomic>
#include <unordered_map>
#include <algorithm>
#include <vector>
#include <utility>
#include <cstdarg>
#include <cstdio>     // vsnprintf

#pragma comment(lib, "Kernel32.lib")

// ---------------- logging ----------------
static void log_line(const char* s) { OutputDebugStringA(s); OutputDebugStringA("\n"); }
static void logf(const char* fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_line(buf);
}

// ---------------- main .text range (Wow.exe) ----------------
static uintptr_t gTextBeg = 0, gTextEnd = 0;

static void InitMainText() {
    HMODULE hExe = GetModuleHandleA(nullptr);
    if (!hExe) return;
    auto dos = (PIMAGE_DOS_HEADER)hExe;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)hExe + dos->e_lfanew);
    gTextBeg = (uintptr_t)hExe + nt->OptionalHeader.BaseOfCode;
    gTextEnd = gTextBeg + nt->OptionalHeader.SizeOfCode;
    logf("[ClientFix][NET] .text = %p..%p", (void*)gTextBeg, (void*)gTextEnd);
}
static inline bool InMainText(void* p) {
    uintptr_t x = (uintptr_t)p;
    return (x >= gTextBeg) && (x < gTextEnd);
}

// first stack frame inside Wow.exe .text
static uint32_t GetGameCallerEip() {
    void* frames[16] = {};
    USHORT n = RtlCaptureStackBackTrace(0, (USHORT)(sizeof(frames) / sizeof(frames[0])), frames, nullptr);
    for (USHORT i = 0; i < n; ++i) if (InMainText(frames[i]))
        return (uint32_t)(uintptr_t)frames[i];
    return (uint32_t)(uintptr_t)(n ? frames[0] : nullptr);
}

// ---------------- histogram + per-frame ----------------
struct Stat { uint32_t count = 0, firstSeenFrame = 0; };

static std::unordered_map<uint32_t, Stat> gHist;
static std::atomic<uint32_t> gFrameId{ 0 };
static std::atomic<uint32_t> gCallsThisFrame{ 0 };
static std::atomic<uint32_t> gBytesThisFrame{ 0 };

static bool EdgePressed(int vk) {
    static SHORT prev[256] = {};
    SHORT cur = GetAsyncKeyState(vk);
    bool pressed = (cur & 0x8000) && !(prev[vk] & 0x8000);
    prev[vk] = cur;
    return pressed;
}

// ---------------- public API ----------------
namespace NetTrace {

    void Init() {
        static bool once = false; if (once) return; once = true;
        InitMainText();
    }

    void RecordRecv(int nbytes, int /*flags*/) {
        if (nbytes <= 0) return;

        const uint32_t caller = GetGameCallerEip();
        auto& s = gHist[caller];
        if (s.count == 0) s.firstSeenFrame = gFrameId.load();
        s.count++;

        gCallsThisFrame.fetch_add(1);
        gBytesThisFrame.fetch_add((uint32_t)nbytes);
    }

    static void DumpTopInternal(int maxCount) {
        std::vector<std::pair<uint32_t, Stat>> v; v.reserve(gHist.size());
        for (auto& kv : gHist) v.push_back(kv);
        std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second.count > b.second.count; });

        log_line("[ClientFix][NET] ---- TOP CALLERS (press F8 to dump) ----");
        int shown = 0;
        for (auto& kv : v) {
            logf("[ClientFix][NET] caller=%08X hits=%u firstSeenFrame=%u",
                kv.first, kv.second.count, kv.second.firstSeenFrame);
            if (++shown >= maxCount) break;
        }
    }

    void DumpTopCallers(int maxCount) { DumpTopInternal(maxCount); }

    void OnFrameBoundary() {
        if (EdgePressed(VK_F8)) DumpTopInternal(20);

        const uint32_t id = gFrameId.load();
        const uint32_t calls = gCallsThisFrame.exchange(0);
        const uint32_t bytes = gBytesThisFrame.exchange(0);
        if (calls | bytes)
            logf("[ClientFix][NET] frame=%u recvCalls=%u bytes=%u", id, calls, bytes);

        gFrameId.fetch_add(1);
    }

} // namespace NetTrace
