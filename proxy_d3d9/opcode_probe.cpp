#include "opcode_probe.h"

#if !defined(_M_IX86)
#error Opcode probe is intended for Win32 (x86) builds only.
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#include <windows.h>
#include <Psapi.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <intrin.h>
#include <mutex>
#include <string>
#include <string_view>

#include "MinHook.h"
#include "fmt/format.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma intrinsic(_ReturnAddress)

namespace {

enum class ProbeMode {
    Off,
    Discover,
    Sender,
};

constexpr unsigned kSpiritHealerOpcode = 0x02E2;

std::once_flag g_initOnce;
ProbeMode g_mode = ProbeMode::Off;
HMODULE g_wowModule = nullptr;
std::uintptr_t g_wowBase = 0;
std::size_t g_wowSize = 0;
std::uint32_t g_senderRva = 0;

using WSASend_t = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
WSASend_t g_origWSASend = nullptr;

using Sender_t = int(__thiscall*)(void*, void*);
Sender_t g_origSender = nullptr;

struct HexString {
    std::string value;
};

HexString ToHex(std::uint64_t v, int width = 0) {
    char buf[32] = {};
    if (width > 0) {
        std::snprintf(buf, sizeof(buf), "%0*llX", width, static_cast<unsigned long long>(v));
    }
    else {
        std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
    }
    return { buf };
}

HexString ToHexLower(std::uint64_t v, int width = 0) {
    char buf[32] = {};
    if (width > 0) {
        std::snprintf(buf, sizeof(buf), "%0*llx", width, static_cast<unsigned long long>(v));
    }
    else {
        std::snprintf(buf, sizeof(buf), "%llx", static_cast<unsigned long long>(v));
    }
    return { buf };
}

void Trim(std::string& s) {
    auto isSpace = [](unsigned char c) { return std::isspace(c) != 0; };
    while (!s.empty() && isSpace(static_cast<unsigned char>(s.back()))) s.pop_back();
    std::size_t i = 0;
    while (i < s.size() && isSpace(static_cast<unsigned char>(s[i]))) ++i;
    if (i > 0) s.erase(0, i);
}

std::string ReadEnv(const char* name) {
    DWORD required = GetEnvironmentVariableA(name, nullptr, 0);
    if (required == 0) return {};
    std::string value(required, '\0');
    DWORD written = GetEnvironmentVariableA(name, value.data(), required);
    if (written == 0) return {};
    if (!value.empty() && value.back() == '\0') value.pop_back();
    value.resize(written);
    std::string copy = value;
    Trim(copy);
    return copy;
}

std::string ToLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

void Log(fmt::memory_buffer& buf) {
    auto text = fmt::to_string(buf);
    OutputDebugStringA(text.c_str());
}

void LogLine(std::string_view message) {
    fmt::memory_buffer buf;
    fmt::format_to(buf, "{}\n", message);
    Log(buf);
}

std::string DescribeAddress(void* address) {
    auto addr = reinterpret_cast<std::uintptr_t>(address);
    if (g_wowBase && addr >= g_wowBase && addr < (g_wowBase + g_wowSize)) {
        return fmt::format("wow+0x{}", ToHex(addr - g_wowBase, 6).value);
    }

    HMODULE mod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(address), &mod)) {
        char path[MAX_PATH] = {};
        if (GetModuleFileNameA(mod, path, MAX_PATH)) {
            const char* name = std::strrchr(path, '\\');
            if (!name) name = path;
            else ++name;
            return fmt::format("{}+0x{}", name, ToHex(addr - reinterpret_cast<std::uintptr_t>(mod), 6).value);
        }
    }

    return fmt::format("0x{}", ToHex(addr, 8).value);
}

void LogDiscoverStack() {
    constexpr USHORT kMaxFrames = 16;
    void* frames[kMaxFrames] = {};
    USHORT captured = CaptureStackBackTrace(0, kMaxFrames, frames, nullptr);
    if (captured == 0) return;

    fmt::memory_buffer buf;
    fmt::format_to(buf, "[OpcodeProbe][discover] WSASend stack:");
    USHORT start = captured > 1 ? 1 : 0;
    for (USHORT i = start; i < captured; ++i) {
        auto desc = DescribeAddress(frames[i]);
        fmt::format_to(buf, " {}", desc);
    }
    fmt::format_to(buf, "\n");
    Log(buf);
}

int WSAAPI hkWSASend(
    SOCKET s, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent,
    DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack();
    }
    return g_origWSASend ? g_origWSASend(s, buffers, bufferCount, bytesSent, flags, overlapped, completion) : SOCKET_ERROR;
}

void LogPacket(void* packet, void* caller) {
    if (!packet) return;
    auto base = reinterpret_cast<std::uint8_t*>(packet);

    std::uint8_t* storage = *reinterpret_cast<std::uint8_t**>(base);
    if (!storage) return;

    std::uint32_t writePos = *reinterpret_cast<std::uint32_t*>(base + 12);
    if (writePos < 4 || writePos > (1u << 16)) {
        return;
    }

    std::uint16_t opcode = *reinterpret_cast<std::uint16_t*>(storage + 2);
    std::string callerDesc = DescribeAddress(caller);

    fmt::memory_buffer buf;
    fmt::format_to(buf, "[OpcodeProbe][sender] opcode=0x{} len={} packet={} caller={}",
        ToHex(opcode, 4).value,
        writePos,
        ToHexLower(reinterpret_cast<std::uintptr_t>(packet), sizeof(void*) * 2).value,
        callerDesc);
    if (opcode == kSpiritHealerOpcode) {
        fmt::format_to(buf, " <<< CMSG_AREA_SPIRIT_HEALER_QUERY");
    }

    fmt::format_to(buf, "\n");
    Log(buf);
}

int __fastcall hkSender(void* self, void*, void* packet) {
    if (g_mode == ProbeMode::Sender) {
        void* caller = _ReturnAddress();
        LogPacket(packet, caller);
    }
    return g_origSender ? g_origSender(self, packet) : 0;
}

bool InstallDiscoverHook() {
    HMODULE ws2 = GetModuleHandleA("Ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("Ws2_32.dll");
    if (!ws2) {
        LogLine("[OpcodeProbe] Failed to load Ws2_32.dll");
        return false;
    }

    auto target = reinterpret_cast<LPVOID>(GetProcAddress(ws2, "WSASend"));
    if (!target) {
        LogLine("[OpcodeProbe] WSASend not found");
        return false;
    }

    if (MH_CreateHook(target, hkWSASend, reinterpret_cast<LPVOID*>(&g_origWSASend)) != MH_OK) {
        LogLine("[OpcodeProbe] MH_CreateHook failed for WSASend");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        LogLine("[OpcodeProbe] MH_EnableHook failed for WSASend");
        return false;
    }

    LogLine("[OpcodeProbe] Discover mode active (WSASend)");
    return true;
}

bool InstallSenderHook() {
    if (!g_senderRva || !g_wowBase) {
        LogLine("[OpcodeProbe] Sender RVA not configured");
        return false;
    }

    auto target = reinterpret_cast<void*>(g_wowBase + g_senderRva);
    if (MH_CreateHook(target, hkSender, reinterpret_cast<void**>(&g_origSender)) != MH_OK) {
        LogLine("[OpcodeProbe] MH_CreateHook failed for sender RVA");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        LogLine("[OpcodeProbe] MH_EnableHook failed for sender RVA");
        return false;
    }

    fmt::memory_buffer buf;
    fmt::format_to(buf, "[OpcodeProbe] Sender mode active at wow+0x{}\n", ToHex(g_senderRva, 6).value);
    Log(buf);
    return true;
}

bool QueryModuleBounds() {
    g_wowModule = GetModuleHandleW(nullptr);
    if (!g_wowModule) {
        LogLine("[OpcodeProbe] Failed to query Wow.exe module");
        return false;
    }

    MODULEINFO info = {};
    if (!GetModuleInformation(GetCurrentProcess(), g_wowModule, &info, sizeof(info))) {
        LogLine("[OpcodeProbe] GetModuleInformation failed");
        return false;
    }

    g_wowBase = reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll);
    g_wowSize = static_cast<std::size_t>(info.SizeOfImage);
    return true;
}

std::uint32_t ParseSenderRva(std::string_view text) {
    if (text.empty()) return 0;
    const char* begin = text.data();
    char* end = nullptr;
    unsigned long value = std::strtoul(begin, &end, 0);
    if (!end || end == begin) return 0;
    return static_cast<std::uint32_t>(value);
}

void Configure() {
    if (!QueryModuleBounds()) {
        return;
    }

    std::string phase = ReadEnv("PROBE_PHASE");
    std::string lower = ToLower(phase);
    if (lower == "discover") {
        g_mode = ProbeMode::Discover;
        InstallDiscoverHook();
        return;
    }
    if (lower == "sender") {
        std::string senderText = ReadEnv("PROBE_SENDER_RVA");
        g_senderRva = ParseSenderRva(senderText);
        if (!g_senderRva) {
            LogLine("[OpcodeProbe] PROBE_SENDER_RVA missing or invalid");
            return;
        }
        g_mode = ProbeMode::Sender;
        InstallSenderHook();
        return;
    }

    if (!phase.empty()) {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] Unknown PROBE_PHASE='{}'\n", phase);
        Log(buf);
    }
}

} // namespace

void OpcodeProbe_Init() {
    std::call_once(g_initOnce, [] {
        Configure();
    });
}

