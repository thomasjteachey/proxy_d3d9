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
#include <WinInet.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>

#include "MinHook.h"
#include "fmt/format.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")

namespace {

enum class ProbeMode {
    Off,
    Discover,
    Winsock,
};

constexpr unsigned kSpiritHealerOpcode = 0x02E2;

std::once_flag g_initOnce;
ProbeMode g_mode = ProbeMode::Off;
HMODULE g_wowModule = nullptr;
std::uintptr_t g_wowBase = 0;
std::size_t g_wowSize = 0;
using Send_t = int (WSAAPI*)(SOCKET, const char*, int, int);
Send_t g_origSend = nullptr;

using Send_t = int (WSAAPI*)(SOCKET, const char*, int, int);
Send_t g_origSend = nullptr;

using WSASend_t = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
WSASend_t g_origWSASend = nullptr;

using Recv_t = int (WSAAPI*)(SOCKET, char*, int, int);
Recv_t g_origRecv = nullptr;

using WSARecv_t = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
WSARecv_t g_origWSARecv = nullptr;

struct ProbeConfig {
    std::string phase;
};

void Log(fmt::memory_buffer& buf);
void LogLine(std::string_view message);

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

std::string ResolveConfigPath() {
    HMODULE module = nullptr;
    if (!GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(&Log), &module)) {
        return {};
    }

    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(module, path, MAX_PATH)) {
        return {};
    }

    std::string fullPath(path);
    auto pos = fullPath.find_last_of("\\/");
    if (pos != std::string::npos) {
        fullPath.resize(pos + 1);
    }
    else {
        fullPath.clear();
    }

    fullPath += "opcode_probe.cfg";
    return fullPath;
}

struct ConfigState {
    ProbeConfig* config = nullptr;
    bool recognized = false;
};

void ApplyConfigValue(ConfigState& state, const std::string& key, const std::string& value, std::size_t lineNumber) {
    if (!state.config) {
        return;
    }

    auto lowerKey = ToLower(key);

    if (lowerKey == "phase") {
        state.config->phase = value;
        state.recognized = true;
    }
    else {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] Unknown config key '{}' on line {}\n", key, lineNumber);
        Log(buf);
    }
}

bool LoadConfigFromFile(ProbeConfig& config, std::string& pathOut) {
    pathOut = ResolveConfigPath();
    if (pathOut.empty()) {
        LogLine("[OpcodeProbe] Failed to resolve opcode_probe.cfg path");
        return false;
    }

    std::ifstream file(pathOut);
    if (!file.is_open()) {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] Config file '{}' not found; probe disabled\n", pathOut);
        Log(buf);
        return false;
    }

    ConfigState state{ &config, false };
    std::string pendingKey;
    std::string pendingValue;
    auto flushPending = [&](std::size_t lineNumber) {
        if (pendingKey.empty()) {
            return;
        }
        Trim(pendingValue);
        ApplyConfigValue(state, pendingKey, pendingValue, lineNumber);
        pendingKey.clear();
        pendingValue.clear();
    };

    std::string line;
    std::size_t lineNumber = 0;
    while (std::getline(file, line)) {
        ++lineNumber;
        auto commentPos = line.find_first_of("#;");
        if (commentPos != std::string::npos) {
            line.erase(commentPos);
        }

        Trim(line);
        if (line.empty()) {
            continue;
        }

        if (!pendingKey.empty()) {
            bool continued = false;
            if (!line.empty() && line.back() == '\\') {
                continued = true;
                line.pop_back();
                Trim(line);
            }
            if (!line.empty()) {
                if (!pendingValue.empty()) pendingValue.append(" ");
                pendingValue.append(line);
            }
            if (!continued) {
                flushPending(lineNumber);
            }
            continue;
        }

        auto equals = line.find('=');
        if (equals == std::string::npos) {
            fmt::memory_buffer buf;
            fmt::format_to(buf, "[OpcodeProbe] Ignoring config line {} (missing '=')\n", lineNumber);
            Log(buf);
            continue;
        }

        std::string key = line.substr(0, equals);
        std::string value = line.substr(equals + 1);
        Trim(key);
        Trim(value);

        bool continued = false;
        if (!value.empty() && value.back() == '\\') {
            continued = true;
            value.pop_back();
            Trim(value);
        }

        if (continued) {
            pendingKey = key;
            pendingValue = value;
            continue;
        }

        ApplyConfigValue(state, key, value, lineNumber);
    }

    flushPending(lineNumber);

    if (!state.recognized) {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] Config '{}' contained no recognized settings\n", pathOut);
        Log(buf);
    }
    else {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] Loaded config from '{}'\n", pathOut);
        Log(buf);
    }

    return state.recognized;
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

void LogDiscoverStack(const char* apiName) {
    constexpr USHORT kMaxFrames = 16;
    void* frames[kMaxFrames] = {};
    USHORT captured = CaptureStackBackTrace(0, kMaxFrames, frames, nullptr);
    if (captured == 0) return;

    fmt::memory_buffer buf;
    fmt::format_to(buf, "[OpcodeProbe][discover] {} stack:", apiName);
    USHORT start = captured > 1 ? 1 : 0;
    for (USHORT i = start; i < captured; ++i) {
        auto desc = DescribeAddress(frames[i]);
        fmt::format_to(buf, " {}", desc);
    }
    fmt::format_to(buf, "\n");
    Log(buf);
}

struct PacketHeader {
    std::uint16_t size = 0;
    std::uint16_t opcode = 0;
};

bool ExtractHeaderFromSpan(const std::uint8_t* data, std::size_t length, PacketHeader& header) {
    if (!data || length < 4) {
        return false;
    }

    header.size = static_cast<std::uint16_t>(data[0] | (static_cast<std::uint16_t>(data[1]) << 8));
    header.opcode = static_cast<std::uint16_t>(data[2] | (static_cast<std::uint16_t>(data[3]) << 8));
    return true;
}

bool ExtractHeaderFromBuffers(LPWSABUF buffers, DWORD bufferCount, std::size_t availableBytes, PacketHeader& header) {
    if (!buffers || bufferCount == 0 || availableBytes < 4) {
        return false;
    }

    std::uint8_t headerBytes[4] = {};
    std::size_t copied = 0;

    for (DWORD i = 0; i < bufferCount && copied < 4 && availableBytes > 0; ++i) {
        const WSABUF& buf = buffers[i];
        if (!buf.buf || buf.len == 0) {
            continue;
        }

        std::size_t bufferLen = static_cast<std::size_t>(buf.len);
        if (bufferLen == 0) {
            continue;
        }

        std::size_t allowed = std::min(bufferLen, availableBytes);
        if (allowed == 0) {
            continue;
        }

        std::size_t toCopy = std::min<std::size_t>(allowed, 4 - copied);
        std::memcpy(headerBytes + copied, buf.buf, toCopy);
        copied += toCopy;
        availableBytes -= toCopy;
    }

    if (copied < 4) {
        return false;
    }

    return ExtractHeaderFromSpan(headerBytes, sizeof(headerBytes), header);
}

std::uint32_t CaptureWowCallerRva() {
    if (!g_wowBase || !g_wowSize) {
        return 0;
    }

    constexpr USHORT kMaxFrames = 32;
    void* frames[kMaxFrames] = {};
    USHORT captured = CaptureStackBackTrace(0, kMaxFrames, frames, nullptr);
    if (captured == 0) {
        return 0;
    }

    for (USHORT i = 0; i < captured; ++i) {
        auto addr = reinterpret_cast<std::uintptr_t>(frames[i]);
        if (addr >= g_wowBase && addr < (g_wowBase + g_wowSize)) {
            return static_cast<std::uint32_t>(addr - g_wowBase);
        }
    }

    return 0;
}

void LogWinsockPacket(const char* direction, const char* apiName, const PacketHeader& header, std::uint32_t callerRva) {
    fmt::memory_buffer buf;
    fmt::format_to(buf, "[OpcodeProbe][winsock][{}] opcode=0x{} size={}",
        direction,
        ToHex(header.opcode, 4).value,
        header.size);

    if (callerRva) {
        fmt::format_to(buf, " caller=wow+0x{}", ToHex(callerRva, 6).value);
    }
    else {
        fmt::format_to(buf, " caller=?");
    }

    if (apiName && *apiName) {
        fmt::format_to(buf, " api={}", apiName);
    }

    if (header.opcode == kSpiritHealerOpcode) {
        fmt::format_to(buf, " <<< CMSG_AREA_SPIRIT_HEALER_QUERY");
    }

    fmt::format_to(buf, "\n");
    Log(buf);
}

int WSAAPI hkSend(SOCKET s, const char* buffer, int length, int flags) {
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("send");
    }
    else if (g_mode == ProbeMode::Winsock && buffer && length > 0) {
        PacketHeader header;
        std::size_t available = static_cast<std::size_t>(length);
        if (ExtractHeaderFromSpan(reinterpret_cast<const std::uint8_t*>(buffer), available, header)) {
            auto callerRva = CaptureWowCallerRva();
            LogWinsockPacket("send", "send", header, callerRva);
        }
    }

    return g_origSend ? g_origSend(s, buffer, length, flags) : SOCKET_ERROR;
}

int WSAAPI hkWSASend(
    SOCKET s, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent,
    DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("WSASend");
    }
    else if (g_mode == ProbeMode::Winsock && buffers && bufferCount > 0) {
        std::size_t available = 0;
        for (DWORD i = 0; i < bufferCount && available < 4; ++i) {
            std::size_t len = static_cast<std::size_t>(buffers[i].len);
            if (len == 0) {
                continue;
            }
            std::size_t toAdd = std::min<std::size_t>(len, 4 - available);
            available += toAdd;
        }

        if (available >= 4) {
            PacketHeader header;
            if (ExtractHeaderFromBuffers(buffers, bufferCount, available, header)) {
                auto callerRva = CaptureWowCallerRva();
                LogWinsockPacket("send", "WSASend", header, callerRva);
            }
        }
    }

    return g_origWSASend ? g_origWSASend(s, buffers, bufferCount, bytesSent, flags, overlapped, completion) : SOCKET_ERROR;
}

int WSAAPI hkRecv(SOCKET s, char* buffer, int length, int flags) {
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("recv");
    }

    int result = g_origRecv ? g_origRecv(s, buffer, length, flags) : SOCKET_ERROR;

    if (g_mode == ProbeMode::Winsock && result > 0 && buffer) {
        PacketHeader header;
        if (ExtractHeaderFromSpan(reinterpret_cast<const std::uint8_t*>(buffer), static_cast<std::size_t>(result), header)) {
            auto callerRva = CaptureWowCallerRva();
            LogWinsockPacket("recv", "recv", header, callerRva);
        }
    }

    return result;
}

int WSAAPI hkWSARecv(
    SOCKET s, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesRecvd,
    LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("WSARecv");
    }

    int result = g_origWSARecv ? g_origWSARecv(s, buffers, bufferCount, bytesRecvd, flags, overlapped, completion) : SOCKET_ERROR;

    if (g_mode == ProbeMode::Winsock && result == 0 && buffers && bufferCount > 0 && bytesRecvd && *bytesRecvd >= 4 && !overlapped) {
        PacketHeader header;
        if (ExtractHeaderFromBuffers(buffers, bufferCount, static_cast<std::size_t>(*bytesRecvd), header)) {
            auto callerRva = CaptureWowCallerRva();
            LogWinsockPacket("recv", "WSARecv", header, callerRva);
        }
    }

    return result;
}

bool InstallHook(const char* moduleName, const char* procName, void* detour, void** original) {
    HMODULE module = GetModuleHandleA(moduleName);
    if (!module) module = LoadLibraryA(moduleName);
    if (!module) {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] Failed to load {}\n", moduleName);
        Log(buf);
        return false;
    }

    auto target = reinterpret_cast<void*>(GetProcAddress(module, procName));
    if (!target) {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] {} not found in {}\n", procName, moduleName);
        Log(buf);
        return false;
    }

    if (MH_CreateHook(target, detour, original) != MH_OK) {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] MH_CreateHook failed for {}\n", procName);
        Log(buf);
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] MH_EnableHook failed for {}\n", procName);
        Log(buf);
        return false;
    }

    return true;
}

bool InstallWinsockHooks() {
    bool anyHooked = false;
    if (InstallHook("Ws2_32.dll", "send", reinterpret_cast<void*>(hkSend), reinterpret_cast<void**>(&g_origSend))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "WSASend", reinterpret_cast<void*>(hkWSASend), reinterpret_cast<void**>(&g_origWSASend))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "recv", reinterpret_cast<void*>(hkRecv), reinterpret_cast<void**>(&g_origRecv))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "WSARecv", reinterpret_cast<void*>(hkWSARecv), reinterpret_cast<void**>(&g_origWSARecv))) {
        anyHooked = true;
    }

    if (!anyHooked) {
        LogLine("[OpcodeProbe] Failed to install Winsock hooks");
    }

    return anyHooked;
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

void Configure() {
    if (!QueryModuleBounds()) {
        return;
    }

    ProbeConfig config;
    std::string configPath;
    if (!LoadConfigFromFile(config, configPath)) {
        return;
    }

    std::string lower = ToLower(config.phase);
    if (lower == "discover") {
        g_mode = ProbeMode::Discover;
        if (InstallWinsockHooks()) {
            LogLine("[OpcodeProbe] Discover mode active (Winsock stack traces)");
        }
        return;
    }

    if (lower.empty() || lower == "winsock") {
        g_mode = ProbeMode::Winsock;
        if (InstallWinsockHooks()) {
            LogLine("[OpcodeProbe] Winsock opcode logging active");
        }
        return;
    }

    if (!config.phase.empty()) {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] Unknown phase '{}' in '{}'\n", config.phase, configPath);
        Log(buf);
    }
}

} // namespace

void OpcodeProbe_Init() {
    std::call_once(g_initOnce, [] {
        Configure();
    });
}

