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

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <intrin.h>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "MinHook.h"
#include "fmt/format.h"

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Wininet.lib")
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
std::uint32_t g_callerRva = 0;

using Send_t = int (WSAAPI*)(SOCKET, const char*, int, int);
Send_t g_origSend = nullptr;

using WSASend_t = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
WSASend_t g_origWSASend = nullptr;

using WSASendTo_t = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
WSASendTo_t g_origWSASendTo = nullptr;

using Sender_t = int(__thiscall*)(void*, void*);
Sender_t g_origSender = nullptr;
void* g_origCaller = nullptr;

struct FlagSpec {
    std::string name;
    std::ptrdiff_t offset = 0;
    int bit = -1;
    bool absolute = false;
};

std::vector<FlagSpec> g_callerFlags;

struct ProbeConfig {
    std::string phase;
    std::string senderRva;
    std::string callerRva;
    std::string callerFlags;
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

std::vector<std::string> SplitList(std::string_view text, char delim = ',') {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start < text.size()) {
        std::size_t end = text.find(delim, start);
        if (end == std::string_view::npos) end = text.size();
        std::string token(text.substr(start, end - start));
        Trim(token);
        if (!token.empty()) parts.push_back(std::move(token));
        start = end + 1;
    }
    return parts;
}

bool ParseOffset(std::string_view text, std::ptrdiff_t& value) {
    std::string copy(text);
    Trim(copy);
    if (copy.empty()) return false;
    const char* begin = copy.c_str();
    char* end = nullptr;
    long long parsed = std::strtoll(begin, &end, 0);
    if (!end || end == begin) return false;
    while (*end && std::isspace(static_cast<unsigned char>(*end))) ++end;
    if (*end != '\0') return false;
    value = static_cast<std::ptrdiff_t>(parsed);
    return true;
}

int ParseBitIndex(std::string_view text) {
    std::string copy(text);
    Trim(copy);
    if (copy.empty()) return -1;
    const char* begin = copy.c_str();
    char* end = nullptr;
    long value = std::strtol(begin, &end, 0);
    if (!end || end == begin) return -1;
    while (*end && std::isspace(static_cast<unsigned char>(*end))) ++end;
    if (*end != '\0') return -1;
    return static_cast<int>(value);
}

bool SafeReadByte(const void* address, std::uint8_t& value) {
    __try {
        value = *reinterpret_cast<const std::uint8_t*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return false;
}

bool SafeReadDword(const void* address, std::uint32_t& value) {
    __try {
        value = *reinterpret_cast<const std::uint32_t*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return false;
}

void ParseCallerFlags(std::string_view text) {
    g_callerFlags.clear();
    if (text.empty()) return;

    auto entries = SplitList(text);
    for (const auto& entry : entries) {
        auto pos = entry.find('@');
        if (pos == std::string::npos) {
            fmt::memory_buffer buf;
            fmt::format_to(buf, "[OpcodeProbe] Ignoring caller_flags entry '{}' (missing '@')\n", entry);
            Log(buf);
            continue;
        }

        std::string name = entry.substr(0, pos);
        Trim(name);
        if (name.empty()) {
            name = entry.substr(pos + 1);
            Trim(name);
        }

        std::string target = entry.substr(pos + 1);
        Trim(target);

        bool absolute = false;
        if (target.rfind("abs:", 0) == 0) {
            absolute = true;
            target.erase(0, 4);
            Trim(target);
        }

        int bit = -1;
        auto bitPos = target.find('|');
        if (bitPos != std::string::npos) {
            std::string bitText = target.substr(bitPos + 1);
            bit = ParseBitIndex(bitText);
            target.erase(bitPos);
            Trim(target);
        }

        std::ptrdiff_t offset = 0;
        if (!ParseOffset(target, offset)) {
            fmt::memory_buffer buf;
            fmt::format_to(buf, "[OpcodeProbe] Failed to parse caller_flags entry '{}' offset '{}'\n", entry, target);
            Log(buf);
            continue;
        }

        FlagSpec spec;
        spec.name = name;
        spec.offset = offset;
        spec.bit = bit;
        spec.absolute = absolute;
        g_callerFlags.push_back(std::move(spec));
    }

    if (!g_callerFlags.empty()) {
        fmt::memory_buffer buf;
        fmt::format_to(buf, "[OpcodeProbe] caller_flags configured:");
        for (const auto& spec : g_callerFlags) {
            long long offValue = static_cast<long long>(spec.offset);
            unsigned long long absValue = offValue >= 0 ? static_cast<unsigned long long>(offValue)
                : static_cast<unsigned long long>(-offValue);
            std::string hex = ToHex(absValue, 0).value;
            if (offValue < 0) {
                hex.insert(hex.begin(), '-');
                hex.insert(hex.begin() + 1, '0');
                hex.insert(hex.begin() + 2, 'x');
            }
            else {
                hex.insert(hex.begin(), '0');
                hex.insert(hex.begin() + 1, 'x');
            }
            fmt::format_to(buf, " {}@{}{}", spec.name, spec.absolute ? "abs:" : "", hex);
            if (spec.bit >= 0) fmt::format_to(buf, "|{}", spec.bit);
        }
        fmt::format_to(buf, "\n");
        Log(buf);
    }
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
    else if (lowerKey == "sender_rva") {
        state.config->senderRva = value;
        state.recognized = true;
    }
    else if (lowerKey == "caller_rva") {
        state.config->callerRva = value;
        state.recognized = true;
    }
    else if (lowerKey == "caller_flags") {
        state.config->callerFlags = value;
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

int WSAAPI hkSend(SOCKET s, const char* buffer, int length, int flags) {
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("send");
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
    return g_origWSASend ? g_origWSASend(s, buffers, bufferCount, bytesSent, flags, overlapped, completion) : SOCKET_ERROR;
}

int WSAAPI hkWSASendTo(
    SOCKET s, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent, DWORD flags,
    const sockaddr* to, int toLength, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("WSASendTo");
    }
    return g_origWSASendTo ? g_origWSASendTo(s, buffers, bufferCount, bytesSent, flags, to, toLength, overlapped, completion) : SOCKET_ERROR;
}

using HttpSendRequestA_t = BOOL(WINAPI*)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
HttpSendRequestA_t g_origHttpSendRequestA = nullptr;

BOOL WINAPI hkHttpSendRequestA(HINTERNET request, LPCSTR headers, DWORD headerLength, LPVOID optional, DWORD optionalLength) {
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("HttpSendRequestA");
    }
    return g_origHttpSendRequestA ? g_origHttpSendRequestA(request, headers, headerLength, optional, optionalLength) : FALSE;
}

using HttpSendRequestW_t = BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
HttpSendRequestW_t g_origHttpSendRequestW = nullptr;

BOOL WINAPI hkHttpSendRequestW(HINTERNET request, LPCWSTR headers, DWORD headerLength, LPVOID optional, DWORD optionalLength) {
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("HttpSendRequestW");
    }
    return g_origHttpSendRequestW ? g_origHttpSendRequestW(request, headers, headerLength, optional, optionalLength) : FALSE;
}

using InternetWriteFile_t = BOOL(WINAPI*)(HINTERNET, LPCVOID, DWORD, LPDWORD);
InternetWriteFile_t g_origInternetWriteFile = nullptr;

BOOL WINAPI hkInternetWriteFile(HINTERNET file, LPCVOID buffer, DWORD numBytesToWrite, LPDWORD numBytesWritten) {
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("InternetWriteFile");
    }
    return g_origInternetWriteFile ? g_origInternetWriteFile(file, buffer, numBytesToWrite, numBytesWritten) : FALSE;
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

void __stdcall LogSpiritHealerCaller(void* self, void* stackBase) {
    if (g_mode != ProbeMode::Sender) {
        return;
    }

    auto selfValue = reinterpret_cast<std::uintptr_t>(self);
    void* retAddr = stackBase ? *reinterpret_cast<void**>(stackBase) : nullptr;

    fmt::memory_buffer buf;
    fmt::format_to(buf, "[OpcodeProbe][caller] this=0x{}", ToHexLower(selfValue, sizeof(void*) * 2).value);

    if (retAddr) {
        fmt::format_to(buf, " ret={}", DescribeAddress(retAddr));
    }

    if (stackBase) {
        auto* values = reinterpret_cast<std::uint32_t*>(stackBase);
        constexpr int kArgsToLog = 4;
        fmt::format_to(buf, " args=");
        for (int i = 1; i <= kArgsToLog; ++i) {
            if (i == 1) fmt::format_to(buf, "[");
            else fmt::format_to(buf, ",");
            std::uint32_t raw = values[i];
            fmt::format_to(buf, "arg{}=0x{}({})", i - 1, ToHex(raw, 8).value, raw ? 1 : 0);
        }
        fmt::format_to(buf, "]");
    }

    if (!g_callerFlags.empty()) {
        fmt::format_to(buf, " flags={");
        bool first = true;
        for (const auto& spec : g_callerFlags) {
            if (!first) fmt::format_to(buf, " ");
            first = false;

            const void* address = nullptr;
            if (spec.absolute) {
                if (g_wowBase) {
                    address = reinterpret_cast<const void*>(g_wowBase + spec.offset);
                }
            }
            else if (self) {
                address = reinterpret_cast<const void*>(reinterpret_cast<const std::uint8_t*>(self) + spec.offset);
            }

            bool haveValue = false;
            int value = 0;
            if (address) {
                if (spec.bit >= 0) {
                    std::uint32_t raw = 0;
                    if (SafeReadDword(address, raw)) {
                        value = ((raw >> spec.bit) & 1) ? 1 : 0;
                        haveValue = true;
                    }
                }
                else {
                    std::uint8_t raw = 0;
                    if (SafeReadByte(address, raw)) {
                        value = raw ? 1 : 0;
                        haveValue = true;
                    }
                }
            }

            if (haveValue) {
                fmt::format_to(buf, "{}={}", spec.name, value);
            }
            else {
                fmt::format_to(buf, "{}=?", spec.name);
            }
        }
        fmt::format_to(buf, "}");
    }
    else {
        fmt::format_to(buf, " flags=none");
    }

    fmt::format_to(buf, "\n");
    Log(buf);
}

extern "C" __declspec(naked) void hkSpiritHealerCaller() {
    __asm {
        pushfd
        pushad
        mov eax, ecx
        lea edx, [esp + 32 + 4]
        push edx
        push eax
        call LogSpiritHealerCaller
        popad
        popfd
        jmp g_origCaller
    }
}

int __fastcall hkSender(void* self, void*, void* packet) {
    if (g_mode == ProbeMode::Sender) {
        void* caller = _ReturnAddress();
        LogPacket(packet, caller);
    }
    return g_origSender ? g_origSender(self, packet) : 0;
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

bool InstallDiscoverHook() {
    bool anyHooked = false;
    if (InstallHook("Ws2_32.dll", "send", reinterpret_cast<void*>(hkSend), reinterpret_cast<void**>(&g_origSend))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "WSASend", reinterpret_cast<void*>(hkWSASend), reinterpret_cast<void**>(&g_origWSASend))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "WSASendTo", reinterpret_cast<void*>(hkWSASendTo), reinterpret_cast<void**>(&g_origWSASendTo))) {
        anyHooked = true;
    }
    if (InstallHook("Wininet.dll", "HttpSendRequestA", reinterpret_cast<void*>(hkHttpSendRequestA), reinterpret_cast<void**>(&g_origHttpSendRequestA))) {
        anyHooked = true;
    }
    if (InstallHook("Wininet.dll", "HttpSendRequestW", reinterpret_cast<void*>(hkHttpSendRequestW), reinterpret_cast<void**>(&g_origHttpSendRequestW))) {
        anyHooked = true;
    }
    if (InstallHook("Wininet.dll", "InternetWriteFile", reinterpret_cast<void*>(hkInternetWriteFile), reinterpret_cast<void**>(&g_origInternetWriteFile))) {
        anyHooked = true;
    }

    if (anyHooked) {
        LogLine("[OpcodeProbe] Discover mode active (network API hooks)");
    }
    else {
        LogLine("[OpcodeProbe] Discover mode failed to install hooks");
    }

    return anyHooked;
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

bool InstallCallerHook() {
    if (!g_callerRva || !g_wowBase) {
        LogLine("[OpcodeProbe] Caller RVA not configured");
        return false;
    }

    auto target = reinterpret_cast<void*>(g_wowBase + g_callerRva);
    if (MH_CreateHook(target, reinterpret_cast<LPVOID>(hkSpiritHealerCaller), reinterpret_cast<LPVOID*>(&g_origCaller)) != MH_OK) {
        LogLine("[OpcodeProbe] MH_CreateHook failed for caller RVA");
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        LogLine("[OpcodeProbe] MH_EnableHook failed for caller RVA");
        return false;
    }

    fmt::memory_buffer buf;
    fmt::format_to(buf, "[OpcodeProbe] Caller hook active at wow+0x{}\n", ToHex(g_callerRva, 6).value);
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

    ProbeConfig config;
    std::string configPath;
    if (!LoadConfigFromFile(config, configPath)) {
        return;
    }

    std::string lower = ToLower(config.phase);
    if (lower == "discover") {
        g_mode = ProbeMode::Discover;
        InstallDiscoverHook();
        return;
    }
    if (lower == "sender") {
        g_senderRva = ParseSenderRva(config.senderRva);
        if (!g_senderRva) {
            fmt::memory_buffer buf;
            fmt::format_to(buf, "[OpcodeProbe] sender_rva missing or invalid in '{}'\n", configPath);
            Log(buf);
            return;
        }
        g_callerRva = ParseSenderRva(config.callerRva);
        if (!config.callerRva.empty() && !g_callerRva) {
            fmt::memory_buffer buf;
            fmt::format_to(buf, "[OpcodeProbe] caller_rva invalid ('{}')\n", config.callerRva);
            Log(buf);
        }
        ParseCallerFlags(config.callerFlags);
        g_mode = ProbeMode::Sender;
        InstallSenderHook();
        if (g_callerRva) {
            InstallCallerHook();
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

