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
#include <atomic>
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
#include <limits>
#include <utility>
#include <chrono>
#include <vector>

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

    extern "C" USHORT NTAPI RtlCaptureStackBackTrace(
        ULONG FramesToSkip,
        ULONG FramesToCapture,
        PVOID* BackTrace,
        PULONG BackTraceHash);

    std::once_flag g_initOnce;
    ProbeMode g_mode = ProbeMode::Off;
    HMODULE g_wowModule = nullptr;
    std::uintptr_t g_wowBase = 0;
    std::size_t g_wowSize = 0;
    using Send_t = int (WSAAPI*)(SOCKET, const char*, int, int);
    Send_t g_origWinsockSend = nullptr;

    using WSASend_t = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    WSASend_t g_origWinsockWSASend = nullptr;

    using Recv_t = int (WSAAPI*)(SOCKET, char*, int, int);
    Recv_t g_origWinsockRecv = nullptr;

    using WSARecv_t = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    WSARecv_t g_origWinsockWSARecv = nullptr;

    using Connect_t = int (WSAAPI*)(SOCKET, const sockaddr*, int);
    Connect_t g_origWinsockConnect = nullptr;

    using WSAConnect_t = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
    WSAConnect_t g_origWinsockWSAConnect = nullptr;

    struct ProbeConfig {
        std::string phase;
        std::uint64_t asqSignature = 0;
        bool hasAsqSignature = false;
        std::uint32_t deepHint = 0;
        bool hasDeepHint = false;
        std::vector<std::string> worldHosts;
        std::vector<in_addr> worldAddrs;
        bool hasWorldHosts = false;
        std::vector<std::uint16_t> worldPorts;
        bool hasWorldPorts = false;
        std::uint32_t maxPacketBytes = 48;
        bool hasMaxPacketBytes = false;
        std::uint32_t debounceMs = 200;
        bool hasDebounceMs = false;
    };

    ProbeConfig g_config;
    std::atomic<std::uint32_t> g_asqCount{ 0 };
    std::atomic<SOCKET> g_trackedSocket{ INVALID_SOCKET };
    std::mutex g_dedupeMutex;
    std::string g_lastLogLine;
    std::chrono::steady_clock::time_point g_lastLogTime;

    void ProbeLogString(std::string_view text);
    void ProbeLogLine(std::string_view message);

    template <typename... Args>
    void ProbeLogFormatLine(const char* fmtStr, Args&&... args) {
        ProbeLogLine(fmt::format(fmtStr, std::forward<Args>(args)...));
    }

    template <typename... Args>
    void LogFormatLine(const char* fmtStr, Args&&... args) {
        LogLine(fmt::format(fmtStr, std::forward<Args>(args)...));
    }

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

    void ProbeLogLine(std::string_view message) {
        std::string text(message);
        text.push_back('\n');
        ProbeLogString(text);
    }

    void ProbeLogString(std::string_view text) {
        std::string owned(text);
        OutputDebugStringA(owned.c_str());
    }

    std::string ResolveConfigPath() {
        HMODULE module = nullptr;
        if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCSTR>(&ProbeLogLine), &module)) {
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
        std::string section;
    };

    bool ParseUint64(const std::string& text, std::uint64_t& value) {
        const char* str = text.c_str();
        char* end = nullptr;
        unsigned long long parsed = _strtoui64(str, &end, 0);
        if (!str || end == str || (end && *end != '\0')) {
            return false;
        }
        value = static_cast<std::uint64_t>(parsed);
        return true;
    }

    bool ParseUint32(const std::string& text, std::uint32_t& value) {
        std::uint64_t temp = 0;
        if (!ParseUint64(text, temp)) {
            return false;
        }
        if (temp > std::numeric_limits<std::uint32_t>::max()) {
            return false;
        }
        value = static_cast<std::uint32_t>(temp);
        return true;
    }

    bool ParseUint16(const std::string& text, std::uint16_t& value) {
        std::uint64_t temp = 0;
        if (!ParseUint64(text, temp)) {
            return false;
        }
        if (temp > std::numeric_limits<std::uint16_t>::max()) {
            return false;
        }
        value = static_cast<std::uint16_t>(temp);
        return true;
    }

    std::vector<std::string> SplitCsv(const std::string& text) {
        std::vector<std::string> values;
        std::size_t start = 0;
        while (start <= text.size()) {
            auto comma = text.find(',', start);
            std::string token;
            if (comma == std::string::npos) {
                token = text.substr(start);
                start = text.size() + 1;
            }
            else {
                token = text.substr(start, comma - start);
                start = comma + 1;
            }

            Trim(token);
            if (!token.empty()) {
                values.emplace_back(std::move(token));
            }
        }
        return values;
    }

    void ApplyConfigValue(ConfigState& state, const std::string& key, const std::string& value, std::size_t lineNumber) {
        if (!state.config) {
            return;
        }

        auto lowerKey = ToLower(key);

        if ((state.section.empty() || state.section == "probe") && lowerKey == "phase") {
            state.config->phase = value;
            state.recognized = true;
        }
        else if (state.section == "watch" && lowerKey == "asq_sig") {
            std::uint64_t parsed = 0;
            if (ParseUint64(value, parsed)) {
                state.config->asqSignature = parsed;
                state.config->hasAsqSignature = true;
                state.recognized = true;
            }
            else {
                ProbeLogFormatLine("[OpcodeProbe] Failed to parse asq_sig on line {}", lineNumber);
            }
        }
        else if (state.section == "watch" && lowerKey == "deep_hint") {
            std::uint32_t parsed = 0;
            if (ParseUint32(value, parsed)) {
                state.config->deepHint = parsed;
                state.config->hasDeepHint = true;
                state.recognized = true;
            }
            else {
                ProbeLogFormatLine("[OpcodeProbe] Failed to parse deep_hint on line {}", lineNumber);
            }
        }
        else if (state.section == "winsock" && lowerKey == "world_host") {
            auto entries = SplitCsv(value);
            if (entries.empty()) {
                ProbeLogFormatLine("[OpcodeProbe] Failed to parse world_host on line {}", lineNumber);
                return;
            }

            std::vector<in_addr> addrs;
            addrs.reserve(entries.size());
            for (const auto& entry : entries) {
                in_addr addr{};
                if (InetPtonA(AF_INET, entry.c_str(), &addr) != 1) {
                    ProbeLogFormatLine("[OpcodeProbe] Failed to parse world_host '{}' on line {}", entry, lineNumber);
                    return;
                }
                addrs.push_back(addr);
            }

            state.config->worldHosts = std::move(entries);
            state.config->worldAddrs = std::move(addrs);
            state.config->hasWorldHosts = true;
            state.recognized = true;
        }
        else if (state.section == "winsock" && lowerKey == "world_port") {
            auto entries = SplitCsv(value);
            if (entries.empty()) {
                ProbeLogFormatLine("[OpcodeProbe] Failed to parse world_port on line {}", lineNumber);
                return;
            }

            std::vector<std::uint16_t> ports;
            ports.reserve(entries.size());
            for (const auto& entry : entries) {
                std::uint16_t parsed = 0;
                if (!ParseUint16(entry, parsed)) {
                    ProbeLogFormatLine("[OpcodeProbe] Failed to parse world_port '{}' on line {}", entry, lineNumber);
                    return;
                }
                ports.push_back(parsed);
            }

            state.config->worldPorts = std::move(ports);
            state.config->hasWorldPorts = true;
            state.recognized = true;
        }
        else if ((state.section == "winsock" || state.section == "filter") && lowerKey == "max_packet_bytes") {
            std::uint32_t parsed = 0;
            if (ParseUint32(value, parsed)) {
                state.config->maxPacketBytes = parsed;
                state.config->hasMaxPacketBytes = true;
                state.recognized = true;
            }
            else {
                ProbeLogFormatLine("[OpcodeProbe] Failed to parse max_packet_bytes on line {}", lineNumber);
            }
        }
        else if ((state.section == "winsock" || state.section == "filter") && lowerKey == "debounce_ms") {
            std::uint32_t parsed = 0;
            if (ParseUint32(value, parsed)) {
                state.config->debounceMs = parsed;
                state.config->hasDebounceMs = true;
                state.recognized = true;
            }
            else {
                ProbeLogFormatLine("[OpcodeProbe] Failed to parse debounce_ms on line {}", lineNumber);
            }
        }
        else {
            if (!state.section.empty()) {
                ProbeLogFormatLine("[OpcodeProbe] Unknown config key '{}' in [{}] on line {}", key, state.section, lineNumber);
            }
            else {
                ProbeLogFormatLine("[OpcodeProbe] Unknown config key '{}' on line {}", key, lineNumber);
            }
        }
    }

    bool LoadConfigFromFile(ProbeConfig& config, std::string& pathOut) {
        pathOut = ResolveConfigPath();
        if (pathOut.empty()) {
            ProbeLogLine("[OpcodeProbe] Failed to resolve opcode_probe.cfg path");
            return false;
        }

        std::ifstream file(pathOut);
        if (!file.is_open()) {
            ProbeLogFormatLine("[OpcodeProbe] Config file '{}' not found; probe disabled", pathOut);
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

            if (!line.empty() && line.front() == '[' && line.back() == ']') {
                flushPending(lineNumber);
                std::string section = line.substr(1, line.size() - 2);
                Trim(section);
                state.section = ToLower(section);
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
                ProbeLogFormatLine("[OpcodeProbe] Ignoring config line {} (missing '=')", lineNumber);
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
            ProbeLogFormatLine("[OpcodeProbe] Config '{}' contained no recognized settings", pathOut);
        }
        else {
            ProbeLogFormatLine("[OpcodeProbe] Loaded config from '{}'", pathOut);
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

        std::string line = fmt::format("[OpcodeProbe][discover] {} stack:", apiName);
        USHORT start = captured > 1 ? 1 : 0;
        for (USHORT i = start; i < captured; ++i) {
            auto desc = DescribeAddress(frames[i]);
            line += fmt::format(" {}", desc);
        }
        ProbeLogLine(line);
    }

    std::string FormatWowFrame(ULONG_PTR rva) {
        if (rva == 0) {
            return "wow+??????";
        }
        return fmt::format("wow+{}", ToHex(rva, 6).value);
    }

    ULONG_PTR WowFrameRva(std::size_t n_wow_frame) {
        if (!g_wowBase || !g_wowSize) {
            return 0;
        }

        void* frames[64] = {};
        constexpr ULONG frameCount = static_cast<ULONG>(sizeof(frames) / sizeof(frames[0]));
        USHORT captured = RtlCaptureStackBackTrace(0, frameCount, frames, nullptr);
        if (captured == 0) {
            return 0;
        }

        const std::uintptr_t lo = g_wowBase;
        const std::uintptr_t hi = g_wowBase + g_wowSize;
        std::size_t seen = 0;
        for (USHORT i = 0; i < captured; ++i) {
            auto addr = reinterpret_cast<std::uintptr_t>(frames[i]);
            if (addr >= lo && addr < hi) {
                if (seen == n_wow_frame) {
                    return static_cast<ULONG_PTR>(addr - lo);
                }
                ++seen;
            }
        }

        return 0;
    }

    std::uint64_t StackSig() {
        if (!g_wowBase || !g_wowSize) {
            return 0;
        }

        void* frames[32] = {};
        constexpr ULONG frameCount = static_cast<ULONG>(sizeof(frames) / sizeof(frames[0]));
        USHORT captured = RtlCaptureStackBackTrace(0, frameCount, frames, nullptr);
        if (captured == 0) {
            return 0;
        }

        const std::uintptr_t lo = g_wowBase;
        const std::uintptr_t hi = g_wowBase + g_wowSize;

        std::uint64_t hash = 0xcbf29ce484222325ULL;
        for (USHORT i = 0; i < captured; ++i) {
            auto addr = reinterpret_cast<std::uintptr_t>(frames[i]);
            if (addr >= lo && addr < hi) {
                std::uint32_t rva = static_cast<std::uint32_t>(addr - lo);
                hash ^= rva;
                hash *= 0x100000001B3ULL;
            }
        }

        return hash;
    }

    bool ShouldLogPacket(SOCKET socket, std::size_t totalLength) {
        SOCKET tracked = g_trackedSocket.load();
        if (tracked == INVALID_SOCKET) {
            return false;
        }
        if (socket != tracked) {
            return false;
        }

        if (g_config.maxPacketBytes > 0 && totalLength > g_config.maxPacketBytes) {
            return false;
        }

        return true;
    }

    bool ShouldSuppressLog(const std::string& line) {
        if (g_config.debounceMs == 0) {
            return false;
        }

        std::lock_guard<std::mutex> lock(g_dedupeMutex);
        auto now = std::chrono::steady_clock::now();
        if (!g_lastLogLine.empty() && line == g_lastLogLine) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLogTime);
            if (elapsed.count() < static_cast<long long>(g_config.debounceMs)) {
                return true;
            }
        }

        g_lastLogLine = line;
        g_lastLogTime = now;
        return false;
    }

    void LogWinsockSendSignature(const char* apiName) {
        auto sig = StackSig();
        auto enc = WowFrameRva(0);
        auto mid = WowFrameRva(4);
        auto deep = WowFrameRva(8);
        auto encStr = FormatWowFrame(enc);
        auto midStr = FormatWowFrame(mid);
        auto deepStr = FormatWowFrame(deep);

        std::string line = fmt::format(
            "[OpcodeProbe][winsock][send] sig=0x{} enc={} mid={} deep={}",
            ToHex(sig, 16).value,
            encStr,
            midStr,
            deepStr);
        if (apiName && apiName[0] != '\0') {
            line += fmt::format(" api={}", apiName);
        }

        if (g_config.hasDeepHint) {
            line += fmt::format(" hint=wow+{}", ToHex(g_config.deepHint, 6).value);
        }

        if (ShouldSuppressLog(line)) {
            return;
        }

        ProbeLogLine(line);

        if (g_config.hasAsqSignature && sig == g_config.asqSignature) {
            auto count = ++g_asqCount;
            const char* apiLabel = (apiName && apiName[0] != '\0') ? apiName : "?";

        ProbeLogFormatLine("[ASQ] match #{} mid={} deep={} api={}",
            count,
            midStr,
            deepStr,
            apiLabel);
    }
}

int WSAAPI hkSend(SOCKET s, const char* buffer, int length, int flags) {
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("send");
    }
    else if (g_mode == ProbeMode::Winsock && buffer && length > 0) {
        std::size_t totalLength = static_cast<std::size_t>(length);
        if (ShouldLogPacket(s, totalLength)) {
            LogWinsockSendSignature("send");
        }
    }

    return g_origWinsockSend ? g_origWinsockSend(s, buffer, length, flags) : SOCKET_ERROR;
}

int WSAAPI hkWSASend(
    SOCKET s, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesSent,
    DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("WSASend");
    }
    else if (g_mode == ProbeMode::Winsock && buffers && bufferCount > 0) {
        std::size_t totalLength = 0;
        bool hasData = false;
        for (DWORD i = 0; i < bufferCount; ++i) {
            if (buffers[i].buf && buffers[i].len > 0) {
                hasData = true;
                totalLength += static_cast<std::size_t>(buffers[i].len);
            }
        }
        if (hasData && ShouldLogPacket(s, totalLength)) {
            LogWinsockSendSignature("WSASend");
        }
    }

    return g_origWinsockWSASend ? g_origWinsockWSASend(s, buffers, bufferCount, bytesSent, flags, overlapped, completion) : SOCKET_ERROR;
}

int WSAAPI hkRecv(SOCKET s, char* buffer, int length, int flags) {
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("recv");
    }

    return g_origWinsockRecv ? g_origWinsockRecv(s, buffer, length, flags) : SOCKET_ERROR;
}

int WSAAPI hkWSARecv(
    SOCKET s, LPWSABUF buffers, DWORD bufferCount, LPDWORD bytesRecvd,
    LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion)
{
    if (g_mode == ProbeMode::Discover) {
        LogDiscoverStack("WSARecv");
    }

    return g_origWinsockWSARecv ? g_origWinsockWSARecv(s, buffers, bufferCount, bytesRecvd, flags, overlapped, completion) : SOCKET_ERROR;
}

    void TryTrackWorldSocket(SOCKET socket, const sockaddr* name, int nameLen) {
        if (!name || nameLen <= 0) {
            return;
        }

        if (!g_config.hasWorldPorts) {
            return;
        }

        if (name->sa_family == AF_INET && nameLen >= static_cast<int>(sizeof(sockaddr_in))) {
            const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(name);
            std::uint16_t port = ntohs(ipv4->sin_port);
            bool portMatch = false;
            for (auto configuredPort : g_config.worldPorts) {
                if (port == configuredPort) {
                    portMatch = true;
                    break;
                }
            }
            if (!portMatch) {
                return;
            }

            if (g_config.hasWorldHosts) {
                bool hostMatch = false;
                for (const auto& configuredAddr : g_config.worldAddrs) {
                    if (ipv4->sin_addr.S_un.S_addr == configuredAddr.S_un.S_addr) {
                        hostMatch = true;
                        break;
                    }
                }
                if (!hostMatch) {
                    return;
                }
            }

            g_trackedSocket.store(socket);
            auto socketValue = static_cast<std::uintptr_t>(socket);
            std::string hostDesc = "*";
            if (g_config.hasWorldHosts) {
                hostDesc = fmt::format("{}", fmt::join(g_config.worldHosts.begin(), g_config.worldHosts.end(), ","));
            }
            std::string portDesc = "*";
            if (g_config.hasWorldPorts) {
                portDesc = fmt::format("{}", fmt::join(g_config.worldPorts.begin(), g_config.worldPorts.end(), ","));
            }
            ProbeLogFormatLine("[OpcodeProbe] Tracking world socket {}:{} (socket=0x{})", hostDesc, portDesc, ToHex(socketValue, static_cast<int>(sizeof(SOCKET) * 2)).value);
        }
    }

    int WSAAPI hkConnect(SOCKET s, const sockaddr* name, int namelen) {
        TryTrackWorldSocket(s, name, namelen);
        return g_origWinsockConnect ? g_origWinsockConnect(s, name, namelen) : SOCKET_ERROR;
    }

    int WSAAPI hkWSAConnect(
        SOCKET s,
        const sockaddr* name,
        int namelen,
        LPWSABUF callerData,
        LPWSABUF calleeData,
        LPQOS sqos,
        LPQOS gqos) {
        TryTrackWorldSocket(s, name, namelen);
        return g_origWinsockWSAConnect ? g_origWinsockWSAConnect(s, name, namelen, callerData, calleeData, sqos, gqos) : SOCKET_ERROR;
    }

bool InstallHook(const char* moduleName, const char* procName, void* detour, void** original) {
    HMODULE module = GetModuleHandleA(moduleName);
    if (!module) module = LoadLibraryA(moduleName);
    if (!module) {
        ProbeLogFormatLine("[OpcodeProbe] Failed to load {}", moduleName);
        return false;
    }

    auto target = reinterpret_cast<void*>(GetProcAddress(module, procName));
    if (!target) {
        ProbeLogFormatLine("[OpcodeProbe] {} not found in {}", procName, moduleName);
        return false;
    }

    if (MH_CreateHook(target, detour, original) != MH_OK) {
        ProbeLogFormatLine("[OpcodeProbe] MH_CreateHook failed for {}", procName);
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        ProbeLogFormatLine("[OpcodeProbe] MH_EnableHook failed for {}", procName);
        return false;
    }

    return true;
}

bool InstallWinsockHooks() {
    bool anyHooked = false;
    if (InstallHook("Ws2_32.dll", "send", reinterpret_cast<void*>(hkSend), reinterpret_cast<void**>(&g_origWinsockSend))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "WSASend", reinterpret_cast<void*>(hkWSASend), reinterpret_cast<void**>(&g_origWinsockWSASend))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "recv", reinterpret_cast<void*>(hkRecv), reinterpret_cast<void**>(&g_origWinsockRecv))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "WSARecv", reinterpret_cast<void*>(hkWSARecv), reinterpret_cast<void**>(&g_origWinsockWSARecv))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "connect", reinterpret_cast<void*>(hkConnect), reinterpret_cast<void**>(&g_origWinsockConnect))) {
        anyHooked = true;
    }
    if (InstallHook("Ws2_32.dll", "WSAConnect", reinterpret_cast<void*>(hkWSAConnect), reinterpret_cast<void**>(&g_origWinsockWSAConnect))) {
        anyHooked = true;
    }

    if (!anyHooked) {
        ProbeLogLine("[OpcodeProbe] Failed to install Winsock hooks");
    }

    return anyHooked;
}

bool QueryModuleBounds() {
    g_wowModule = GetModuleHandleW(nullptr);
    if (!g_wowModule) {
        ProbeLogLine("[OpcodeProbe] Failed to query Wow.exe module");
        return false;
    }

    MODULEINFO info = {};
    if (!GetModuleInformation(GetCurrentProcess(), g_wowModule, &info, sizeof(info))) {
        ProbeLogLine("[OpcodeProbe] GetModuleInformation failed");
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

    g_config = ProbeConfig{};
    g_asqCount.store(0);
    g_trackedSocket.store(INVALID_SOCKET);
    {
        std::lock_guard<std::mutex> lock(g_dedupeMutex);
        g_lastLogLine.clear();
        g_lastLogTime = {};
    }
    std::string configPath;
    if (!LoadConfigFromFile(g_config, configPath)) {
        return;
    }

    std::string lower = ToLower(g_config.phase);
    if (lower == "discover") {
        g_mode = ProbeMode::Discover;
        if (InstallWinsockHooks()) {
            ProbeLogLine("[OpcodeProbe] Discover mode active (Winsock stack traces)");
        }
        return;
    }

    if (lower.empty() || lower == "winsock") {
        g_mode = ProbeMode::Winsock;
        if (InstallWinsockHooks()) {
            ProbeLogLine("[OpcodeProbe] Winsock stack signature logging active");
        }
        return;
    }

    if (!g_config.phase.empty()) {
        ProbeLogFormatLine("[OpcodeProbe] Unknown phase '{}' in '{}'", g_config.phase, configPath);
    }
}

} // namespace

void OpcodeProbe_Init() {
    std::call_once(g_initOnce, [] {
        Configure();
    });
}

