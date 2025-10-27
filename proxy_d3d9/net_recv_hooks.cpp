// net_recv_hooks.cpp — drop-in, no DllMain and no manual wiring required.
// Hooks recv/WSARecv, streams counts to DebugView, and runs a ~60Hz tick.

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>   // must be before windows.h
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <cstdint>
#include <cstdarg>
#include <cstdio>       // vsnprintf
#include <atomic>

#include "MinHook.h"
#include "net_trace.h"

#pragma comment(lib, "Ws2_32.lib")
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

// ---------------- recv/WSARecv detours ----------------
using RECV_t = int (WSAAPI*)(SOCKET, char*, int, int);
using WSARECV_t = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
    LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static RECV_t    o_recv = nullptr;
static WSARECV_t o_WSARecv = nullptr;

static int WSAAPI hk_recv(SOCKET s, char* buf, int len, int flags) {
    int r = o_recv(s, buf, len, flags);
    if (r > 0) NetTrace::RecordRecv(r, flags);
    return r;
}

static int WSAAPI hk_WSARecv(SOCKET s, LPWSABUF bufs, DWORD bufcnt, LPDWORD recvd,
    LPDWORD flags, LPWSAOVERLAPPED ov,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE comp) {
    int r = o_WSARecv(s, bufs, bufcnt, recvd, flags, ov, comp);
    // Count only immediate (non-overlapped) completions
    if (r == 0 && recvd && *recvd > 0 && ov == nullptr)
        NetTrace::RecordRecv((int)*recvd, flags ? (int)*flags : 0);
    return r;
}

static void InstallNetHooks() {
    HMODULE hWS2 = GetModuleHandleA("ws2_32.dll");
    if (!hWS2) hWS2 = LoadLibraryA("ws2_32.dll");
    if (!hWS2) { log_line("[ClientFix][NET] ws2_32 not present"); return; }

    auto p_recv = (RECV_t)GetProcAddress(hWS2, "recv");
    auto p_WSARecv = (WSARECV_t)GetProcAddress(hWS2, "WSARecv");

    if (p_recv &&
        MH_CreateHook((LPVOID)p_recv, (LPVOID)hk_recv, (LPVOID*)&o_recv) == MH_OK &&
        MH_EnableHook((LPVOID)p_recv) == MH_OK)
        log_line("[ClientFix][NET] hooked recv");
    else
        log_line("[ClientFix][NET] failed to hook recv");

    if (p_WSARecv &&
        MH_CreateHook((LPVOID)p_WSARecv, (LPVOID)hk_WSARecv, (LPVOID*)&o_WSARecv) == MH_OK &&
        MH_EnableHook((LPVOID)p_WSARecv) == MH_OK)
        log_line("[ClientFix][NET] hooked WSARecv");
    else
        log_line("[ClientFix][NET] failed to hook WSARecv");
}

// ---------------- background tick thread (~60 Hz) ----------------
static DWORD WINAPI TraceTickThread(LPVOID) {
    for (;;) {
        NetTrace::OnFrameBoundary();
        Sleep(16);
    }
    return 0;
}

// ---------------- autoboot without DllMain ----------------
// We use a CRT startup callback so you can keep your existing DllMain.
static LONG gBootOnce = 0;

static DWORD WINAPI BootstrapThread(LPVOID) {
    if (InterlockedCompareExchange(&gBootOnce, 1, 0) != 0) return 0;

    // init MinHook (ignore "already initialized")
    MH_Initialize();

    NetTrace::Init();
    InstallNetHooks();

    HANDLE h = CreateThread(nullptr, 0, TraceTickThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
    return 0;
}

static void __cdecl NetRecv_ModuleInit() {
    // spin up a worker so we don't do heavy work inside CRT init
    HANDLE h = CreateThread(nullptr, 0, BootstrapThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
}

typedef void(__cdecl* INITFN)();
#pragma section(".CRT$XCU", read)                // user-mode C initializers
__declspec(allocate(".CRT$XCU")) INITFN _netrecv_autoinit = NetRecv_ModuleInit;
