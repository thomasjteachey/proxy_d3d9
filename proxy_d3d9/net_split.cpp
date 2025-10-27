// net_split.cpp — small-packet splitter to keep first hit from being “eaten”.
// Hook recv/WSARecv; if two tiny packets arrive within a couple ms,
// delay only the 2nd by 1 ms so the client processes them on separate ticks.

#if !defined(_M_IX86)
#error Build this file as Win32 (x86)
#endif

// --- IMPORTANT: order/guards to avoid winsock.h vs winsock2.h conflicts ---
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// If your project uses a PCH that already included <windows.h> (and thus winsock.h),
// either: (A) add winsock2.h to the PCH BEFORE windows.h, or
// (B) compile THIS file without PCH (Project -> Properties -> C/C++ -> Precompiled Headers -> Not Using).
// The guard below prevents windows.h from pulling winsock.h in THIS TU:
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_    // stop windows.h including winsock.h
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windows.h>
#include <mmsystem.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "winmm.lib")

#include "MinHook.h"
#include "net_split.h"

static void logA(const char* s) { OutputDebugStringA(s); }

// ------- tuning knobs -------
static volatile LONG g_on = 1;          // enabled by default
static const DWORD   kWindowMs = 16;  // two packets within 2ms considered same frame
static const int     kMaxSmallSz = 80; // treat <=80 bytes as “small gameplay” packet
static const int     kIgnoreSz = 2;  // ignore 2-byte keepalives
static const DWORD   kDelayMs = 17;  // delay the second packet by 1 ms
// ----------------------------

template<class T> static T VolLoad(const volatile T* p) {
    return (T)InterlockedCompareExchange((volatile LONG*)p, 0, 0);
}

static DWORD g_lastSmallTick = 0;
static bool  g_lastWasSmall = false;

static VOID ApplyTimerRes(bool on) {
    static LONG ref = 0;
    if (on) {
        if (InterlockedIncrement(&ref) == 1) {
            timeBeginPeriod(1);
            logA("[ClientFix][NETSPLIT] timeBeginPeriod(1)\n");
        }
    }
    else {
        if (InterlockedDecrement(&ref) == 0) {
            timeEndPeriod(1);
            logA("[ClientFix][NETSPLIT] timeEndPeriod(1)\n");
        }
    }
}

static inline bool IsSmallPkt(int n) {
    return (n > kIgnoreSz) && (n <= kMaxSmallSz);
}

// ---- recv hook ----
typedef int (WSAAPI* recv_t)(SOCKET, char*, int, int);
static recv_t pRecv = nullptr;

static int WSAAPI hkRecv(SOCKET s, char* buf, int len, int flags)
{
    int n = pRecv(s, buf, len, flags);
    if (!VolLoad(&g_on) || n <= 0) return n;

    DWORD now = timeGetTime();
    bool small = IsSmallPkt(n);

    if (small) {
        if (g_lastWasSmall && (now - g_lastSmallTick) <= kWindowMs) {
            logA("[ClientFix][NETSPLIT] split (recv) Sleep(1)\n");
            Sleep(kDelayMs);             // let the first packet “own” this tick
            now = timeGetTime();
        }
        g_lastSmallTick = now;
        g_lastWasSmall = true;
    }
    else {
        g_lastWasSmall = false;
    }
    return n;
}

// ---- WSARecv hook (sync only) ----
typedef int (WSAAPI* WSARecv_t)(
    SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static WSARecv_t pWSARecv = nullptr;

static int WSAAPI hkWSARecv(
    SOCKET s, LPWSABUF bufs, DWORD bufCount, LPDWORD pBytes, LPDWORD flags,
    LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE comp)
{
    int r = pWSARecv(s, bufs, bufCount, pBytes, flags, ov, comp);
    if (!VolLoad(&g_on)) return r;

    // handle only non-overlapped completions here (overlapped completes later)
    if (ov || r == SOCKET_ERROR || !pBytes) return r;

    DWORD total = *pBytes;
    if ((int)total <= 0) return r;

    DWORD now = timeGetTime();
    bool small = IsSmallPkt((int)total);

    if (small) {
        if (g_lastWasSmall && (now - g_lastSmallTick) <= kWindowMs) {
            logA("[ClientFix][NETSPLIT] split (WSARecv) Sleep(1)\n");
            Sleep(kDelayMs);
            now = timeGetTime();
        }
        g_lastSmallTick = now;
        g_lastWasSmall = true;
    }
    else {
        g_lastWasSmall = false;
    }
    return r;
}

// ---- hotkey thread (F6) ----
static DWORD WINAPI KeyThread(LPVOID) {
    logA("[ClientFix][NETSPLIT] F6 toggles splitter ON/OFF\n");
    for (;;) {
        if (GetAsyncKeyState(VK_F6) & 1) {
            bool on = !VolLoad(&g_on);
            NetSplit_Enable(on);
            logA(on ? "[ClientFix][NETSPLIT] ON\n" : "[ClientFix][NETSPLIT] OFF\n");
        }
        Sleep(30);
    }
}

// ---- public API ----
void NetSplit_Init()
{
    static bool once = false; if (once) return; once = true;

    if (MH_Initialize() != MH_OK) { /* already inited is fine */ }

    HMODULE hWs2 = GetModuleHandleA("Ws2_32.dll");
    if (!hWs2) hWs2 = LoadLibraryA("Ws2_32.dll");

    FARPROC p1 = hWs2 ? GetProcAddress(hWs2, "recv") : nullptr;
    FARPROC p2 = hWs2 ? GetProcAddress(hWs2, "WSARecv") : nullptr;

    if (p1 && MH_CreateHook(p1, hkRecv, (LPVOID*)&pRecv) == MH_OK) MH_EnableHook(p1);
    if (p2 && MH_CreateHook(p2, hkWSARecv, (LPVOID*)&pWSARecv) == MH_OK) MH_EnableHook(p2);

    ApplyTimerRes(true);

    HANDLE th = CreateThread(nullptr, 0, KeyThread, nullptr, 0, nullptr);
    if (th) CloseHandle(th);

    logA("[ClientFix][NETSPLIT] initialized\n");
}

void NetSplit_Enable(bool on) {
    InterlockedExchange(&g_on, on ? 1 : 0);
    // keep 1ms timer active while module is in use
}

bool NetSplit_IsOn() {
    return VolLoad(&g_on) != 0;
}
