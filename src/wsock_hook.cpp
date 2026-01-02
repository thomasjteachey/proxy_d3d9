#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdint.h>
#include <ws2tcpip.h>

#include "MinHook.h"
#include "net_trace.h"
#include "wsock_hook.h"

#pragma comment(lib, "Ws2_32.lib")

using recv_t = int (WINAPI*)(SOCKET, char*, int, int);
using WSARecv_t = int (WINAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static recv_t gOrigRecv = nullptr;
static WSARecv_t gOrigWSARecv = nullptr;

static int WINAPI hkRecv(SOCKET s, char* buf, int len, int flags)
{
    int r = gOrigRecv ? gOrigRecv(s, buf, len, flags) : SOCKET_ERROR;
    if (r > 0)
        NetTrace::RecordRecv(r, flags);
    return r;
}

static int WINAPI hkWSARecv(SOCKET s, LPWSABUF buffers, DWORD bufferCount,
    LPDWORD numberOfBytesRecvd, LPDWORD flags, LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutine)
{
    int rc = gOrigWSARecv ? gOrigWSARecv(s, buffers, bufferCount, numberOfBytesRecvd, flags, overlapped, completionRoutine) : SOCKET_ERROR;
    if (rc == 0 && numberOfBytesRecvd && *numberOfBytesRecvd)
    {
        const int f = flags ? (int)*flags : 0;

        // Feed the packet decoder with the exact bytes placed in the caller's WSABUFs.
        ULONG remaining = *numberOfBytesRecvd;
        for (DWORD i = 0; i < bufferCount && remaining > 0; i++)
        {
            const ULONG chunk = buffers[i].len < remaining ? buffers[i].len : remaining;
            if (chunk && buffers[i].buf)
                NetTrace::RecordRecv((uint64_t)(uintptr_t)s, (const uint8_t*)buffers[i].buf, (int)chunk, f);
            remaining -= chunk;
        }
    }
    return rc;
}

namespace WSockHook {

void Install()
{
    static bool once = false;
    if (once) return;
    once = true;

    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) return;

    auto pRecv = (void*)GetProcAddress(ws2, "recv");
    auto pWSARecv = (void*)GetProcAddress(ws2, "WSARecv");

    if (pRecv) {
        if (MH_CreateHook(pRecv, hkRecv, reinterpret_cast<void**>(&gOrigRecv)) == MH_OK)
            MH_EnableHook(pRecv);
    }

    if (pWSARecv) {
        if (MH_CreateHook(pWSARecv, hkWSARecv, reinterpret_cast<void**>(&gOrigWSARecv)) == MH_OK)
            MH_EnableHook(pWSARecv);
    }

    OutputDebugStringA("[ClientFix][NET] WSock hooks installed (recv/WSARecv)\n");
}

} // namespace WSockHook
