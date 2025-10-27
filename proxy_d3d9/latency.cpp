#include <windows.h>
#include <mmsystem.h>
#pragma comment(lib, "winmm.lib")

#include "MinHook.h"
#include "latency.h"

static volatile LONG g_inited = 0;
static volatile LONG g_on = 0;
static VOID(WINAPI* pSleep_Real)(DWORD) = nullptr;

static void logA(const char* s) { OutputDebugStringA(s); }

static VOID WINAPI Sleep_Hook(DWORD ms)
{
    if (g_on)
    {
        // Clamp tiny sleeps to 1ms to avoid long scheduler delays
        if (ms > 1 && ms <= 15) ms = 17;
    }
    pSleep_Real(ms);
}

static void ApplyWinMM(bool on)
{
    static LONG ref = 0;
    if (on)
    {
        if (InterlockedIncrement(&ref) == 1)
        {
            timeBeginPeriod(1);
            logA("[ClientFix][LAT] timeBeginPeriod(1)\n");
        }
    }
    else
    {
        if (InterlockedDecrement(&ref) == 0)
        {
            timeEndPeriod(1);
            logA("[ClientFix][LAT] timeEndPeriod(1)\n");
        }
    }
}

static DWORD WINAPI HotkeyThread(LPVOID)
{
    logA("[ClientFix][LAT] Hotkey thread up (F9 toggles 1ms mode)\n");
    // Start disabled by default
    Latency_Enable(false);

    for (;;)
    {
        if (GetAsyncKeyState(VK_F9) & 1)
        {
            bool on = !Latency_IsEnabled();
            Latency_Enable(on);
            logA(on
                ? "[ClientFix][LAT] 1ms mode: ON\n"
                : "[ClientFix][LAT] 1ms mode: OFF\n");
        }
        Sleep(50);
    }
}

void Latency_Init()
{
    if (InterlockedExchange(&g_inited, 1)) return;

    if (MH_Initialize() != MH_OK)
        logA("[ClientFix][LAT] MH_Initialize already done (ok)\n");

    // Resolve Sleep from kernel32 explicitly (safer)
    FARPROC p = GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep");
    if (!p) { logA("[ClientFix][LAT] GetProcAddress(Sleep) failed\n"); return; }

    if (MH_CreateHook(p, &Sleep_Hook, reinterpret_cast<LPVOID*>(&pSleep_Real)) == MH_OK &&
        MH_EnableHook(p) == MH_OK)
    {
        logA("[ClientFix][LAT] Sleep() hook enabled\n");
    }
    else
    {
        logA("[ClientFix][LAT] Sleep() hook FAILED\n");
    }

    // Hotkey thread (F9)
    HANDLE h = CreateThread(nullptr, 0, HotkeyThread, nullptr, 0, nullptr);
    if (h) CloseHandle(h);
}

void Latency_Enable(bool on)
{
    InterlockedExchange(&g_on, on ? 1 : 0);
    ApplyWinMM(on);
}

bool Latency_IsEnabled()
{
    return InterlockedCompareExchange(&g_on, 0, 0) != 0;
}
