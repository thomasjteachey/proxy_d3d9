#if !defined(_M_IX86)
#error Build this file as Win32 (x86)
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <mmsystem.h>
#include <cstdint>
#pragma comment(lib, "winmm.lib")

static volatile LONG g_frame = 0;
static volatile LONG g_inited = 0;
static volatile LONG g_renderTid = 0;

void FrameFence_Init() {
    if (InterlockedCompareExchange(&g_inited, 1, 0) == 0) {
        timeBeginPeriod(1); // better Sleep(0)/SwitchToThread cadence
    }
}

void FrameFence_Tick() {
    InterlockedIncrement(&g_frame);
}

unsigned FrameFence_Id() {
    return (unsigned)InterlockedCompareExchange(&g_frame, 0, 0);
}

bool FrameFence_WaitNext(unsigned maxWaitMs) {
    const unsigned start = timeGetTime();
    const unsigned cur = FrameFence_Id();
    while (FrameFence_Id() == cur) {
        if (timeGetTime() - start >= maxWaitMs) return false; // safety
        Sleep(0); // yield without burning a full ms
    }
    return true;
}

void FrameFence_SetRenderThreadId(uint32_t tid) {
    InterlockedCompareExchange(&g_renderTid, static_cast<LONG>(tid), 0);
}

uint32_t FrameFence_RenderThreadId() {
    return static_cast<uint32_t>(InterlockedCompareExchange(&g_renderTid, 0, 0));
}
