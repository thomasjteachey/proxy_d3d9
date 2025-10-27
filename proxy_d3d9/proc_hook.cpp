// proc_hook.cpp — general on-hit proc hooks + optional same-frame splitter
// Build: Win32 / MSVC (inline asm). Requires MinHook in project.
// Hotkeys:
//   F9  -> toggle SameFrameSplit (off/on). You'll see a log line when it toggles.
// Logs:
//   [ClientFix][PROC] hook ENABLED ...
//   [ClientFix][PROC] HIT  ret=XXXXXXXX target=YYYYYYYY
//   [ClientFix][PROC] SPLIT (1ms)  ret=XXXXXXXX  dt=Z ms

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>
#include <stdint.h>
#include <stdarg.h>
#include "MinHook.h"

#if !defined(_M_IX86)
#error proc_hook.cpp must be compiled for Win32 (x86). Switch platform to Win32 in Configuration Manager.
#endif

// ======= PASTE YOUR RETURN ADDRESSES HERE (from your F8 dumps) =======
static uintptr_t gRetAddrs[] = {
    0x00467E64, // dominant path
    0x00466F38, // rarer path
};
// =====================================================================

static void logf(const char* fmt, ...)
{
    char b[512]; va_list ap; va_start(ap, fmt);
    _vsnprintf(b, sizeof(b) - 1, fmt, ap);
    va_end(ap); b[sizeof(b) - 1] = 0;
    OutputDebugStringA(b);
}

struct HookRec {
    uintptr_t retAddr = 0;   // post-CALL address (your "caller=" value)
    uintptr_t callAddr = 0;   // CALL location (ret-5) if opcode is E8
    uintptr_t target = 0;   // resolved callee
    void* tramp = nullptr; // MinHook trampoline
    bool      active = false;
    DWORD     lastHitTick = 0;    // for same-frame detection
};

static const int MAX_HOOKS = 8;
static HookRec gHooks[MAX_HOOKS];
static int     gHookCount = 0;

static volatile bool gSameFrameSplit = false;  // toggled by F9

// -------- helper: resolve E8 rel32 callee from a return address --------
static bool ResolveFromRet(uintptr_t ret, uintptr_t& callOut, uintptr_t& targetOut)
{
    if (ret < 5) return false;
    BYTE* call = (BYTE*)(ret - 5);
    if (*call != 0xE8) return false; // only handle "CALL rel32"
    int32_t rel = *(int32_t*)(call + 1);
    uintptr_t target = ret + rel;     // EIP (ret) + rel32
    callOut = (uintptr_t)call;
    targetOut = target;
    return true;
}

// -------- detour plumbing: inline-asm stubs (Win32 only) --------
static void __stdcall OnHit(HookRec* ctx)
{
    DWORD now = GetTickCount();
    DWORD dt = now - ctx->lastHitTick;

    if (gSameFrameSplit && dt <= 5) {
        // simple "split": nudge the 2nd event out of the same tick
        logf("[ClientFix][PROC] SPLIT (1ms)  ret=%08X  dt=%u ms\n",
            (unsigned)ctx->retAddr, (unsigned)dt);
        Sleep(1);
        now = GetTickCount();
    }

    ctx->lastHitTick = now;

    // Throttled "HIT" log (avoid spamming every microcall)
    static DWORD lastPrint = 0;
    if (now - lastPrint > 75) {
        lastPrint = now;
        logf("[ClientFix][PROC] HIT  ret=%08X  target=%08X\n",
            (unsigned)ctx->retAddr, (unsigned)ctx->target);
    }
}

#define MAKE_STUB(N) \
    static HookRec* gCtx##N = nullptr; \
    static void*    gTramp##N = nullptr; \
    extern "C" __declspec(naked) void Detour##N() { \
        __asm { \
            pushfd \
            pushad \
            push dword ptr [gCtx##N] \
            call OnHit \
            add  esp, 4 \
            popad \
            popfd \
            mov  eax, dword ptr [gTramp##N] \
            jmp  eax \
        } \
    }

MAKE_STUB(0)
MAKE_STUB(1)
MAKE_STUB(2)
MAKE_STUB(3)
MAKE_STUB(4)
MAKE_STUB(5)
MAKE_STUB(6)
MAKE_STUB(7)

struct StubRow { void (*det)(); void** pTramp; HookRec** pCtx; };
static StubRow gRows[MAX_HOOKS] = {
    { Detour0, &gTramp0, &gCtx0 },
    { Detour1, &gTramp1, &gCtx1 },
    { Detour2, &gTramp2, &gCtx2 },
    { Detour3, &gTramp3, &gCtx3 },
    { Detour4, &gTramp4, &gCtx4 },
    { Detour5, &gTramp5, &gCtx5 },
    { Detour6, &gTramp6, &gCtx6 },
    { Detour7, &gTramp7, &gCtx7 },
};

static void InstallOne(int idx, HookRec& H)
{
    *gRows[idx].pCtx = &H;
    *gRows[idx].pTramp = nullptr;

    if (MH_Initialize() != MH_OK) {
        // already initialized is fine
    }

    if (MH_CreateHook((LPVOID)H.target, (LPVOID)gRows[idx].det, gRows[idx].pTramp) == MH_OK &&
        MH_EnableHook((LPVOID)H.target) == MH_OK)
    {
        H.tramp = *gRows[idx].pTramp;
        H.active = true;
        logf("[ClientFix][PROC] hook ENABLED  ret=%08X  call=%08X  target=%08X\n",
            (unsigned)H.retAddr, (unsigned)H.callAddr, (unsigned)H.target);
    }
    else {
        logf("[ClientFix][PROC] hook FAILED  ret=%08X  target=%08X\n",
            (unsigned)H.retAddr, (unsigned)H.target);
    }
}

static void InstallProcHooks()
{
    gHookCount = 0;
    const size_t n = sizeof(gRetAddrs) / sizeof(gRetAddrs[0]);
    for (size_t i = 0; i < n && gHookCount < MAX_HOOKS; ++i)
    {
        HookRec H{};
        H.retAddr = gRetAddrs[i];

        if (!ResolveFromRet(H.retAddr, H.callAddr, H.target)) {
            logf("[ClientFix][PROC] skip (not E8)  ret=%08X\n", (unsigned)H.retAddr);
            continue;
        }

        // de-dupe same target
        bool dup = false;
        for (int j = 0; j < gHookCount; ++j) {
            if (gHooks[j].target == H.target) { dup = true; break; }
        }
        if (dup) continue;

        gHooks[gHookCount++] = H;
    }

    for (int i = 0; i < gHookCount; ++i)
        InstallOne(i, gHooks[i]);

    logf("[ClientFix][PROC] prepared=%d (from %u ret addrs)\n",
        gHookCount, (unsigned)(sizeof(gRetAddrs) / sizeof(gRetAddrs[0])));
}

// Tiny hotkey thread to toggle the splitter
static DWORD WINAPI KeyThread(LPVOID)
{
    logf("[ClientFix][PROC] F9 toggles SameFrameSplit (currently %s)\n", gSameFrameSplit ? "ON" : "OFF");
    for (;;) {
        Sleep(16);
        if (GetAsyncKeyState(VK_F9) & 1) {
            gSameFrameSplit = !gSameFrameSplit;
            logf("[ClientFix][PROC] SameFrameSplit: %s\n", gSameFrameSplit ? "ON" : "OFF");
        }
    }
    // unreachable
    // return 0;
}

static void Proc_InitOnce()
{
    static bool once = false; if (once) return; once = true;
    InstallProcHooks();
    CreateThread(nullptr, 0, KeyThread, nullptr, 0, nullptr);
    logf("[ClientFix][PROC] ready — trigger any on-hit proc. F9 toggles same-frame split.\n");
}

// Auto-init when DLL loads (no DllMain needed here)
struct _AutoProc { _AutoProc() { Proc_InitOnce(); } } _gAutoProc;
