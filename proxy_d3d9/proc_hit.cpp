// proc_hook.cpp — hook general on-hit proc paths via known net/handler callsites.
// You paste the RETURN addresses you printed (the values shown as "caller=XXXXXXXX").
// At runtime we resolve each to the CALL (E8) and then to its callee, hook it,
// and print when it hits. Works for Frostbite or any other procs traversing same path.

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <windows.h>
#include <stdint.h>
#include <stdarg.h>
#include <vector>
#include <algorithm>

#include "MinHook.h"   // ensure MinHook headers/lib are in your project

#if !defined(_M_IX86)
#error proc_hook.cpp is for 32-bit builds only.
#endif

// ======= PASTE YOUR KNOWN RETURN ADDRESSES HERE (from your F8 dumps) =======
static uintptr_t gRetAddrs[] = {
    0x00467E64, // dominant path you saw
    0x00466F38, // rarer path you saw
    // add more later if you discover them
};
// ==========================================================================

static void logf(const char* fmt, ...)
{
    char b[512]; va_list ap; va_start(ap, fmt);
    _vsnprintf(b, sizeof(b) - 1, fmt, ap);
    va_end(ap); b[sizeof(b) - 1] = 0;
    OutputDebugStringA(b);
}

// One hook record
struct HookRec {
    uintptr_t retAddr = 0;   // return address (instruction after CALL) from your dump
    uintptr_t callAddr = 0;   // address of CALL opcode (retAddr - 5), only if 0xE8
    uintptr_t target = 0;   // resolved callee
    void* tramp = nullptr; // MinHook trampoline
    bool      active = false;
};

static const int MAX_HOOKS = 8;
static HookRec gHooks[MAX_HOOKS];
static int     gHookCount = 0;

// Forward
static void __stdcall OnHit(HookRec* ctx);

// We create a small set of naked stubs that preserve regs/flags, call OnHit(), then tail-jump.
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

// Resolve a return address (post-CALL) to the CALL and its direct callee (E8 rel32 only)
static bool ResolveFromRet(uintptr_t ret, uintptr_t& callOut, uintptr_t& targetOut)
{
    if (ret < 5) return false;
    BYTE* call = (BYTE*)(ret - 5);
    if (*call != 0xE8) {
        // Not a simple near call; skip for now. (Can extend to FF /2 if needed.)
        return false;
    }
    int32_t rel = *(int32_t*)(call + 1);
    uintptr_t target = ret + rel;  // (EIP + rel32)
    callOut = (uintptr_t)call;
    targetOut = target;
    return true;
}

// Throttled hit print so we don’t spam
static void __stdcall OnHit(HookRec* ctx)
{
    static DWORD lastTick = 0;
    DWORD now = GetTickCount();
    if (now - lastTick > 75) {
        lastTick = now;
        logf("[ClientFix][PROC] HIT  ret=%08X  target=%08X\n",
            (unsigned)ctx->retAddr, (unsigned)ctx->target);
    }
}

static void InstallOne(int idx, HookRec& H)
{
    if (idx >= MAX_HOOKS) return;

    *gRows[idx].pCtx = &H;
    *gRows[idx].pTramp = nullptr;

    // Safe idempotent MinHook init
    if (MH_Initialize() != MH_OK) { /* already inited is fine */ }

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

        // avoid duplicate same target
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

static void RemoveProcHooks()
{
    for (int i = 0; i < gHookCount; ++i) {
        if (gHooks[i].active) {
            MH_DisableHook((LPVOID)gHooks[i].target);
            gHooks[i].active = false;
        }
    }
    logf("[ClientFix][PROC] hooks removed\n");
}

// Auto-init when the DLL loads (no DllMain needed)
static void Proc_InitOnce()
{
    static bool once = false; if (once) return; once = true;
    InstallProcHooks();
    logf("[ClientFix][PROC] ready — trigger any on-hit proc; you should see HIT lines if it flows here.\n");
}
struct _Auto { _Auto() { Proc_InitOnce(); } } _gAuto;
