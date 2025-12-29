#include "hitgate.h"

#include <windows.h>
#include <vector>
#include <mutex>
#include <cstdio>
#include <cstdint>

#include "MinHook.h"
#include "aob_scan.h"
#include "task_queue.h"
#include "frame_fence.h"

static void log_line(const char* s) { OutputDebugStringA(s); OutputDebugStringA("\n"); }

static std::atomic<long> gHitGateOn{ 1 };
static std::atomic<long> gBlockProcVisuals{ 0 };

static void* g_Ori14A = nullptr;
static uint8_t* g_14AStart = nullptr;

struct DeferredSVK {
    void* self;
    int a1;
    int a2;
    SVKStarter_t orig;
};

static std::mutex gDeferredMx;
static std::vector<DeferredSVK> gDeferredSVK;

static void HitGate_FlushDeferred()
{
    std::vector<DeferredSVK> pending;
    {
        std::lock_guard<std::mutex> lock(gDeferredMx);
        pending.swap(gDeferredSVK);
    }

    {
        char line[128];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] flush frame=%u deferred=%zu",
            FrameFence_Id(), pending.size());
        log_line(line);
    }

    for (const auto& entry : pending) {
        if (entry.orig) {
            __try { entry.orig(entry.self, entry.a1, entry.a2); }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    }
}

void HitGate_ArmOneFrame()
{
    if (!HitGate_IsEnabled()) return;

    if (gBlockProcVisuals.exchange(1) == 0) {
        char line[128];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] armed frame=%u",
            FrameFence_Id());
        log_line(line);
        ScheduleNextFrame([] {
            gBlockProcVisuals.store(0);
            HitGate_FlushDeferred();
        });
    }
}

bool HitGate_TryDeferSVK(void* self, int a1, int a2, SVKStarter_t orig)
{
    if (!HitGate_IsEnabled()) return false;
    if (gBlockProcVisuals.load() == 0) return false;

    {
        std::lock_guard<std::mutex> lock(gDeferredMx);
        gDeferredSVK.push_back({ self, a1, a2, orig });
        char line[128];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] SVK deferred count=%zu",
            gDeferredSVK.size());
        log_line(line);
    }

    return true;
}

bool HitGate_IsEnabled()
{
    return gHitGateOn.load() != 0;
}

uint8_t* HitGate_Get14AStart()
{
    return g_14AStart;
}

// -------------------- 0x14A handler hook --------------------
static void __cdecl On14AEnter()
{
    log_line("[ClientFix][HitGate] On14AEnter() fired");
    HitGate_ArmOneFrame();
}

extern "C" void __declspec(naked) hk14A()
{
    __asm {
        pushfd
        pushad
        call On14AEnter
        popad
        popfd
        jmp dword ptr [g_Ori14A]
    }
}

static void* ResolveAttackerStateHandler()
{
    uint8_t* textBase = nullptr; size_t textSize = 0;
    uint8_t* imageBase = nullptr; size_t imageSize = 0;
    if (!GetTextRange(textBase, textSize) || !GetImageRange(imageBase, imageSize)) return nullptr;

    uintptr_t imageStart = reinterpret_cast<uintptr_t>(imageBase);
    uintptr_t imageEnd = imageStart + imageSize;
    uintptr_t textStart = reinterpret_cast<uintptr_t>(textBase);
    uintptr_t textEnd = textStart + textSize;

    for (size_t i = 0; i + 7 <= textSize; ++i) {
        const uint8_t* p = textBase + i;
        if (p[0] != 0xFF) continue;
        if (p[1] != 0x14 && p[1] != 0x24) continue;
        if (p[2] != 0x85 && p[2] != 0x8D) continue;

        uint32_t tableAddr = *reinterpret_cast<const uint32_t*>(p + 3);
        if (tableAddr < imageStart || tableAddr + sizeof(uintptr_t) >= imageEnd) continue;

        uintptr_t entryAddr = static_cast<uintptr_t>(tableAddr) + (0x14A * sizeof(uintptr_t));
        if (entryAddr < imageStart || entryAddr + sizeof(uintptr_t) > imageEnd) continue;

        uintptr_t fn = *reinterpret_cast<uintptr_t*>(entryAddr);
        if (fn > 0x1000 && fn < imageSize) {
            fn = imageStart + fn;
        }

        if (fn >= textStart && fn < textEnd) {
            char line[128];
            std::snprintf(line, sizeof(line),
                "[ClientFix][HitGate] 0x14A handler found: 0x%p",
                reinterpret_cast<void*>(fn));
            log_line(line);
            return reinterpret_cast<void*>(fn);
        }
    }

    return nullptr;
}

static bool IsPlausibleHookTarget(void* target)
{
    uint8_t* textBase = nullptr; size_t textSize = 0;
    if (!GetTextRange(textBase, textSize)) {
        log_line("[ClientFix][HitGate] .text range not found");
        return false;
    }

    auto* ptr = reinterpret_cast<uint8_t*>(target);
    if (ptr < textBase || ptr >= textBase + textSize) {
        log_line("[ClientFix][HitGate] 0x14A handler target not in .text");
        return false;
    }

    uint8_t first = 0;
    __try { first = *ptr; }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        log_line("[ClientFix][HitGate] 0x14A handler target unreadable");
        return false;
    }

    switch (first) {
    case 0x55: // push ebp
    case 0x53: // push ebx
    case 0x56: // push esi
    case 0x57: // push edi
        return true;
    default:
        break;
    }

    char line[128];
    std::snprintf(line, sizeof(line),
        "[ClientFix][HitGate] 0x14A handler target byte not plausible: 0x%02X",
        first);
    log_line(line);
    return false;
}

void HitGate_Init()
{
    void* target = ResolveAttackerStateHandler();
    if (!target) {
        log_line("[ClientFix][HitGate] 0x14A handler not found");
        return;
    }

    if (!IsPlausibleHookTarget(target)) {
        log_line("[ClientFix][HitGate] 0x14A handler hook skipped (invalid target)");
        return;
    }

    if (MH_CreateHook(target, &hk14A, &g_Ori14A) == MH_OK &&
        MH_EnableHook(target) == MH_OK) {
        g_14AStart = static_cast<uint8_t*>(target);
        log_line("[ClientFix][HitGate] 0x14A handler hook installed (naked)");
    }
    else {
        log_line("[ClientFix][HitGate] 0x14A handler hook FAILED");
    }
}
