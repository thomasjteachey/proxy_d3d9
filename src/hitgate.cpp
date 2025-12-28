#include "hitgate.h"

#include <windows.h>
#include <vector>
#include <mutex>

#include "MinHook.h"
#include "aob_scan.h"
#include "task_queue.h"

static void log_line(const char* s) { OutputDebugStringA(s); OutputDebugStringA("\n"); }

static std::atomic<long> gHitGateOn{ 1 };
static std::atomic<long> gBlockProcVisuals{ 0 };
static thread_local int tls_in14a = 0;

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

    if (!pending.empty()) {
        log_line("[ClientFix][HitGate] flush");
    }

    for (const auto& entry : pending) {
        if (entry.orig) {
            entry.orig(entry.self, entry.a1, entry.a2);
        }
    }
}

void HitGate_ArmOneFrame()
{
    if (!HitGate_IsEnabled()) return;

    if (gBlockProcVisuals.exchange(1) == 0) {
        log_line("[ClientFix][HitGate] armed");
        ScheduleNextFrame([] {
            gBlockProcVisuals.store(0);
            HitGate_FlushDeferred();
        });
    }
}

bool HitGate_TryDeferSVK(void* self, int a1, int a2, SVKStarter_t orig)
{
    if (!HitGate_IsEnabled()) return false;
    if (tls_in14a > 0) {
        log_line("[ClientFix][HitGate] SVK immediate (tls_in14a)");
        return false;
    }
    if (gBlockProcVisuals.load() == 0) return false;

    {
        std::lock_guard<std::mutex> lock(gDeferredMx);
        gDeferredSVK.push_back({ self, a1, a2, orig });
    }

    log_line("[ClientFix][HitGate] SVK deferred");
    return true;
}

bool HitGate_IsEnabled()
{
    return gHitGateOn.load() != 0;
}

// -------------------- 0x14A handler hook --------------------
using AttackerStateHandler_t = void(__thiscall*)(void* self, void* pkt);
static AttackerStateHandler_t gAttackerStateHandler = nullptr;

static void __fastcall hkAttackerStateHandler(void* self, void* /*edx*/, void* pkt)
{
    ++tls_in14a;
    HitGate_ArmOneFrame();
    if (gAttackerStateHandler) {
        gAttackerStateHandler(self, pkt);
    }
    --tls_in14a;
}

static void* ResolveAttackerStateHandler()
{
    // Pattern: 66 3D 4A 01 75 ?? E8 ?? ?? ?? ??
    // cmp ax, 014A; jne short; call rel32
    const uint8_t pat1[] = { 0x66, 0x3D, 0x4A, 0x01, 0x75, 0x00, 0xE8, 0, 0, 0, 0 };
    const char* mask1 = "xxxxx?x????";
    auto* hit = static_cast<uint8_t*>(FindPattern(pat1, mask1));
    if (hit) {
        int32_t rel = *reinterpret_cast<int32_t*>(hit + 7);
        return hit + 11 + rel;
    }

    // Alternate: 66 3D 4A 01 0F 85 ?? ?? ?? ?? E8 ?? ?? ?? ??
    const uint8_t pat2[] = {
        0x66, 0x3D, 0x4A, 0x01, 0x0F, 0x85, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0
    };
    const char* mask2 = "xxxxxx????x????";
    hit = static_cast<uint8_t*>(FindPattern(pat2, mask2));
    if (hit) {
        int32_t rel = *reinterpret_cast<int32_t*>(hit + 11);
        return hit + 15 + rel;
    }

    return nullptr;
}

void HitGate_Init()
{
    void* target = ResolveAttackerStateHandler();
    if (!target) {
        log_line("[ClientFix][HitGate] 0x14A handler not found");
        return;
    }

    if (MH_CreateHook(target, &hkAttackerStateHandler, reinterpret_cast<void**>(&gAttackerStateHandler)) == MH_OK &&
        MH_EnableHook(target) == MH_OK) {
        log_line("[ClientFix][HitGate] 0x14A handler hook installed");
    }
    else {
        log_line("[ClientFix][HitGate] 0x14A handler hook FAILED");
    }
}
