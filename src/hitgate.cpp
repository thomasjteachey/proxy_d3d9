#include "hitgate.h"

#include <windows.h>
#include <vector>
#include <mutex>
#include <cstdio>

#include "MinHook.h"
#include "aob_scan.h"
#include "task_queue.h"
#include "frame_fence.h"

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

    {
        char line[128];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] flush frame=%u deferred=%zu",
            FrameFence_Id(), pending.size());
        log_line(line);
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
    if (tls_in14a > 0) {
        log_line("[ClientFix][HitGate] SVK immediate (tls_in14a)");
        return false;
    }
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

// -------------------- 0x14A handler hook --------------------
using AttackerStateHandler_t = void(__thiscall*)(void* self, void* pkt);
static AttackerStateHandler_t gAttackerStateHandler = nullptr;

static void __fastcall hkAttackerStateHandler(void* self, void* /*edx*/, void* pkt)
{
    ++tls_in14a;
    log_line("[ClientFix][HitGate] attackerstate handler hit");
    if (gAttackerStateHandler) {
        gAttackerStateHandler(self, pkt);
    }
    HitGate_ArmOneFrame();
    --tls_in14a;
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
