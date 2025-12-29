#include "hitgate.h"

#include <windows.h>
#include <vector>
#include <mutex>
#include <cstdio>
#include <cstdint>
#include <cstring>

#include "aob_scan.h"
#include "task_queue.h"
#include "frame_fence.h"

static void log_line(const char* s) { OutputDebugStringA(s); OutputDebugStringA("\n"); }

static std::atomic<long> gHitGateOn{ 1 };
static std::atomic<long> gBlockProcVisuals{ 0 };

static std::atomic<uint32_t> gRenderTid{ 0 };
static std::atomic<uint32_t> gDispatchTid{ 0 };
static std::atomic<bool> gTidLogged{ false };

static std::atomic<uint32_t> gHoldUntilFrame{ 0 };
static std::atomic<int> gHoldBudget{ 0 };
static std::atomic<bool> gHoldEnabled{ false };

static std::atomic<uint32_t> gDispatchHits{ 0 };
static std::atomic<uint32_t> gLastOpcode{ 0 };
static std::atomic<uint32_t> gLastTid{ 0 };
static std::atomic<uint32_t> gSaw14A{ 0 };

static uint8_t* gDispatchCallsite = nullptr;
static uint32_t gDispatchTableDisp = 0;
static uint8_t* gDispatchRet = nullptr;
static bool gDispatchUsesEcx = false;
static uint8_t* gDispatchStub = nullptr;
static int gDispatchScore = 0;

static void MaybeLogThreadIds();

struct DeferredSVK {
    void* self;
    int a1;
    int a2;
    SVKStarter_t orig;
};

static std::mutex gDeferredMx;
static std::vector<DeferredSVK> gDeferredSVK;

static void SafeCallSVK(void* self, int a1, int a2, SVKStarter_t orig)
{
    __try { orig(self, a1, a2); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

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
            SafeCallSVK(entry.self, entry.a1, entry.a2, entry.orig);
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

void HitGate_SetRenderThreadId(uint32_t tid)
{
    uint32_t expected = 0;
    if (gRenderTid.compare_exchange_strong(expected, tid)) {
        FrameFence_Init();
    }
    MaybeLogThreadIds();
}

static void MaybeLogThreadIds()
{
    if (gTidLogged.load()) return;
    uint32_t render = gRenderTid.load();
    uint32_t dispatch = gDispatchTid.load();
    if (render == 0 || dispatch == 0) return;
    if (!gTidLogged.exchange(true)) {
        char line[160];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] thread ids render=%lu dispatch=%lu",
            static_cast<unsigned long>(render),
            static_cast<unsigned long>(dispatch));
        log_line(line);
    }
}

// -------------------- dispatch callsite hook --------------------
static void __cdecl OnDispatchEnter(uint32_t opcode)
{
    gDispatchHits.fetch_add(1, std::memory_order_relaxed);
    gLastOpcode.store(opcode, std::memory_order_relaxed);
    gLastTid.store(GetCurrentThreadId(), std::memory_order_relaxed);

    if (!HitGate_IsEnabled()) return;

    uint32_t expected = 0;
    gDispatchTid.compare_exchange_strong(expected, GetCurrentThreadId());
    MaybeLogThreadIds();

    if (opcode == 0x14A) {
        gSaw14A.fetch_add(1, std::memory_order_relaxed);
        static int c = 0;
        if (c++ < 50) {
            log_line("[ClientFix][HitGate] SAW opcode 0x14A");
        }
        gHoldEnabled.store(true);

        const uint32_t hold = FrameFence_Id() + 1;
        gHoldUntilFrame.store(hold);
        gHoldBudget.store(32);
        char line[128];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] hold armed opcode=0x14A until=%u",
            hold);
        log_line(line);
        return;
    }

    if (!gHoldEnabled.load()) return;

    const uint32_t hold = gHoldUntilFrame.load();
    if (hold == 0) return;
    if (gHoldBudget.load() <= 0) {
        gHoldUntilFrame.store(0);
        return;
    }

    const uint32_t renderTid = gRenderTid.load();
    const uint32_t dispatchTid = gDispatchTid.load();
    if (renderTid != 0 && renderTid == dispatchTid) {
        gHoldUntilFrame.store(0);
        gHoldBudget.store(0);
        return;
    }

    if (renderTid == 0 || dispatchTid == 0) {
        if (FrameFence_Id() >= hold) gHoldUntilFrame.store(0);
        return;
    }

    const int budgetBefore = gHoldBudget.fetch_sub(1);
    if (budgetBefore > 0) {
        const DWORD start = GetTickCount();
        static DWORD s_lastHoldLog = 0;
        const DWORD now = start;
        if (now - s_lastHoldLog > 1000) {
            s_lastHoldLog = now;
            char line[160];
            std::snprintf(line, sizeof(line),
                "[ClientFix][HitGate] holding dispatch until frame=%u budget=%d",
                hold, budgetBefore);
            log_line(line);
        }
        while (FrameFence_Id() < hold) {
            if (GetTickCount() - start > 20) break;
            Sleep(0);
        }
    }

    if (FrameFence_Id() >= hold || gHoldBudget.load() <= 0) {
        gHoldUntilFrame.store(0);
    }
}

static uint8_t* BuildDispatchStub(bool usesEcx, uint32_t tableDisp, uint8_t* retaddr)
{
    std::vector<uint8_t> code;
    auto emit = [&code](uint8_t b) { code.push_back(b); };
    auto emit32 = [&code](uint32_t v) {
        code.push_back(static_cast<uint8_t>(v));
        code.push_back(static_cast<uint8_t>(v >> 8));
        code.push_back(static_cast<uint8_t>(v >> 16));
        code.push_back(static_cast<uint8_t>(v >> 24));
    };

    emit(0x9C); // pushfd
    emit(0x60); // pushad
    emit(usesEcx ? 0x51 : 0x50); // push ecx/eax
    emit(0xE8); // call rel32
    size_t callRelPos = code.size();
    emit32(0);
    emit(0x83); emit(0xC4); emit(0x04); // add esp, 4
    emit(0x61); // popad
    emit(0x9D); // popfd
    emit(0xFF); emit(0x14); emit(usesEcx ? 0x8D : 0x85); // call [reg*4 + disp32]
    size_t dispPos = code.size();
    emit32(tableDisp);
    emit(0xE9); // jmp rel32
    size_t jmpRelPos = code.size();
    emit32(0);

    uint8_t* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, code.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!stub) return nullptr;

    std::memcpy(stub, code.data(), code.size());

    int32_t callRel = reinterpret_cast<uint8_t*>(&OnDispatchEnter) -
        (stub + callRelPos + sizeof(int32_t));
    std::memcpy(stub + callRelPos, &callRel, sizeof(callRel));

    int32_t jmpRel = retaddr - (stub + jmpRelPos + sizeof(int32_t));
    std::memcpy(stub + jmpRelPos, &jmpRel, sizeof(jmpRel));

    FlushInstructionCache(GetCurrentProcess(), stub, code.size());
    return stub;
}

static bool ReadPtr(uintptr_t addr, uintptr_t& out)
{
    __try {
        out = *reinterpret_cast<uintptr_t*>(addr);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool FindDispatchCallsite()
{
    uint8_t* textBase = nullptr; size_t textSize = 0;
    uint8_t* imageBase = nullptr; size_t imageSize = 0;
    if (!GetTextRange(textBase, textSize) || !GetImageRange(imageBase, imageSize)) return false;

    uintptr_t imageStart = reinterpret_cast<uintptr_t>(imageBase);
    uintptr_t imageEnd = imageStart + imageSize;
    uintptr_t textStart = reinterpret_cast<uintptr_t>(textBase);
    uintptr_t textEnd = textStart + textSize;
    auto normalize_ptr = [&](uintptr_t ptr) -> uintptr_t {
        if (ptr > 0x1000 && ptr < imageSize) return imageStart + ptr;
        return ptr;
    };
    auto ptr_in_text = [&](uintptr_t ptr) -> bool {
        return ptr >= textStart && ptr < textEnd;
    };

    int bestScore = -1;
    uint8_t* bestSite = nullptr;
    uint32_t bestTable = 0;
    bool bestUsesEcx = false;
    int candidates = 0;

    for (size_t i = 0; i + 7 <= textSize; ++i) {
        const uint8_t* p = textBase + i;
        if (p[0] != 0xFF) continue;
        if (p[1] != 0x14) continue;
        if (p[2] != 0x85 && p[2] != 0x8D) continue;

        ++candidates;
        uint32_t tableAddr = *reinterpret_cast<const uint32_t*>(p + 3);
        if (tableAddr < imageStart || tableAddr + sizeof(uintptr_t) >= imageEnd) continue;

        uintptr_t tableStart = static_cast<uintptr_t>(tableAddr);
        uintptr_t tableEnd = tableStart + ((512 + 1) * sizeof(uintptr_t));
        if (tableEnd > imageEnd) continue;

        uintptr_t entryAddr = tableStart + (0x14A * sizeof(uintptr_t));
        uintptr_t fn = 0;
        if (!ReadPtr(entryAddr, fn)) continue;
        fn = normalize_ptr(fn);
        if (!ptr_in_text(fn)) continue;

        int score = 0;
        for (size_t idx = 0; idx <= 512; ++idx) {
            uintptr_t entry = 0;
            if (!ReadPtr(tableStart + (idx * sizeof(uintptr_t)), entry)) continue;
            entry = normalize_ptr(entry);
            if (ptr_in_text(entry)) ++score;
        }

        if (score < 100) continue;

        if (score > bestScore) {
            bestScore = score;
            bestSite = const_cast<uint8_t*>(p);
            bestTable = tableAddr;
            bestUsesEcx = (p[2] == 0x8D);
        }
    }

    {
        char line[160];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] dispatch candidates=%d",
            candidates);
        log_line(line);
    }

    if (!bestSite) return false;

    gDispatchCallsite = bestSite;
    gDispatchTableDisp = bestTable;
    gDispatchRet = gDispatchCallsite + 7;
    gDispatchUsesEcx = bestUsesEcx;
    gDispatchScore = bestScore;
    return true;
}

void HitGate_Init()
{
    if (!FindDispatchCallsite()) {
        log_line("[ClientFix][HitGate] dispatch callsite not found");
        return;
    }

    gDispatchStub = BuildDispatchStub(gDispatchUsesEcx, gDispatchTableDisp, gDispatchRet);
    if (!gDispatchStub) {
        log_line("[ClientFix][HitGate] dispatch stub alloc failed");
        return;
    }

    DWORD oldProt = 0;
    if (!VirtualProtect(gDispatchCallsite, 7, PAGE_EXECUTE_READWRITE, &oldProt)) {
        log_line("[ClientFix][HitGate] dispatch callsite protect failed");
        return;
    }

    int32_t rel = gDispatchStub - (gDispatchCallsite + 5);
    gDispatchCallsite[0] = 0xE8;
    std::memcpy(gDispatchCallsite + 1, &rel, sizeof(rel));
    gDispatchCallsite[5] = 0x90;
    gDispatchCallsite[6] = 0x90;

    DWORD ignore = 0;
    VirtualProtect(gDispatchCallsite, 7, oldProt, &ignore);
    FlushInstructionCache(GetCurrentProcess(), gDispatchCallsite, 7);

    {
        char line[160];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] Dispatch callsite hook installed @ 0x%p index=%s table=0x%08X score=%d",
            gDispatchCallsite, gDispatchUsesEcx ? "ECX" : "EAX", gDispatchTableDisp, gDispatchScore);
        log_line(line);
    }

    uint8_t* textBase = nullptr; size_t textSize = 0;
    uint8_t* imageBase = nullptr; size_t imageSize = 0;
    if (GetTextRange(textBase, textSize) && GetImageRange(imageBase, imageSize)) {
        uintptr_t textStart = reinterpret_cast<uintptr_t>(textBase);
        uintptr_t textEnd = textStart + textSize;
        uintptr_t imageStart = reinterpret_cast<uintptr_t>(imageBase);
        uintptr_t imageEnd = imageStart + imageSize;
        auto normalize_ptr = [&](uintptr_t ptr) -> uintptr_t {
            if (ptr > 0x1000 && ptr < imageSize) return imageStart + ptr;
            return ptr;
        };
        auto ptr_in_text = [&](uintptr_t ptr) -> bool {
            return ptr >= textStart && ptr < textEnd;
        };
        auto table = reinterpret_cast<uintptr_t*>(gDispatchTableDisp);
        for (int i = 0; i < 8; ++i) {
            uintptr_t entry = 0;
            if (!ReadPtr(reinterpret_cast<uintptr_t>(table + i), entry)) continue;
            entry = normalize_ptr(entry);
            char line[160];
            std::snprintf(line, sizeof(line),
                "[ClientFix][HitGate] table[%d]=0x%08X",
                i, static_cast<uint32_t>(entry));
            log_line(line);
        }
        if (gDispatchTableDisp >= imageStart && gDispatchTableDisp < imageEnd) {
            uintptr_t entry = 0;
            if (ReadPtr(reinterpret_cast<uintptr_t>(table + 0x14A), entry)) {
                entry = normalize_ptr(entry);
                char line[160];
                std::snprintf(line, sizeof(line),
                    "[ClientFix][HitGate] table[0x14A]=0x%08X%s",
                    static_cast<uint32_t>(entry),
                    ptr_in_text(entry) ? "" : " (NOT IN .text)");
                log_line(line);
            }
        }
    }
}

uint32_t HitGate_GetDispatchHits()
{
    return gDispatchHits.load(std::memory_order_relaxed);
}

uint32_t HitGate_GetSaw14A()
{
    return gSaw14A.load(std::memory_order_relaxed);
}

uint32_t HitGate_GetLastOpcode()
{
    return gLastOpcode.load(std::memory_order_relaxed);
}

uint32_t HitGate_GetLastDispatchTid()
{
    return gLastTid.load(std::memory_order_relaxed);
}
