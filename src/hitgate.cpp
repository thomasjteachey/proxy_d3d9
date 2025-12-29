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

static uint8_t* gDispatchCallsite = nullptr;
static uint32_t gDispatchTableDisp = 0;
static uint8_t* gDispatchRet = nullptr;
static bool gDispatchUsesEcx = false;
static uint8_t* gDispatchStub = nullptr;

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

// -------------------- dispatch callsite hook --------------------
static void __cdecl OnDispatchEnter(uint32_t opcode)
{
    if (opcode != 0x14A) return;
    log_line("[ClientFix][HitGate] HitGate armed (opcode 0x14A)");
    HitGate_ArmOneFrame();
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

    for (size_t i = 0; i + 7 <= textSize; ++i) {
        const uint8_t* p = textBase + i;
        if (p[0] != 0xFF) continue;
        if (p[1] != 0x14 && p[1] != 0x24) continue;
        if (p[2] != 0x85 && p[2] != 0x8D) continue;

        uint32_t tableAddr = *reinterpret_cast<const uint32_t*>(p + 3);
        if (tableAddr < imageStart || tableAddr + sizeof(uintptr_t) >= imageEnd) continue;

        uintptr_t entryAddr = static_cast<uintptr_t>(tableAddr) + (0x14A * sizeof(uintptr_t));
        if (entryAddr < imageStart || entryAddr + sizeof(uintptr_t) > imageEnd) continue;

        uintptr_t fn = 0;
        if (!ReadPtr(entryAddr, fn)) continue;
        if (fn > 0x1000 && fn < imageSize) {
            fn = imageStart + fn;
        }

        if (fn >= textStart && fn < textEnd) {
            gDispatchCallsite = const_cast<uint8_t*>(p);
            gDispatchTableDisp = tableAddr;
            gDispatchRet = gDispatchCallsite + 7;
            gDispatchUsesEcx = (p[2] == 0x8D);
            return true;
        }
    }

    return false;
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
            "[ClientFix][HitGate] Dispatch callsite hook installed @ 0x%p index=%s table=0x%08X",
            gDispatchCallsite, gDispatchUsesEcx ? "ECX" : "EAX", gDispatchTableDisp);
        log_line(line);
    }
}
