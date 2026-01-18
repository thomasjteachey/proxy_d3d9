#include "hitgate.h"
#include "net_trace.h"

#include <windows.h>
#include <vector>
#include <mutex>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>
#include <algorithm>

#include "aob_scan.h"
#include "task_queue.h"
#include "frame_fence.h"

// Forward decls (used before definition)
static void LogInfo(const char* fmt, ...);


static void log_line(const char* s) { OutputDebugStringA(s); OutputDebugStringA("\n"); }
static void BytesToString(const uint8_t* bytes, size_t count, char* out, size_t outSize)
{
    size_t pos = 0;
    for (size_t i = 0; i < count && pos + 3 < outSize; ++i) {
        int wrote = std::snprintf(out + pos, outSize - pos, "%02X", bytes[i]);
        if (wrote < 0) break;
        pos += static_cast<size_t>(wrote);
        if (i + 1 < count && pos + 2 < outSize) {
            out[pos++] = ' ';
            out[pos] = '\0';
        }
    }
}

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
static std::atomic<uint32_t> gSaw14ATid{ 0 };
static std::array<std::atomic<uint32_t>, 0x300> gOpcodeHitCounts{};


// fallback: if we can't find the classic opcode-dispatch callsite, we can still
// observe + optionally gate opcode dispatch by placing INT3 breakpoints on the
// indirect CALL-reg sites that drive packet dispatch in this client build.
static void InstallDispatchBreakpoints();
static uint8_t* gDispatchCallsite = nullptr;
static uint32_t gDispatchTableDisp = 0;
static uint8_t* gDispatchRet = nullptr;
static uint8_t gDispatchSib = 0;
static uint8_t gDispatchIndexReg = 0;
static uint8_t* gDispatchStub = nullptr;
static int gDispatchScore = 0;
static uint8_t gDispatchMode = 0; // 0=direct call [table+idx*4], 1=mov reg,[table+idx*4] then call reg
static uint8_t gDispatchDestReg = 0; // only used for mode=1

static uintptr_t gOpcodeTable = 0;
static int gOpcodeTableScore = 0;

static size_t gTextSize = 0;
struct JmpDetour {
    uint8_t* target = nullptr;
    uint8_t* detour = nullptr;
    uint8_t stolen[8] = {};
    size_t stolenLen = 0;
    uint8_t* trampoline = nullptr;
};

static uint8_t* gOpcode14AStub = nullptr;
static uint8_t* gOpcode14ATrampoline = nullptr;
static JmpDetour gOpcode14ADetour;

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

static void __cdecl OnOpcode14AHit()
{
    // This is called from the detoured opcode-table handler for 0x14A.
    uint32_t c = gSaw14A.fetch_add(1, std::memory_order_relaxed) + 1;
    gSaw14ATid.store(GetCurrentThreadId(), std::memory_order_relaxed);

    if (c <= 25)
        LogInfo("[HitGate] opcode 0x14A hit #%u (frame=%u)", c, NetTrace::GetFrame());

    // Allow exactly one proc-visual push through on the next frame.
    HitGate_ArmOneFrame();
}

static void __cdecl OnOpcodeProbeHit(uint32_t opcode)
{
    gDispatchHits.fetch_add(1, std::memory_order_relaxed);
    gLastOpcode.store(opcode, std::memory_order_relaxed);
    gLastTid.store(GetCurrentThreadId(), std::memory_order_relaxed);

    if (opcode == 0x14A) {
        OnOpcode14AHit();
    }

    if (opcode < gOpcodeHitCounts.size()) {
        uint32_t count = gOpcodeHitCounts[opcode].fetch_add(1, std::memory_order_relaxed);
        if (count < 5) {
            char line[160];
            std::snprintf(line, sizeof(line),
                "[ClientFix][HitGate] opcode hit opcode=0x%X count=%u",
                opcode, count + 1);
            log_line(line);
        }
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

static void __cdecl HitGate_DispatchHook(uint32_t opcode)
{
    OnDispatchEnter(opcode);
}

static void InstallDispatchBreakpoints()
{
    log_line("[ClientFix][HitGate] dispatch breakpoints not available in this build");
}


static uint8_t* BuildDispatchStub(uint8_t sib, uint32_t tableDisp, uint8_t* retaddr, uint8_t indexRegId)
{
    // The original instruction we patch is 7 bytes:  FF 14 <sib> <disp32>
    // When we replace it with a 5-byte CALL rel32, the return address pushed will be (site+5),
    // but the *real* post-instruction address is (site+7). Fix by rewriting the return address
    // on the stack to retaddr, then use RET at the end of the stub.

    uint8_t* stub = (uint8_t*)VirtualAlloc(nullptr, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub)
        return nullptr;

    uint8_t* w = stub;

    // mov dword ptr [esp], imm32   ; rewrite return address
    *w++ = 0xC7; *w++ = 0x04; *w++ = 0x24;
    *(uint32_t*)w = (uint32_t)(uintptr_t)retaddr; w += 4;

    // pushfd / pushad
    *w++ = 0x9C;
    *w++ = 0x60;

    // push <indexReg>
    *w++ = (uint8_t)(0x50 + (indexRegId & 7));

    // call HitGate_DispatchHook(uint32 opcodeIndex)
    *w++ = 0xE8;
    {
        int32_t rel = (int32_t)((uint8_t*)&HitGate_DispatchHook - (w + 4));
        *(int32_t*)w = rel;
        w += 4;
    }

    // add esp, 4
    *w++ = 0x83; *w++ = 0xC4; *w++ = 0x04;

    // popad / popfd
    *w++ = 0x61;
    *w++ = 0x9D;

    // call dword ptr [disp32 + indexReg*4]  (original semantics)
    *w++ = 0xFF; *w++ = 0x14; *w++ = sib;
    *(uint32_t*)w = tableDisp; w += 4;

    // ret  (to retaddr we wrote above)
    *w++ = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), stub, (SIZE_T)(w - stub));
    return stub;
}

static uint8_t* BuildDispatchMovStub(uint8_t destRegId, uint8_t indexRegId, uint32_t tableDisp, uint8_t* retaddr)
{
    // Handles a dispatch pattern of:
    //   mov rDest, dword ptr [disp32 + rIndex*4]
    //   ... (possibly a couple bytes) ...
    //   call rDest
    // We patch the MOV (7 bytes), do the gate/log, re-run the MOV, then RET back to retaddr (after MOV).

    uint8_t* stub = (uint8_t*)VirtualAlloc(nullptr, 128, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub)
        return nullptr;

    uint8_t* w = stub;

    // mov dword ptr [esp], imm32   ; rewrite return address to the real post-MOV address (site+7)
    *w++ = 0xC7; *w++ = 0x04; *w++ = 0x24;
    *(uint32_t*)w = (uint32_t)(uintptr_t)retaddr; w += 4;

    // pushfd / pushad
    *w++ = 0x9C;
    *w++ = 0x60;

    // push <indexReg>
    *w++ = (uint8_t)(0x50 + (indexRegId & 7));

    // call HitGate_DispatchHook(uint32 opcodeIndex)
    *w++ = 0xE8;
    {
        int32_t rel = (int32_t)((uint8_t*)&HitGate_DispatchHook - (w + 4));
        *(int32_t*)w = rel;
        w += 4;
    }

    // add esp, 4
    *w++ = 0x83; *w++ = 0xC4; *w++ = 0x04;

    // popad / popfd
    *w++ = 0x61;
    *w++ = 0x9D;

    // Re-run the original MOV: 8B /r with SIB [disp32 + indexReg*4]
    //   8B <modrm> <sib> <disp32>
    // modrm: mod=00 r/m=100 (SIB), reg=destReg
    uint8_t modrm = (uint8_t)(0x04 | ((destRegId & 7) << 3));
    // sib: scale=4 (2), index=indexReg, base=disp32 (5)
    uint8_t sib = (uint8_t)(0x80 | ((indexRegId & 7) << 3) | 0x05);

    *w++ = 0x8B;
    *w++ = modrm;
    *w++ = sib;
    *(uint32_t*)w = tableDisp; w += 4;

    // ret  (to retaddr we wrote above)
    *w++ = 0xC3;

    FlushInstructionCache(GetCurrentProcess(), stub, (SIZE_T)(w - stub));
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

static uintptr_t NormalizePtr(uintptr_t ptr, uintptr_t imageStart, size_t imageSize)
{
    if (ptr > 0x1000 && ptr < imageSize) return imageStart + ptr;
    return ptr;
}

static bool ResolveTableEntryVA(uint32_t raw, uintptr_t base, uintptr_t imageEnd, uintptr_t& outVA)
{
    uintptr_t rawPtr = static_cast<uintptr_t>(raw);
    if (rawPtr >= base && rawPtr < imageEnd) {
        outVA = rawPtr;
        return true;
    }

    uintptr_t va = base + rawPtr;
    if (va >= base && va < imageEnd) {
        outVA = va;
        return true;
    }

    return false;
}

static bool PtrInRange(uintptr_t ptr, uintptr_t start, uintptr_t end)
{
    return ptr >= start && ptr < end;
}

static void LogInfo(const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    log_line(buf);
}


enum class TableEncoding {
    Unknown,
    VA,
    RVA
};

static TableEncoding DetectTableEncoding(uintptr_t tableAddr, uintptr_t imageStart, uintptr_t imageEnd,
    int& vaHits, int& rvaHits)
{
    vaHits = 0;
    rvaHits = 0;
    constexpr size_t entryCount = 512;
    constexpr int samples = 64;
    size_t step = entryCount / samples;
    if (step == 0) step = 1;

    for (int i = 0; i < samples; ++i) {
        size_t idx = static_cast<size_t>(i) * step;
        if (idx >= entryCount) idx = entryCount - 1;
        uintptr_t entry = 0;
        if (!ReadPtr(tableAddr + (idx * sizeof(uintptr_t)), entry)) continue;
        uintptr_t rawPtr = static_cast<uint32_t>(entry);
        if (PtrInRange(rawPtr, imageStart, imageEnd)) ++vaHits;
        uintptr_t rvaVa = imageStart + rawPtr;
        if (PtrInRange(rvaVa, imageStart, imageEnd)) ++rvaHits;
    }

    if (vaHits == 0 && rvaHits == 0) return TableEncoding::Unknown;
    return (rvaHits > vaHits) ? TableEncoding::RVA : TableEncoding::VA;
}

static bool ResolveEntryByEncoding(uint32_t raw, TableEncoding encoding, uintptr_t imageStart,
    uintptr_t imageEnd, uintptr_t& outVa)
{
    if (encoding == TableEncoding::RVA) {
        uintptr_t va = imageStart + static_cast<uintptr_t>(raw);
        if (PtrInRange(va, imageStart, imageEnd)) {
            outVa = va;
            return true;
        }
        return false;
    }
    if (encoding == TableEncoding::VA) {
        uintptr_t va = static_cast<uintptr_t>(raw);
        if (PtrInRange(va, imageStart, imageEnd)) {
            outVa = va;
            return true;
        }
        return false;
    }

    return ResolveTableEntryVA(raw, imageStart, imageEnd, outVa);
}

static bool FindOpcodeTable(uintptr_t& outTable, int& outScore)
{
    uint8_t* textBase = nullptr; size_t textSize = 0;
    uint8_t* imageBase = nullptr; size_t imageSize = 0;
    uint8_t* rdataBase = nullptr; size_t rdataSize = 0;
    uint8_t* dataBase = nullptr; size_t dataSize = 0;
    if (!GetTextRange(textBase, textSize) || !GetImageRange(imageBase, imageSize)) return false;
    if (!GetSectionRange(".rdata", rdataBase, rdataSize) || !GetSectionRange(".data", dataBase, dataSize)) return false;

    const uintptr_t imageStart = reinterpret_cast<uintptr_t>(imageBase);
    const uintptr_t textStart = reinterpret_cast<uintptr_t>(textBase);
    const uintptr_t textEnd = textStart + textSize;

    const size_t entryCount = 512;
    const int minScore = 300;

    auto scan_section = [&](uint8_t* base, size_t size, uintptr_t& bestTable, int& bestScore) {
        uintptr_t start = reinterpret_cast<uintptr_t>(base);
        uintptr_t end = start + size;
        for (uintptr_t addr = start; addr + (entryCount * sizeof(uintptr_t)) <= end; addr += sizeof(uintptr_t)) {
            int score = 0;
            for (size_t idx = 0; idx < entryCount; ++idx) {
                uintptr_t entry = 0;
                if (!ReadPtr(addr + (idx * sizeof(uintptr_t)), entry)) continue;
                entry = NormalizePtr(entry, imageStart, imageSize);
                if (PtrInRange(entry, textStart, textEnd)) ++score;
            }

            if (score < minScore) continue;

            uintptr_t entry = 0;
            if (!ReadPtr(addr + (0x14A * sizeof(uintptr_t)), entry)) continue;
            uintptr_t normalized = NormalizePtr(entry, imageStart, imageSize);
            if (!PtrInRange(normalized, textStart, textEnd)) continue;

            if (score > bestScore) {
                bestScore = score;
                bestTable = addr;
            }
        }
    };

    uintptr_t bestTable = 0;
    int bestScore = -1;
    scan_section(rdataBase, rdataSize, bestTable, bestScore);
    scan_section(dataBase, dataSize, bestTable, bestScore);

    if (!bestTable) return false;
    outTable = bestTable;
    outScore = bestScore;
    return true;
}

static void LogOpcodeTable(uintptr_t tableAddr, int score)
{
    uint8_t* textBase = nullptr; size_t textSize = 0;
    uint8_t* imageBase = nullptr; size_t imageSize = 0;
    if (!GetTextRange(textBase, textSize) || !GetImageRange(imageBase, imageSize)) return;

    uintptr_t imageStart = reinterpret_cast<uintptr_t>(imageBase);
    uintptr_t textStart = reinterpret_cast<uintptr_t>(textBase);
    uintptr_t textEnd = textStart + textSize;

    char line[256];
    std::snprintf(line, sizeof(line),
        "[ClientFix][HitGate] PID=%lu opcode table candidate=0x%p score=%d",
        static_cast<unsigned long>(GetCurrentProcessId()),
        reinterpret_cast<void*>(tableAddr), score);
    log_line(line);

    for (int i = 0; i < 8; ++i) {
        uintptr_t entry = 0;
        if (!ReadPtr(tableAddr + (i * sizeof(uintptr_t)), entry)) continue;
        uintptr_t normalized = NormalizePtr(entry, imageStart, imageSize);
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] table[%d]=0x%08X%s",
            i, static_cast<uint32_t>(normalized),
            PtrInRange(normalized, textStart, textEnd) ? "" : " (NOT IN .text)");
        log_line(line);
    }

    uintptr_t entry = 0;
    if (ReadPtr(tableAddr + (0x14A * sizeof(uintptr_t)), entry)) {
        uintptr_t handlerVa = 0;
        bool resolved = ResolveTableEntryVA(static_cast<uint32_t>(entry), imageStart, imageStart + imageSize, handlerVa);
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] table[0x14A] raw=0x%08X%s va=0x%08X%s",
            static_cast<uint32_t>(entry),
            resolved ? "" : " (BAD)",
            static_cast<uint32_t>(handlerVa),
            PtrInRange(handlerVa, textStart, textEnd) ? "" : " (NOT IN .text)");
        log_line(line);
    }
}

static uint8_t* BuildOpcodeWrapperStub(uint32_t opcode, uintptr_t origHandler)
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
    emit(0x68); // push imm32
    emit32(opcode);
    emit(0xE8); // call rel32
    size_t callRelPos = code.size();
    emit32(0);
    emit(0x83); emit(0xC4); emit(0x04); // add esp, 4
    emit(0x61); // popad
    emit(0x9D); // popfd
    emit(0xB8); // mov eax, imm32
    emit32(static_cast<uint32_t>(origHandler));
    emit(0xFF); emit(0xE0); // jmp eax

    uint8_t* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, code.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!stub) return nullptr;

    std::memcpy(stub, code.data(), code.size());
    int32_t callRel = reinterpret_cast<uint8_t*>(&OnOpcodeProbeHit) -
        (stub + callRelPos + sizeof(int32_t));
    std::memcpy(stub + callRelPos, &callRel, sizeof(callRel));

    FlushInstructionCache(GetCurrentProcess(), stub, code.size());
    return stub;
}

static uint8_t* BuildOpcodeHitStub(void (*hitFn)(), uintptr_t trampoline, size_t* outTrampolineOffset)
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
    emit(0xE8); // call rel32
    size_t callRelPos = code.size();
    emit32(0);
    emit(0x61); // popad
    emit(0x9D); // popfd
    emit(0xB8); // mov eax, imm32
    size_t trampolineOffset = code.size();
    emit32(static_cast<uint32_t>(trampoline));
    emit(0xFF); emit(0xE0); // jmp eax

    uint8_t* stub = static_cast<uint8_t*>(VirtualAlloc(nullptr, code.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!stub) return nullptr;

    std::memcpy(stub, code.data(), code.size());
    int32_t callRel = reinterpret_cast<uint8_t*>(hitFn) -
        (stub + callRelPos + sizeof(int32_t));
    std::memcpy(stub + callRelPos, &callRel, sizeof(callRel));
    if (outTrampolineOffset) {
        *outTrampolineOffset = trampolineOffset;
    }

    FlushInstructionCache(GetCurrentProcess(), stub, code.size());
    return stub;
}

static bool Hook32_JmpDetour(void* target, void* detour, JmpDetour& out)
{
    if (!target || !detour) return false;
    out.target = static_cast<uint8_t*>(target);
    out.detour = static_cast<uint8_t*>(detour);
    out.stolenLen = 5;

    std::memcpy(out.stolen, out.target, out.stolenLen);

    size_t trampSize = out.stolenLen + 5;
    out.trampoline = static_cast<uint8_t*>(VirtualAlloc(nullptr, trampSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!out.trampoline) return false;

    std::memcpy(out.trampoline, out.stolen, out.stolenLen);
    out.trampoline[out.stolenLen] = 0xE9;
    int32_t backRel = (out.target + out.stolenLen) - (out.trampoline + out.stolenLen + 5);
    std::memcpy(out.trampoline + out.stolenLen + 1, &backRel, sizeof(backRel));

    DWORD oldProt = 0;
    if (!VirtualProtect(out.target, out.stolenLen, PAGE_EXECUTE_READWRITE, &oldProt)) {
        return false;
    }

    out.target[0] = 0xE9;
    int32_t detourRel = out.detour - (out.target + 5);
    std::memcpy(out.target + 1, &detourRel, sizeof(detourRel));

    DWORD ignore = 0;
    VirtualProtect(out.target, out.stolenLen, oldProt, &ignore);
    FlushInstructionCache(GetCurrentProcess(), out.target, out.stolenLen);
    FlushInstructionCache(GetCurrentProcess(), out.trampoline, trampSize);
    return true;
}

static bool GetModuleRange(HMODULE mod, uintptr_t& start, uintptr_t& end)
{
    if (!mod) return false;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(mod) + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;
    start = reinterpret_cast<uintptr_t>(mod);
    end = start + nt->OptionalHeader.SizeOfImage;
    return true;
}

static bool WriteTableEntry(uintptr_t entryAddr, uint32_t rawValue)
{
    DWORD oldProt = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(entryAddr), sizeof(uintptr_t), PAGE_READWRITE, &oldProt)) {
        char line[160];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] opcode table protect failed err=%lu",
            static_cast<unsigned long>(GetLastError()));
        log_line(line);
        return false;
    }

    *reinterpret_cast<uint32_t*>(entryAddr) = rawValue;

    DWORD ignore = 0;
    VirtualProtect(reinterpret_cast<void*>(entryAddr), sizeof(uintptr_t), oldProt, &ignore);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(entryAddr), sizeof(uintptr_t));
    return true;
}

static void AppendProbeRange(std::vector<uint16_t>& opcodes, uint16_t start, uint16_t end, size_t maxCount)
{
    if (start > end || maxCount == 0) return;
    size_t length = static_cast<size_t>(end - start + 1);
    size_t step = length / maxCount;
    if (step == 0) step = 1;
    size_t added = 0;
    for (uint16_t op = start; op <= end && added < maxCount; op = static_cast<uint16_t>(op + step)) {
        opcodes.push_back(op);
        ++added;
        if (end - op < step) break;
    }
}

static bool PatchOpcodeTableProbes(uintptr_t tableAddr)
{
    uint8_t* imageBase = nullptr; size_t imageSize = 0;
    if (!GetImageRange(imageBase, imageSize)) return false;
    uintptr_t imageStart = reinterpret_cast<uintptr_t>(imageBase);
    uintptr_t imageEnd = imageStart + imageSize;

    int vaHits = 0;
    int rvaHits = 0;
    TableEncoding encoding = DetectTableEncoding(tableAddr, imageStart, imageEnd, vaHits, rvaHits);

    {
        char line[200];
        const char* mode = (encoding == TableEncoding::RVA) ? "RVA" :
            (encoding == TableEncoding::VA) ? "VA" : "UNKNOWN";
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] tableEncoding=%s vaHits=%d rvaHits=%d",
            mode, vaHits, rvaHits);
        log_line(line);
    }

    if (encoding == TableEncoding::RVA) {
        uintptr_t entryAddr = tableAddr + (0x14A * sizeof(uintptr_t));
        uintptr_t entry = 0;
        if (!ReadPtr(entryAddr, entry)) {
            log_line("[ClientFix][HitGate] table[0x14A] read failed");
            return false;
        }

        uint32_t rawEntry = static_cast<uint32_t>(entry);
        uintptr_t handlerVa = 0;
        if (!ResolveEntryByEncoding(rawEntry, encoding, imageStart, imageEnd, handlerVa)) {
            char line[200];
            std::snprintf(line, sizeof(line),
                "[ClientFix][HitGate] table[0x14A]=0x%08X not RVA in image; skip detour",
                rawEntry);
            log_line(line);
            return false;
        }

        size_t trampolineOffset = 0;
        uint8_t* stub = BuildOpcodeHitStub(&OnOpcode14AHit, 0, &trampolineOffset);
        if (!stub) {
            log_line("[ClientFix][HitGate] opcode 0x14A stub alloc failed");
            return false;
        }

        if (!Hook32_JmpDetour(reinterpret_cast<void*>(handlerVa), stub, gOpcode14ADetour)) {
            log_line("[ClientFix][HitGate] opcode 0x14A detour failed");
            return false;
        }

        gOpcode14AStub = stub;
        gOpcode14ATrampoline = gOpcode14ADetour.trampoline;
        uint32_t trampVal = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(gOpcode14ATrampoline));
        std::memcpy(gOpcode14AStub + trampolineOffset, &trampVal, sizeof(trampVal));
        FlushInstructionCache(GetCurrentProcess(), gOpcode14AStub, 32);

        char line[240];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] detoured 0x14A handler=0x%08X raw=0x%08X stub=0x%p tramp=0x%p",
            static_cast<uint32_t>(handlerVa),
            rawEntry,
            gOpcode14AStub,
            gOpcode14ATrampoline);
        log_line(line);
        return true;
    }

    std::vector<uint16_t> opcodes;
    opcodes.reserve(64);
    AppendProbeRange(opcodes, 0x140, 0x170, 16);
    AppendProbeRange(opcodes, 0x1A0, 0x1D0, 16);
    AppendProbeRange(opcodes, 0x200, 0x240, 16);
    opcodes.push_back(0x14A);
    std::sort(opcodes.begin(), opcodes.end());
    opcodes.erase(std::unique(opcodes.begin(), opcodes.end()), opcodes.end());

    for (uint16_t opcode : opcodes) {
        uintptr_t entryAddr = tableAddr + (opcode * sizeof(uintptr_t));
        uintptr_t entry = 0;
        if (!ReadPtr(entryAddr, entry)) continue;

        uint32_t rawEntry = static_cast<uint32_t>(entry);
        uintptr_t handlerVa = 0;
        if (!ResolveEntryByEncoding(rawEntry, encoding, imageStart, imageEnd, handlerVa)) {
            char line[200];
            std::snprintf(line, sizeof(line),
                "[ClientFix][HitGate] table[0x%X]=0x%08X not VA/RVA in image; skip",
                opcode, rawEntry);
            log_line(line);
            continue;
        }

        uint8_t* stub = BuildOpcodeWrapperStub(opcode, handlerVa);
        if (!stub) continue;

        uint32_t patchedRaw = (encoding == TableEncoding::RVA)
            ? static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stub) - imageStart)
            : static_cast<uint32_t>(reinterpret_cast<uintptr_t>(stub));

        if (!WriteTableEntry(entryAddr, patchedRaw)) continue;

        if (opcode == 0x14A) {
            uintptr_t readbackEntry = 0;
            uintptr_t resolved = 0;
            ReadPtr(entryAddr, readbackEntry);
            ResolveEntryByEncoding(static_cast<uint32_t>(readbackEntry), encoding, imageStart, imageEnd, resolved);
            char line[240];
            std::snprintf(line, sizeof(line),
                "[ClientFix][HitGate] patched table[0x14A] raw=0x%08X resolvedVA=0x%08X",
                static_cast<uint32_t>(readbackEntry),
                static_cast<uint32_t>(resolved));
            log_line(line);
        }
    }

    return true;
}


// 3-arg image range helper used by dispatch-scan code.
// This is intentionally self-contained to avoid relying on other compilation units.
static bool GetImageRange(uint8_t*& start, uint8_t*& end, size_t& size)
{
    HMODULE hMod = GetModuleHandleA(nullptr);
    if (!hMod)
        return false;

    auto* base = reinterpret_cast<uint8_t*>(hMod);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    size = static_cast<size_t>(nt->OptionalHeader.SizeOfImage);
    start = base;
    end = base + size;
    return true;
}


static bool GetCurrentImageRange(uintptr_t& imageStart, uintptr_t& imageEnd)
{
    uint8_t* s = nullptr;
    uint8_t* e = nullptr;
    size_t sz = 0;
    if (!GetImageRange(s, e, sz))
        return false;
    imageStart = (uintptr_t)s;
    imageEnd = (uintptr_t)e;
    return true;
}

static uintptr_t ReadTableU32(uintptr_t tableAddr, uint32_t index)
{
    uint32_t v = 0;
    __try
    {
        v = *reinterpret_cast<uint32_t*>(tableAddr + (uintptr_t)index * sizeof(uint32_t));
        return (uintptr_t)v;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

// overload used by callsites that expect to learn whether the entry was RVA-encoded.
// NOTE: take pointers for the image bounds so callers don't need to cast.
static uintptr_t ResolveTableEntryVA(uintptr_t raw, const uint8_t* imageStartPtr, const uint8_t* imageEndPtr, size_t imageSize, bool& entryIsRva)
{
    const uintptr_t imageStart = reinterpret_cast<uintptr_t>(imageStartPtr);
    const uintptr_t imageEnd   = reinterpret_cast<uintptr_t>(imageEndPtr);

    if (raw >= imageStart && raw < imageEnd)
    {
        entryIsRva = false;
        return raw;
    }

    uintptr_t va = imageStart + raw;
    if (raw < imageSize && va >= imageStart && va < imageEnd)
    {
        entryIsRva = true;
        return va;
    }

    entryIsRva = false;
    return 0;
}

static bool FindDispatchCallsite(uintptr_t tableAddr, uint8_t* imageStart, uint8_t* imageEnd);

static bool FindDispatchCallsite()
{
    uint8_t* textBase = nullptr;
    size_t   textSize = 0;
    if (!GetTextRange(textBase, textSize))
        return false;
    gTextSize = textSize;

    uintptr_t imageStart = 0;
    uintptr_t imageEnd = 0;
    if (!GetCurrentImageRange(imageStart, imageEnd))
        return false;

    uintptr_t tableAddr = gOpcodeTable;
    if (tableAddr == 0) {
        int score = 0;
        if (!FindOpcodeTable(tableAddr, score))
            return false;
        gOpcodeTable = tableAddr;
        gOpcodeTableScore = score;
    }

    return FindDispatchCallsite(tableAddr,
        reinterpret_cast<uint8_t*>(imageStart),
        reinterpret_cast<uint8_t*>(imageEnd));
}

static bool FindDispatchCallsite(uintptr_t tableAddr, uint8_t* imageStart, uint8_t* imageEnd)
{
    // We want to hook the main opcode dispatch so we can observe/gate combat opcodes.
    // Some builds use a direct:
    //   call dword ptr [disp32 + idx*4]        ; FF 14 <sib> <disp32>
    // Other builds use:
    //   mov rDest, dword ptr [disp32 + idx*4]  ; 8B /r <sib> <disp32>
    //   call rDest

    gDispatchCallsite = nullptr;
    gDispatchRet = nullptr;
    gDispatchScore = 0;
    gDispatchMode = 0;
    gDispatchDestReg = 0;
    gDispatchSib = 0;
    gDispatchIndexReg = 0;
    gDispatchTableDisp = 0;

    if (!imageStart || !imageEnd || imageEnd <= imageStart)
        return false;

    uint32_t imageSize = (uint32_t)(imageEnd - imageStart);

    // .text start heuristic used elsewhere in the project
    uint8_t* textStart = imageStart + 0x1000;
    uint8_t* textEnd = imageStart + gTextSize;
    if (textEnd > imageEnd)
        textEnd = imageEnd;

    if (textEnd <= textStart + 16)
        return false;

    // Sanity: resolve 0x14A to ensure tableAddr looks like a real opcode table.
    bool entryIsRva = false;
    uintptr_t raw14A = ReadTableU32(tableAddr, 0x14A);
    uintptr_t handler14A = ResolveTableEntryVA(raw14A, imageStart, imageEnd, imageSize, entryIsRva);
    bool handler14AInText = (handler14A >= (uintptr_t)textStart && handler14A < (uintptr_t)textEnd);

    uint8_t* bestSite = nullptr;
    uint8_t bestSib = 0;
    uint8_t bestIdx = 0;
    uint8_t bestMode = 0;
    uint8_t bestDest = 0;
    int bestScore = 0;

    for (uint8_t* p = textStart; p + 7 <= textEnd; ++p)
    {
        // Pattern A: call dword ptr [disp32 + idx*4]  => FF 14 <sib> <disp32>
        if (p[0] == 0xFF && p[1] == 0x14)
        {
            uint8_t sib = p[2];
            uint32_t disp32 = *(uint32_t*)(p + 3);

            if (disp32 == (uint32_t)tableAddr)
            {
                uint8_t idxReg = (sib >> 3) & 7;
                if (idxReg != 4) // index=ESP is invalid for SIB
                {
                    int score = 600;
                    if (handler14AInText)
                        score += 50;

                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestSite = p;
                        bestSib = sib;
                        bestIdx = idxReg;
                        bestMode = 0;
                        bestDest = 0;
                    }
                }
            }
        }

        // Pattern B: mov rDest, dword ptr [disp32 + idx*4]  => 8B <modrm> <sib> <disp32>
        //            then a nearby "call rDest" (FF D0+dest)
        if (p[0] == 0x8B && ((p[1] & 0xC7) == 0x04))
        {
            uint8_t modrm = p[1];
            uint8_t sib = p[2];
            uint32_t disp32 = *(uint32_t*)(p + 3);

            if (disp32 == (uint32_t)tableAddr)
            {
                uint8_t scale = (sib >> 6) & 3;
                uint8_t idxReg = (sib >> 3) & 7;
                uint8_t base = sib & 7;

                if (scale == 2 && base == 5 && idxReg != 4)
                {
                    uint8_t destReg = (modrm >> 3) & 7;

                    bool hasCall = false;
                    uint8_t callModrm = (uint8_t)(0xD0 + (destReg & 7)); // FF /2 with mod=11
                    for (uint8_t* q = p + 7; q + 2 <= textEnd && q < p + 7 + 32; ++q)
                    {
                        if (q[0] == 0xFF && q[1] == callModrm)
                        {
                            hasCall = true;
                            break;
                        }
                    }

                    int score = hasCall ? 750 : 500;
                    if (handler14AInText)
                        score += 25;

                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestSite = p;
                        bestSib = sib;
                        bestIdx = idxReg;
                        bestMode = 1;
                        bestDest = destReg;
                    }
                }
            }
        }
    }

    if (!bestSite)
        return false;

    gDispatchScore = bestScore;
    gDispatchCallsite = bestSite;
    gDispatchRet = bestSite + 7;
    gDispatchSib = bestSib;
    gDispatchIndexReg = bestIdx;
    gDispatchMode = bestMode;
    gDispatchDestReg = bestDest;
    gDispatchTableDisp = (uint32_t)tableAddr;

    LogInfo("[ClientFix][HitGate] dispatch callsite=0x%08X mode=%u idxReg=%u destReg=%u disp=0x%08X score=%d",
        (uint32_t)(uintptr_t)gDispatchCallsite,
        (unsigned)gDispatchMode,
        (unsigned)gDispatchIndexReg,
        (unsigned)gDispatchDestReg,
        (unsigned)gDispatchTableDisp,
        gDispatchScore);

    return true;
}


static const char* GetExeBasename(char* out, size_t outSize)
{
    if (outSize == 0) return "";
    out[0] = '\0';
    char path[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(nullptr, path, static_cast<DWORD>(sizeof(path)));
    if (len == 0) return "";
    const char* lastSlash = strrchr(path, '\\');
    const char* lastFwd = strrchr(path, '/');
    const char* last = lastSlash ? lastSlash : lastFwd;
    if (lastFwd && lastSlash) {
        last = (lastFwd > lastSlash) ? lastFwd : lastSlash;
    } else if (lastFwd) {
        last = lastFwd;
    }
    const char* exe = (last && *(last + 1) != '\0') ? last + 1 : path;
    std::snprintf(out, outSize, "%s", exe);
    return out;
}

void HitGate_Init()
{
    {
        uintptr_t exeStart = 0;
        uintptr_t exeEnd = 0;
        if (GetModuleRange(GetModuleHandleA(nullptr), exeStart, exeEnd)) {
            char line[200];
            std::snprintf(line, sizeof(line),
                "[ClientFix][HitGate] wow.exe base=0x%p end=0x%p size=0x%X",
                reinterpret_cast<void*>(exeStart),
                reinterpret_cast<void*>(exeEnd),
                static_cast<unsigned int>(exeEnd - exeStart));
            log_line(line);
        }

        uintptr_t dllStart = 0;
        uintptr_t dllEnd = 0;
        HMODULE dllMod = GetModuleHandleA("d3d9.dll");
        if (GetModuleRange(dllMod, dllStart, dllEnd)) {
            char line[200];
            std::snprintf(line, sizeof(line),
                "[ClientFix][HitGate] d3d9.dll base=0x%p end=0x%p size=0x%X",
                reinterpret_cast<void*>(dllStart),
                reinterpret_cast<void*>(dllEnd),
                static_cast<unsigned int>(dllEnd - dllStart));
            log_line(line);
        }

        char line[200];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] OnOpcode14AHit=0x%p",
            reinterpret_cast<void*>(&OnOpcode14AHit));
        log_line(line);
    }

    uintptr_t opcodeTable = 0;
    int opcodeScore = 0;
    if (FindOpcodeTable(opcodeTable, opcodeScore)) {
        gOpcodeTable = opcodeTable;
        gOpcodeTableScore = opcodeScore;
        LogOpcodeTable(opcodeTable, opcodeScore);
        PatchOpcodeTableProbes(opcodeTable);
    } else {
        log_line("[ClientFix][HitGate] opcode handler table not found");
    }

    if (!FindDispatchCallsite()) {
        log_line("[ClientFix][HitGate] dispatch callsite not found");
        InstallDispatchBreakpoints();
        return;
    }

    auto index_reg_name = [](uint8_t regId) {
        switch (regId) {
        case 0: return "EAX";
        case 1: return "ECX";
        case 2: return "EDX";
        case 3: return "EBX";
        case 5: return "EBP";
        case 6: return "ESI";
        case 7: return "EDI";
        default: return "UNKNOWN";
        }
    };
    {
        char line[220];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] dispatch selected callsite=0x%p sib=0x%02X idxReg=%s table=0x%08X score=%d",
            gDispatchCallsite, (unsigned)gDispatchMode, gDispatchSib, index_reg_name(gDispatchIndexReg),
            (unsigned)gDispatchDestReg, gDispatchTableDisp, gDispatchScore);
        log_line(line);
    }

    gDispatchStub = (gDispatchMode == 0)
        ? BuildDispatchStub(gDispatchSib, gDispatchTableDisp, gDispatchRet, gDispatchIndexReg)
        : BuildDispatchMovStub(gDispatchDestReg, gDispatchIndexReg, gDispatchTableDisp, gDispatchRet);
    if (!gDispatchStub) {
        log_line("[ClientFix][HitGate] dispatch stub alloc failed");
        return;
    }

    DWORD oldProt = 0;
    if (!VirtualProtect(gDispatchCallsite, 7, PAGE_EXECUTE_READWRITE, &oldProt)) {
        char line[160];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] dispatch callsite protect failed err=%lu",
            static_cast<unsigned long>(GetLastError()));
        log_line(line);
        return;
    }

    uint8_t before[8] = {};
    std::memcpy(before, gDispatchCallsite, sizeof(before));

    int32_t rel = gDispatchStub - (gDispatchCallsite + 5);
    gDispatchCallsite[0] = 0xE8;
    std::memcpy(gDispatchCallsite + 1, &rel, sizeof(rel));
    gDispatchCallsite[5] = 0x90;
    gDispatchCallsite[6] = 0x90;

    DWORD ignore = 0;
    VirtualProtect(gDispatchCallsite, 7, oldProt, &ignore);
    FlushInstructionCache(GetCurrentProcess(), gDispatchCallsite, 7);

    uint8_t after[8] = {};
    std::memcpy(after, gDispatchCallsite, sizeof(after));
    char beforeText[64] = {};
    char afterText[64] = {};
    BytesToString(before, sizeof(before), beforeText, sizeof(beforeText));
    BytesToString(after, sizeof(after), afterText, sizeof(afterText));
    {
        char line[220];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] dispatch callsite bytes BEFORE=%s AFTER=%s",
            beforeText, afterText);
        log_line(line);
    }
    bool patchOk = true;
    if (std::memcmp(before, after, sizeof(before)) == 0) {
        log_line("[ClientFix][HitGate] dispatch callsite bytes unchanged after patch");
        patchOk = false;
    }
    if (after[0] != 0xE8) {
        log_line("[ClientFix][HitGate] PATCH FAILED: callsite does not start with E8");
        patchOk = false;
    }
    if (!patchOk) {
        gHitGateOn.store(0);
        return;
    }

    {
        char exeName[MAX_PATH] = {};
        GetExeBasename(exeName, sizeof(exeName));
        char line[256];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] PID=%lu EXE=%s base=0x%p callsite=0x%p table=0x%08X AFTER=%s",
            static_cast<unsigned long>(GetCurrentProcessId()),
            exeName[0] ? exeName : "(unknown)",
            GetModuleHandleA(nullptr),
            gDispatchCallsite,
            gDispatchTableDisp,
            afterText);
        log_line(line);
    }

    {
        char line[200];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] Dispatch callsite hook installed @ 0x%p mode=%u sib=0x%02X idxReg=%s destReg=%u table=0x%08X score=%d",
            gDispatchCallsite, (unsigned)gDispatchMode, gDispatchSib, index_reg_name(gDispatchIndexReg),
            (unsigned)gDispatchDestReg, gDispatchTableDisp, gDispatchScore);
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

uint32_t HitGate_GetSaw14ATid()
{
    return gSaw14ATid.load(std::memory_order_relaxed);
}

uint32_t HitGate_GetLastOpcode()
{
    return gLastOpcode.load(std::memory_order_relaxed);
}

uint32_t HitGate_GetLastDispatchTid()
{
    return gLastTid.load(std::memory_order_relaxed);
}
