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

static uint8_t* gDispatchCallsite = nullptr;
static uint32_t gDispatchTableDisp = 0;
static uint8_t* gDispatchRet = nullptr;
static uint8_t gDispatchSib = 0;
static uint8_t gDispatchIndexReg = 0;
static uint8_t* gDispatchStub = nullptr;
static int gDispatchScore = 0;

static uintptr_t gOpcodeTable = 0;
static int gOpcodeTableScore = 0;
static void* gOrig14A = nullptr;

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
    gSaw14A.fetch_add(1, std::memory_order_relaxed);
    gSaw14ATid.store(GetCurrentThreadId(), std::memory_order_relaxed);
}

extern "C" __declspec(naked) void My14AWrapper()
{
    __asm {
        pushfd
        pushad
    }
    OnOpcode14AHit();
    __asm {
        popad
        popfd
        jmp dword ptr [gOrig14A]
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

static uint8_t* BuildDispatchStub(uint8_t sib, uint32_t tableDisp, uint8_t* retaddr, uint8_t indexRegId)
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
    emit(static_cast<uint8_t>(0x50 + indexRegId)); // push <index-reg>
    emit(0xE8); // call rel32
    size_t callRelPos = code.size();
    emit32(0);
    emit(0x83); emit(0xC4); emit(0x04); // add esp, 4
    emit(0x61); // popad
    emit(0x9D); // popfd
    emit(0xFF); emit(0x14); emit(sib); // call [reg*4 + disp32]
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

static bool PatchOpcode14A(uintptr_t tableAddr)
{
    uint8_t* imageBase = nullptr; size_t imageSize = 0;
    if (!GetImageRange(imageBase, imageSize)) return false;
    uintptr_t imageStart = reinterpret_cast<uintptr_t>(imageBase);
    uintptr_t imageEnd = imageStart + imageSize;

    uintptr_t entryAddr = tableAddr + (0x14A * sizeof(uintptr_t));
    uintptr_t entry = 0;
    if (!ReadPtr(entryAddr, entry)) return false;

    uintptr_t handlerVa = 0;
    uint32_t rawEntry = static_cast<uint32_t>(entry);
    if (!ResolveTableEntryVA(rawEntry, imageStart, imageEnd, handlerVa)) {
        char line[200];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] table[0x14A]=0x%08X not VA/RVA in image; abort",
            rawEntry);
        log_line(line);
        return false;
    }

    {
        char line[200];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] table[0x14A] raw=0x%08X -> handlerVA=0x%08X (base=0x%p)",
            rawEntry, static_cast<uint32_t>(handlerVa), reinterpret_cast<void*>(imageStart));
        log_line(line);
    }

    gOrig14A = reinterpret_cast<void*>(handlerVa);

    DWORD oldProt = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(entryAddr), sizeof(uintptr_t), PAGE_READWRITE, &oldProt)) {
        char line[160];
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] opcode table protect failed err=%lu",
            static_cast<unsigned long>(GetLastError()));
        log_line(line);
        return false;
    }

    *reinterpret_cast<uintptr_t*>(entryAddr) = reinterpret_cast<uintptr_t>(&My14AWrapper);

    DWORD ignore = 0;
    VirtualProtect(reinterpret_cast<void*>(entryAddr), sizeof(uintptr_t), oldProt, &ignore);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(entryAddr), sizeof(uintptr_t));

    char line[200];
    std::snprintf(line, sizeof(line),
        "[ClientFix][HitGate] patched table[0x14A] orig=0x%08X wrapper=0x%08X",
        static_cast<uint32_t>(handlerVa),
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&My14AWrapper)));
    log_line(line);
    return true;
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
    uint8_t bestSib = 0;
    uint8_t bestIndexReg = 0;
    int candidates = 0;

    for (size_t i = 0; i + 7 <= textSize; ++i) {
        const uint8_t* p = textBase + i;
        if (p[0] != 0xFF) continue;
        if (p[1] != 0x14) continue;
        uint8_t sib = p[2];
        bool scale4 = (sib & 0xC0) == 0x80;
        bool baseNone = (sib & 0x07) == 0x05;
        uint8_t idx = (sib >> 3) & 0x07;
        bool idxOk = (idx != 4);
        if (!(scale4 && baseNone && idxOk)) continue;

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
            bestSib = sib;
            bestIndexReg = idx;
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
    gDispatchSib = bestSib;
    gDispatchIndexReg = bestIndexReg;
    gDispatchScore = bestScore;
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
    uintptr_t opcodeTable = 0;
    int opcodeScore = 0;
    if (FindOpcodeTable(opcodeTable, opcodeScore)) {
        gOpcodeTable = opcodeTable;
        gOpcodeTableScore = opcodeScore;
        LogOpcodeTable(opcodeTable, opcodeScore);
        PatchOpcode14A(opcodeTable);
    } else {
        log_line("[ClientFix][HitGate] opcode handler table not found");
    }

    if (!FindDispatchCallsite()) {
        log_line("[ClientFix][HitGate] dispatch callsite not found");
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
            gDispatchCallsite, gDispatchSib, index_reg_name(gDispatchIndexReg),
            gDispatchTableDisp, gDispatchScore);
        log_line(line);
    }

    gDispatchStub = BuildDispatchStub(gDispatchSib, gDispatchTableDisp, gDispatchRet, gDispatchIndexReg);
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
            "[ClientFix][HitGate] Dispatch callsite hook installed @ 0x%p sib=0x%02X idxReg=%s table=0x%08X score=%d",
            gDispatchCallsite, gDispatchSib, index_reg_name(gDispatchIndexReg),
            gDispatchTableDisp, gDispatchScore);
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
