// hooks.cpp — EndScene + SVK auto-discovery; F7 = cycle active candidate (safe, deferred)

#include "hooks.h"
#include "MinHook.h"

#include <windows.h>
#include <d3d9.h>
#include <cstdint>
#include <cstdio>
#include <vector>
#include <cstring>
#include <intrin.h>
#include "net_trace.h"
#include "frame_fence.h"
#include "hitgate.h"


#include "task_queue.h"   // RunScheduled()

// ------------------------ logging helpers ------------------------
static void dbg(const char* s) { OutputDebugStringA(s); }
static void dbgln(const char* s) { OutputDebugStringA(s); OutputDebugStringA("\n"); }
static void dbgprintf(const char* fmt, ...) {
    char b[512];
    va_list ap; va_start(ap, fmt);
    _vsnprintf_s(b, _TRUNCATE, fmt, ap);
    va_end(ap);
    dbgln(b);
}
static const char* hex24(const uint8_t* p) {
    static char buf[3 * 24 + 1];
    for (int i = 0; i < 24; i++) sprintf_s(&buf[i * 3], 4, "%02X ", p[i]);
    buf[3 * 24] = '\0';
    return buf;
}

// -------------------------- PE helpers ---------------------------
static bool GetSectionRange(HMODULE mod, const char* name, uint8_t*& base, size_t& size) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>((uint8_t*)mod + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        char nm[9] = {}; memcpy(nm, sec->Name, 8);
        if (_stricmp(nm, name) == 0) {
            base = (uint8_t*)mod + sec->VirtualAddress;
            size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            return true;
        }
    }
    return false;
}
static uint8_t* FindAscii(uint8_t* base, size_t sz, const char* needle) {
    size_t n = strlen(needle);
    if (!n || sz < n) return nullptr;
    for (size_t i = 0; i + n <= sz; ++i) if (memcmp(base + i, needle, n) == 0) return base + i;
    return nullptr;
}
static uint8_t* FindFuncStart(uint8_t* p, uint8_t* textBase) {
    for (int i = 0; i < 0x400; ++i) {
        uint8_t* q = p - i; if (q < textBase) break;
        __try { if (q[0] == 0x55 && q[1] == 0x8B && q[2] == 0xEC) return q; }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }
    }
    return nullptr;
}

// ------------------------------ EndScene --------------------------
using EndScene_t = HRESULT(WINAPI*)(IDirect3DDevice9* dev);
static EndScene_t oEndScene = nullptr;

static void EnableSVKIfPending(); // forward
static void HandleHotkeys();      // forward

static HRESULT WINAPI hkEndScene(IDirect3DDevice9* dev)
{
    FrameFence_Tick();    // <-- one tick per rendered frame
    EnableSVKIfPending(); // flip content hooks after first real frame
    HandleHotkeys();      // F7 to cycle active candidate
    RunScheduled(FrameFence_Id()); // your per-frame jobs if any
    return oEndScene(dev);
}
void InstallEndSceneHook(IDirect3DDevice9* dev)
{
    if (!dev || oEndScene) return;
    void** vtbl = *reinterpret_cast<void***>(dev);
    void* target = vtbl[42]; // IDirect3DDevice9::EndScene
    if (MH_CreateHook(target, hkEndScene, reinterpret_cast<void**>(&oEndScene)) == MH_OK &&
        MH_EnableHook(target) == MH_OK)
        dbgln("[ClientFix] EndScene hook enabled");
    else
        dbgln("[ClientFix] EndScene hook FAILED");
}

// --------------- SVK starter hooks (multi-candidate; only 1 enabled) ---------------
struct SVKCand {
    uint8_t* start;   // hooked function start (callee)
    SVKStarter_t orig;   // trampoline
    bool        created;
    bool        enabled;
};
static std::vector<SVKCand> gCands;
static int   gActiveIdx = -1;   // currently enabled candidate
static LONG  gHitCt = 0;

extern "C" void* _ReturnAddress(void);

// Shared detour for whichever candidate is currently enabled
static void __fastcall hkSVK_Any(void* self, void* /*edx*/, int a1, int a2)
{
    uint8_t* textBase = nullptr; size_t textSize = 0;
    GetSectionRange(GetModuleHandleA(nullptr), ".text", textBase, textSize);
    uint8_t* ret = (uint8_t*)_ReturnAddress();   // return to the CALLER
    uint8_t* callerStart = FindFuncStart(ret, textBase);
    uint8_t* handlerStart = HitGate_Get14AStart();
    bool callerIn14A = handlerStart && ret >= handlerStart && ret < handlerStart + 0x1000;

    SVKStarter_t callOrig = nullptr;
    int active = gActiveIdx;
    if (active >= 0 && active < (int)gCands.size() && gCands[active].enabled)
        callOrig = gCands[active].orig;

    LONG n = InterlockedIncrement(&gHitCt);
    if (n <= 20) {
        char line[256];
        std::snprintf(line, sizeof(line),
            "[ClientFix] SVK HIT[cand %d]: self=%p a1=%d a2=%d caller=%p",
            active, self, a1, a2, callerStart);
        dbgln(line);
    }

    if (callOrig && !callerIn14A && HitGate_TryDeferSVK(self, a1, a2, callOrig)) {
        return;
    }

    if (callOrig) {
        if (callerIn14A) {
            dbgln("[ClientFix][HitGate] SVK immediate (caller inside 0x14A)");
        }
        __try { callOrig(self, a1, a2); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            dbgln("[ClientFix] SVK detour exception — disabling active hook");
            if (active >= 0) { MH_DisableHook(gCands[active].start); gCands[active].enabled = false; }
        }
    }
}

// Helper: add candidate + create hook (do not enable yet)
static void AddCand(uint8_t* start)
{
    for (auto& c : gCands) if (c.start == start) return; // de-dupe
    SVKCand c{}; c.start = start; c.created = false; c.enabled = false; c.orig = nullptr;

    if (MH_CreateHook((LPVOID)c.start, (LPVOID)hkSVK_Any, (LPVOID*)&c.orig) == MH_OK) {
        c.created = true;
        dbgprintf("[ClientFix] SVK CAND add: start=0x%p bytes=%s", start, hex24(start));
    }
    else {
        dbgprintf("[ClientFix] SVK CAND add FAILED: start=0x%p", start);
    }
    gCands.push_back(c);
}

static void EnableOnly(int idx)
{
    // disable all
    for (int i = 0; i < (int)gCands.size(); ++i) {
        if (gCands[i].enabled) { MH_DisableHook(gCands[i].start); gCands[i].enabled = false; }
    }
    gActiveIdx = -1;
    // enable requested
    if (idx >= 0 && idx < (int)gCands.size() && gCands[idx].created) {
        if (MH_EnableHook(gCands[idx].start) == MH_OK) {
            gCands[idx].enabled = true;
            gActiveIdx = idx;
            dbgprintf("[ClientFix] SVK cand ENABLED (active=%d) @ 0x%p", idx, gCands[idx].start);
        }
        else {
            dbgln("[ClientFix]  -> enable failed");
        }
    }
}

static void HandleHotkeys()
{
    // F7 = cycle active candidate (only after first frame; harmless if none)
    if ((GetAsyncKeyState(VK_F7) & 1) && !gCands.empty()) {
        int next = (gActiveIdx + 1) % (int)gCands.size();
        EnableOnly(next);
    }
}

static void DiscoverSVKCallers()
{
    HMODULE mod = GetModuleHandleA(nullptr);
    uint8_t* rbase = nullptr; size_t rsz = 0;
    uint8_t* tbase = nullptr; size_t tsz = 0;
    if (!GetSectionRange(mod, ".rdata", rbase, rsz) || !GetSectionRange(mod, ".text", tbase, tsz)) {
        dbgln("[ClientFix] .rdata/.text not found"); return;
    }

    // Fast-path: add explicit prolog patterns we’ve already seen in your logs
    {
        static const uint8_t PAT0[] = {
            0x55,0x8B,0xEC,0x8B,0x45,0x10,0x53,0x56,0x57,0x6A,0x00,0x8B,
            0xF1,0x8B,0x4D,0x0C,0x8B,0x56,0x08,0x50,0x51,0xC1,0xE2,0x05
        };
        for (size_t i = 0; i + sizeof(PAT0) <= tsz; ++i)
            if (memcmp(tbase + i, PAT0, sizeof(PAT0)) == 0) { AddCand(tbase + i); break; }
    }
    {
        static const uint8_t PAT1[] = {
            0x55,0x8B,0xEC,0x8B,0x45,0x10,0x53,0x56,0x57,0x6A,0x00,0x8B,
            0xF1,0x8B,0x4D,0x0C,0x50,0x8B,0x46,0x08,0x8D,0x14,0xC5,0x00
        };
        // simple masked compare for final 4 bytes
        const char* MSK1 = "xxxxxxxxxxxxxxx" "xxxxx" "????";
        auto matchMask = [](const uint8_t* p, const uint8_t* pat, const char* m) {
            for (; *m; ++m, ++p, ++pat) if (*m == 'x' && *p != *pat) return false; return true;
        };
        for (size_t i = 0; i + 24 <= tsz; ++i)
            if (matchMask(tbase + i, PAT1, MSK1)) { AddCand(tbase + i); break; }
    }
    // You also saw a third prolog (0x00405860) — add a masked finder for it:
    {
        static const uint8_t PAT2[] = {
            0x55,0x8B,0xEC,0x8B,0x45,0x10,0x53,0x56,0x57,0x6A,0x00,0x8B,
            0xF1,0x8B,0x4D,0x0C,0x50,0x8B,0x46,0x08,0x8D,0x14,0x40,0x03
        };
        const char* MSK2 = "xxxxxxxxxxxxxxxxxxxxxxxx"; // exact 24
        for (size_t i = 0; i + 24 <= tsz; ++i)
            if (memcmp(tbase + i, PAT2, 24) == 0) { AddCand(tbase + i); break; }
    }

    // Generic discovery: locate loader via DBC string and add all direct callers
    const char* NEEDLE = "DBFilesClient\\SpellVisualKit.dbc";
    uint8_t* s = FindAscii(rbase, rsz, NEEDLE);
    if (s) {
        dbgprintf("[ClientFix] SVK string @ 0x%p", s);
        uint8_t* loader = nullptr;
        for (size_t i = 0; i + 4 <= tsz; ++i) {
            uint8_t* at = tbase + i;
            if (*(uint32_t*)at == (uint32_t)(uintptr_t)s) {
                uint8_t* f = FindFuncStart(at, tbase);
                if (f) { loader = f; break; }
            }
        }
        if (loader) {
            dbgprintf("[ClientFix] SVK loader func start=0x%p bytes=%s", loader, hex24(loader));
            // direct CALL rel32 → loader
            for (size_t i = 0; i + 5 <= tsz; ++i) {
                uint8_t* at = tbase + i;
                if (at[0] != 0xE8) continue;
                int32_t rel = *(int32_t*)(at + 1);
                uint8_t* tgt = at + 5 + rel;
                if (tgt == loader) {
                    uint8_t* f = FindFuncStart(at, tbase);
                    if (f) AddCand(f);
                }
            }
        }
    }

    dbgprintf("[ClientFix] SVK candidates prepared: %d", (int)gCands.size());
}

static void EnableSVKIfPending()
{
    static bool once = false;
    if (once) return;
    once = true;

    // Choose index 0 by default (if any), disable all others
    if (gActiveIdx < 0 && !gCands.empty()) EnableOnly(0);
}

// ------------------------- Install all (called once) ------------------
static bool gCombatHooksInstalled = false;

void InstallCombatHooks()
{
    if (gCombatHooksInstalled) return;
    gCombatHooksInstalled = true;

    DiscoverSVKCallers(); // find & create hooks (deferred)
    if (gActiveIdx < 0 && !gCands.empty()) {
        dbgln("[ClientFix] SVK forcing enable candidate 0");
        EnableOnly(0);
    }
    HitGate_Init();
}
