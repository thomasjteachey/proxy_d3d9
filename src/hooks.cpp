// hooks.cpp — EndScene + SVK loader hook

#include "hooks.h"
#include "MinHook.h"

#include <windows.h>
#include <d3d9.h>
#include <cstdint>
#include <cstdio>
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

static HRESULT WINAPI hkEndScene(IDirect3DDevice9* dev)
{
    HitGate_SetRenderThreadId(static_cast<uint32_t>(GetCurrentThreadId()));
    FrameFence_SetRenderThreadId(static_cast<uint32_t>(GetCurrentThreadId()));
    FrameFence_Tick();    // <-- one tick per rendered frame
    RunScheduled(FrameFence_Id()); // your per-frame jobs if any
    static DWORD s_last = 0;
    DWORD now = GetTickCount();
    if (now - s_last > 1000) {
        s_last = now;
        dbgprintf("[ClientFix][HitGate] dispatchHits=%u saw14A=%u lastOpcode=0x%X dispatchTid=%u renderTid=%u frame=%u",
            HitGate_GetDispatchHits(), HitGate_GetSaw14A(), HitGate_GetLastOpcode(),
            HitGate_GetLastDispatchTid(), FrameFence_RenderThreadId(), FrameFence_Id());
    }
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

// -------------------------- SVK loader hook --------------------------
static uint8_t* gSVKLoaderStart = nullptr;
static void* gSVKLoaderTrampoline = nullptr;
static bool gSVKHookArmed = false;
static LONG gSVKHitCt = 0;

static void __cdecl OnSVKLoaderHit(void* retAddr)
{
    uint8_t* textBase = nullptr; size_t textSize = 0;
    uint8_t* callerStart = nullptr;
    if (GetSectionRange(GetModuleHandleA(nullptr), ".text", textBase, textSize)) {
        callerStart = FindFuncStart(reinterpret_cast<uint8_t*>(retAddr), textBase);
    }

    LONG n = InterlockedIncrement(&gSVKHitCt);
    if (n <= 20) {
        char line[256];
        std::snprintf(line, sizeof(line),
            "[ClientFix] SVK loader HIT: ret=%p caller=%p",
            retAddr, callerStart);
        dbgln(line);
    }
}

extern "C" void __declspec(naked) hkSVKLoader()
{
    __asm {
        pushfd
        pushad

        mov  eax, [esp + 36]
        push eax
        call OnSVKLoaderHit
        add  esp, 4

        popad
        popfd
        jmp dword ptr [gSVKLoaderTrampoline]
    }
}

static void DiscoverSVKLoader()
{
    HMODULE mod = GetModuleHandleA(nullptr);
    uint8_t* rbase = nullptr; size_t rsz = 0;
    uint8_t* tbase = nullptr; size_t tsz = 0;
    if (!GetSectionRange(mod, ".rdata", rbase, rsz) || !GetSectionRange(mod, ".text", tbase, tsz)) {
        dbgln("[ClientFix] .rdata/.text not found"); return;
    }

    const char* NEEDLE = "DBFilesClient\\SpellVisualKit.dbc";
    uint8_t* s = FindAscii(rbase, rsz, NEEDLE);
    if (!s) {
        dbgln("[ClientFix] SVK string not found");
        return;
    }

    dbgprintf("[ClientFix] SVK string @ 0x%p", s);
    for (size_t i = 0; i + 4 <= tsz; ++i) {
        uint8_t* at = tbase + i;
        if (*(uint32_t*)at == (uint32_t)(uintptr_t)s) {
            uint8_t* f = FindFuncStart(at, tbase);
            if (f) { gSVKLoaderStart = f; break; }
        }
    }

    if (gSVKLoaderStart) {
        dbgprintf("[ClientFix] SVK loader func start=0x%p bytes=%s", gSVKLoaderStart, hex24(gSVKLoaderStart));
    } else {
        dbgln("[ClientFix] SVK loader func not found");
    }
}

// ------------------------- Install all (called once) ------------------
static bool gCombatHooksInstalled = false;

static bool IsWowProcess()
{
    char path[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(nullptr, path, static_cast<DWORD>(sizeof(path)));
    const char* exe = path;
    if (len == 0) {
        exe = "";
    } else {
        const char* lastSlash = strrchr(path, '\\');
        const char* lastFwd = strrchr(path, '/');
        const char* last = lastSlash ? lastSlash : lastFwd;
        if (lastFwd && lastSlash) {
            last = (lastFwd > lastSlash) ? lastFwd : lastSlash;
        } else if (lastFwd) {
            last = lastFwd;
        }
        if (last && *(last + 1) != '\0') {
            exe = last + 1;
        }
    }

    char line[512];
    std::snprintf(line, sizeof(line),
        "[ClientFix][HitGate] PID=%lu EXE=%s",
        static_cast<unsigned long>(GetCurrentProcessId()),
        path[0] ? path : "(unknown)");
    dbgln(line);

    if (_stricmp(exe, "Wow.exe") != 0) {
        std::snprintf(line, sizeof(line),
            "[ClientFix][HitGate] Not Wow.exe (%s), skipping combat hooks",
            exe[0] ? exe : "(unknown)");
        dbgln(line);
        return false;
    }
    return true;
}

void InstallCombatHooks()
{
    if (gCombatHooksInstalled) return;
    gCombatHooksInstalled = true;

    if (!IsWowProcess()) return;

    DiscoverSVKLoader();
    if (gSVKLoaderStart && !gSVKHookArmed) {
        if (MH_CreateHook((LPVOID)gSVKLoaderStart, (LPVOID)hkSVKLoader, &gSVKLoaderTrampoline) == MH_OK &&
            MH_EnableHook((LPVOID)gSVKLoaderStart) == MH_OK) {
            dbgln("[ClientFix] SVK loader hook installed");
            gSVKHookArmed = true;
        }
        else {
            dbgln("[ClientFix] SVK loader hook FAILED");
        }
    }

    HitGate_Init();   // <-- ADD (installs dispatch callsite hook)
}
