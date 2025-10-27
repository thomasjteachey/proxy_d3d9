// svk_scan.cpp  —  SpellVisualKit loader probe + caller histogram (32-bit)
// Build: MSVC /MT or /MD, Win32. Requires MinHook in your project.

#include <windows.h>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <vector>
#include <algorithm>

#include "MinHook.h"

// -------------------------------------------------------------
// Tiny logging helpers (OutputDebugStringA)
// -------------------------------------------------------------
static void dbgputs(const char* s) { OutputDebugStringA(s); }
static void dbgv(const char* fmt, ...)
{
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);
}

// Prefix everything consistently in the viewer
#define LOGP(tag, fmt, ...) dbgv("[ClientFix][" tag "] " fmt, __VA_ARGS__)
#define LOGS(tag, s)        dbgv("[ClientFix][" tag "] %s", s)

// -------------------------------------------------------------
// PE section helpers (for scanning .rdata / .text)
// -------------------------------------------------------------
struct Sect { uint8_t* base; uint32_t size; };

static bool getSect(HMODULE mod, const char* name, Sect& out)
{
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(mod) + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        char nm[9] = { 0 };
        memcpy(nm, sec->Name, 8);
        if (strcmp(nm, name) == 0)
        {
            out.base = reinterpret_cast<uint8_t*>(mod) + sec->VirtualAddress;
            out.size = sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static uint8_t* find_string_in_rdata(HMODULE mod, const char* needle)
{
    Sect r{}; if (!getSect(mod, ".rdata", r)) return nullptr;
    const size_t nlen = strlen(needle);
    for (size_t i = 0; i + nlen <= r.size; ++i)
    {
        if (memcmp(r.base + i, needle, nlen) == 0)
            return r.base + i;
    }
    return nullptr;
}

// raw scan .text for little-endian 32-bit immediate equal to ptr
static void find_imm_refs_in_text(HMODULE mod, const void* imm, std::vector<uint8_t*>& outHits)
{
    Sect t{}; if (!getSect(mod, ".text", t)) return;
    const uint32_t val = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(imm));
    for (size_t i = 0; i + 4 <= t.size; ++i)
    {
        if (*reinterpret_cast<uint32_t*>(t.base + i) == val)
            outHits.push_back(t.base + i);
    }
}

// heuristically walk backward to the probable start of the function
static uint8_t* find_func_start(uint8_t* p, size_t back = 0x300)
{
    Sect t{}; if (!getSect(GetModuleHandle(nullptr), ".text", t)) return p;

    uintptr_t tb = reinterpret_cast<uintptr_t>(t.base);
    uintptr_t te = tb + t.size;
    uintptr_t cur = reinterpret_cast<uintptr_t>(p);

    if (cur < tb || cur >= te) return p;

    uintptr_t lo = (cur > tb + back) ? (cur - back) : tb;

    for (uintptr_t q = cur; q-- > lo; )
    {
        // classic prolog: push ebp; mov ebp, esp
        if (*(uint16_t*)q == 0x8B55 && *(uint8_t*)(q + 2) == 0xEC)
            return reinterpret_cast<uint8_t*>(q);

        // alternative: push <reg>; push <reg>; sub esp, imm8/imm32
        if (*(uint8_t*)q == 0x55 || *(uint8_t*)q == 0x56 || *(uint8_t*)q == 0x57)
        {
            // Accept a boundary after lots of 0xCC or a RET
            if (*(uint8_t*)(q - 1) == 0xCC || *(uint8_t*)(q - 1) == 0xC3 || *(uint8_t*)(q - 1) == 0xC2)
                return reinterpret_cast<uint8_t*>(q);
        }
    }
    return p; // fallback
}

// -------------------------------------------------------------
// Caller histogram (who calls the loader)
// -------------------------------------------------------------
struct CallerRec
{
    uint8_t* funcStart;
    volatile long hits;
};

static CRITICAL_SECTION g_cs;
static bool g_csInit = false;
static std::vector<CallerRec> g_callers;

static CallerRec* find_or_add(uint8_t* funcStart)
{
    if (!g_csInit) { InitializeCriticalSection(&g_cs); g_csInit = true; }
    EnterCriticalSection(&g_cs);
    for (auto& c : g_callers)
        if (c.funcStart == funcStart) { LeaveCriticalSection(&g_cs); return &c; }
    CallerRec rec{ funcStart, 0 };
    g_callers.push_back(rec);
    LeaveCriticalSection(&g_cs);
    return &g_callers.back();
}

extern "C" void DumpSVKCallers()
{
    if (!g_csInit) { OutputDebugStringA("[ClientFix][SVK] no callers yet\n"); return; }

    EnterCriticalSection(&g_cs);
    std::vector<CallerRec> copy = g_callers;
    LeaveCriticalSection(&g_cs);

    std::sort(copy.begin(), copy.end(),
        [](const CallerRec& a, const CallerRec& b) { return a.hits > b.hits; });

    OutputDebugStringA("[ClientFix][SVK] ---- TOP CALLERS ----\n");
    const size_t N = std::min<size_t>(copy.size(), 16);
    for (size_t i = 0; i < N; ++i)
        dbgv("[ClientFix][SVK] caller=%p hits=%ld\n", copy[i].funcStart, copy[i].hits);
}

// -------------------------------------------------------------
// SVK loader hook (naked stub avoids calling-convention guesses)
// -------------------------------------------------------------
static void* g_OriLoader = nullptr; // MinHook trampoline

static void __cdecl OnLoaderHit(void* retAddr)
{
    uint8_t* start = find_func_start(reinterpret_cast<uint8_t*>(retAddr));
    auto* rec = find_or_add(start);
    InterlockedIncrement(&rec->hits);
}

extern "C" void __declspec(naked) hkLoader()
{
    __asm {
        // on entry: [esp] = return address into CALLER of loader
        pushfd
        pushad

        mov  eax, [esp + 36]      // ret address saved above pushfd+pushad
        push eax
        call OnLoaderHit
        add  esp, 4

        popad
        popfd
        jmp dword ptr[g_OriLoader]  // tail-jump into MinHook trampoline
    }
}

// -------------------------------------------------------------
// Public entrypoints used by the rest of your project
// -------------------------------------------------------------
static HMODULE gExe = nullptr;
static uint8_t* gLoaderStart = nullptr;
static bool gHookArmed = false;

static void install_loader_probe()
{
    if (gHookArmed || !gLoaderStart) return;

    if (MH_CreateHook((LPVOID)gLoaderStart, (LPVOID)hkLoader, &g_OriLoader) == MH_OK &&
        MH_EnableHook((LPVOID)gLoaderStart) == MH_OK)
    {
        OutputDebugStringA("[ClientFix][SVK] loader probe installed\n");
        gHookArmed = true;
    }
    else
    {
        OutputDebugStringA("[ClientFix][SVK] loader probe FAILED\n");
    }
}

extern "C" void SVK_Init()
{
    gExe = GetModuleHandle(nullptr);

    // 1) locate literal "DBFilesClient\\SpellVisualKit.dbc"
    const char* kNeedle = "DBFilesClient\\SpellVisualKit.dbc";
    uint8_t* str = find_string_in_rdata(gExe, kNeedle);
    if (!str) { OutputDebugStringA("[ClientFix][SVK] string not found\n"); return; }

    dbgv("[ClientFix][SVK] string @ %p\n\n", str);

    // 2) find who references the string
    std::vector<uint8_t*> refs;
    find_imm_refs_in_text(gExe, str, refs);
    if (refs.empty()) { OutputDebugStringA("[ClientFix][SVK] no code refs\n"); return; }

    // consider the first ref as being inside the "loader" function
    gLoaderStart = find_func_start(refs[0]);

    dbgv("[ClientFix][SVK] loader func start=%p bytes=%02X %02X %02X %02X %02X %02X \n\n",
        gLoaderStart, gLoaderStart[0], gLoaderStart[1], gLoaderStart[2],
        gLoaderStart[3], gLoaderStart[4], gLoaderStart[5]);

    // pre-seed a few unique caller functions (nice to print)
    std::vector<uint8_t*> uniqFuncs;
    for (auto r : refs)
    {
        uint8_t* f = find_func_start(r);
        if (std::find(uniqFuncs.begin(), uniqFuncs.end(), f) == uniqFuncs.end())
        {
            uniqFuncs.push_back(f);
            dbgv("[ClientFix][SVK] CAND add: start=%p bytes=%02X %02X %02X %02X %02X %02X \n\n",
                f, f[0], f[1], f[2], f[3], f[4], f[5]);
        }
    }
}

extern "C" void SVK_EnableOnEndScene()
{
    if (!gHookArmed)
    {
        install_loader_probe();
        OutputDebugStringA("[ClientFix][SVK] SVK hook enabled (first EndScene)\n");
    }
}
