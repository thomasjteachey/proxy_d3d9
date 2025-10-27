// call_split.cpp — generalized call-splitter with frame-fence + per-actor gating.
// - Auto-scans .text for every CALL E8 that targets the same handler(s) as your seeds.
// - If two calls for the same actor occur in the same frame, the 2nd waits for next frame.
// - No inline asm; x86 only.

#if !defined(_M_IX86)
#error Build this file for Win32 (x86)
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <vector>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <algorithm>

#include "frame_fence.h"

// -------- knobs --------
static volatile LONG g_enabled = 1;    // F10 toggles ON/OFF. Starts ON.
static const size_t  kMaxSites = 256; // max callsites to patch
// -----------------------

static void dlog(const char* s) { OutputDebugStringA(s); }
static void dprintfA(const char* fmt, ...) {
    char b[512]; va_list ap; va_start(ap, fmt);
#if _MSC_VER >= 1400
    _vsnprintf_s(b, _TRUNCATE, fmt, ap);
#else
    _vsnprintf(b, sizeof(b) - 1, fmt, ap); b[sizeof(b) - 1] = 0;
#endif
    va_end(ap); OutputDebugStringA(b);
}

// Your seed RETURN addresses (from your TOP CALLERS logs)
static const uintptr_t kSeedRetAddrs[] = {
    0x00467E64,   // dominant
    0x00466F38    // rarer
};

struct Site {
    uintptr_t ret;        // EIP after CALL
    BYTE* call;       // address of CALL E8 .. (ret-5)
    BYTE      orig[5];    // saved bytes
    void* stub;       // our stub (executable)
    uintptr_t target;     // resolved callee
    bool      armed;
};

static std::vector<Site>       g_sites;
static std::vector<uintptr_t>  g_targets; // unique handler targets

// --- PE helpers to find .text ---
static bool GetTextRange(BYTE*& base, BYTE*& text, DWORD& textSize)
{
    base = (BYTE*)GetModuleHandleA(nullptr);
    if (!base) return false;
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD ch = sec->Characteristics;
        if ((ch & IMAGE_SCN_CNT_CODE) && (ch & IMAGE_SCN_MEM_EXECUTE)) {
            text = base + sec->VirtualAddress;
            textSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            return true;
        }
    }
    return false;
}

static inline bool IsCallE8At(BYTE* p) { return p && p[0] == 0xE8; }

static bool ResolveCallFromRet(uintptr_t ret, BYTE*& callOut, uintptr_t& tgtOut)
{
    if (ret < 5) return false;
    BYTE* call = (BYTE*)(ret - 5);
    if (!IsCallE8At(call)) return false;
    int32_t rel = *reinterpret_cast<int32_t*>(call + 1);
    uintptr_t target = (uintptr_t)(call + 5) + rel;
    callOut = call;
    tgtOut = target;
    return true;
}

static bool ProtWrite(void* p, const void* src, SIZE_T n) {
    DWORD old; if (!VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(p, src, n); FlushInstructionCache(GetCurrentProcess(), p, n);
    VirtualProtect(p, n, old, &old);
    return true;
}

// ---- per-actor last-frame (ECX == this) ----
struct ActorFrame {
    void* key;
    unsigned lastFrame;
};
static ActorFrame g_actorFrames[256] = {};

static unsigned* TouchActor(void* key)
{
    if (!key) return nullptr;
    size_t idx = (reinterpret_cast<uintptr_t>(key) >> 4) & (256 - 1);
    for (size_t i = 0; i < 256; ++i) {
        size_t p = (idx + i) & (256 - 1);
        if (g_actorFrames[p].key == key || g_actorFrames[p].key == nullptr) {
            g_actorFrames[p].key = key;
            return &g_actorFrames[p].lastFrame;
        }
    }
    g_actorFrames[0].key = key;
    return &g_actorFrames[0].lastFrame;
}

// ----- decision function called from stubs -----
extern "C" __declspec(noinline) void __cdecl CallSplit_OnEnter(void* ecxThis, uintptr_t callsite)
{
    (void)callsite;
    if (InterlockedCompareExchange(&g_enabled, 0, 0) == 0) return;

    const unsigned curFrame = FrameFence_Id();
    unsigned* lastPtr = TouchActor(ecxThis);

    unsigned last = lastPtr ? *lastPtr : 0;
    if (last == curFrame) {
        // same frame for this actor — wait for next rendered frame
        FrameFence_WaitNext(12); // safety timeout in case of pause/loading
    }

    const unsigned after = FrameFence_Id();
    if (lastPtr) *lastPtr = after;
}

// Build stub:
// pushfd; pushad; push ecx; push imm32(callsite); mov eax,&OnEnter; call eax; add esp,8; popad; popfd; mov eax,target; jmp eax;
static void* BuildStub(uintptr_t target, uintptr_t callsite)
{
    BYTE code[] = {
        0x9C,                         // pushfd
        0x60,                         // pushad
        0x51,                         // push ecx
        0x68, 0,0,0,0,                // push imm32 (callsite)
        0xB8, 0,0,0,0,                // mov eax, &CallSplit_OnEnter
        0xFF, 0xD0,                   // call eax
        0x83, 0xC4, 0x08,             // add esp, 8
        0x61,                         // popad
        0x9D,                         // popfd
        0xB8, 0,0,0,0,                // mov eax, target
        0xFF, 0xE0                    // jmp eax
    };

    BYTE* mem = (BYTE*)VirtualAlloc(nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return nullptr;

    *reinterpret_cast<uintptr_t*>(code + 4) = callsite;
    *reinterpret_cast<void**>(code + 9) = (void*)&CallSplit_OnEnter;
    *reinterpret_cast<uintptr_t*>(code + 22) = target;

    memcpy(mem, code, sizeof(code));
    FlushInstructionCache(GetCurrentProcess(), mem, sizeof(code));
    return mem;
}

static bool ArmSite(Site& s)
{
    if (!s.stub) s.stub = BuildStub(s.target, (uintptr_t)s.call);
    if (!s.stub) return false;

    BYTE patched[5] = { 0xE8, 0,0,0,0 };
    intptr_t rel = (intptr_t)s.stub - (intptr_t)(s.call + 5);
    *reinterpret_cast<int32_t*>(patched + 1) = (int32_t)rel;

    if (!ProtWrite(s.call, patched, 5)) return false;
    s.armed = true;
    dprintfA("[CALLSPLIT] armed call=0x%08X -> stub=0x%p (target=0x%08X)\n",
        (unsigned)(uintptr_t)s.call, s.stub, (unsigned)s.target);
    return true;
}
static void DisarmSite(Site& s)
{
    if (!s.armed) return;
    ProtWrite(s.call, s.orig, 5);
    s.armed = false;
    dprintfA("[CALLSPLIT] restored call=0x%08X\n", (unsigned)(uintptr_t)s.call);
}

// ---- scan .text for all E8 -> any target in g_targets ----
static void ScanAndPatchAll()
{
    BYTE* base = nullptr; BYTE* text = nullptr; DWORD textSize = 0;
    if (!GetTextRange(base, text, textSize)) { dlog("[CALLSPLIT] GetTextRange failed\n"); return; }

    size_t added = 0;
    for (DWORD i = 0; i + 5 <= textSize && g_sites.size() < kMaxSites; ++i) {
        BYTE* p = text + i;
        if (!IsCallE8At(p)) continue;

        int32_t rel = *reinterpret_cast<int32_t*>(p + 1);
        uintptr_t tgt = (uintptr_t)(p + 5) + rel;

        if (std::find(g_targets.begin(), g_targets.end(), tgt) == g_targets.end())
            continue;

        if (std::any_of(g_sites.begin(), g_sites.end(),
            [p](const Site& s) { return s.call == p; }))
            continue;

        Site s{};
        s.ret = (uintptr_t)(p + 5);
        s.call = p;
        s.target = tgt;
        s.stub = nullptr;
        s.armed = false;
        memcpy(s.orig, p, 5);
        g_sites.push_back(s);
        ++added;
    }

    dprintfA("[CALLSPLIT] scan added=%u (total=%u)\n", (unsigned)added, (unsigned)g_sites.size());
    for (auto& s : g_sites) ArmSite(s);
}

// ---- hotkey thread: F10 toggles ----
static DWORD WINAPI KeyThread(LPVOID)
{
    dlog("[CALLSPLIT] F10 toggles ON/OFF\n");
    for (;;) {
        if (GetAsyncKeyState(VK_F10) & 1) {
            bool turnOn = InterlockedCompareExchange(&g_enabled, 0, 0) == 0;
            InterlockedExchange(&g_enabled, turnOn ? 1 : 0);
            for (auto& s : g_sites) { if (turnOn) ArmSite(s); else DisarmSite(s); }
            dlog(turnOn ? "[CALLSPLIT] ON\n" : "[CALLSPLIT] OFF\n");
        }
        Sleep(30);
    }
}

void CallSplit_Init()
{
    static bool once = false; if (once) return; once = true;

    FrameFence_Init();   // make sure timer granularity is good

    // 1) resolve seed targets from your two ret-addrs
    for (uintptr_t ret : kSeedRetAddrs) {
        BYTE* call = nullptr; uintptr_t tgt = 0;
        if (ResolveCallFromRet(ret, call, tgt)) {
            if (std::find(g_targets.begin(), g_targets.end(), tgt) == g_targets.end()) {
                g_targets.push_back(tgt);
                dprintfA("[CALLSPLIT] seed ret=0x%08X call=0x%08X target=0x%08X\n",
                    (unsigned)ret, (unsigned)(uintptr_t)call, (unsigned)tgt);
            }
        }
        else {
            dprintfA("[CALLSPLIT] seed ret=0x%08X not CALL — skipped\n", (unsigned)ret);
        }
    }

    // 2) patch all callsites to those targets
    ScanAndPatchAll();

    // 3) hotkey
    HANDLE th = CreateThread(nullptr, 0, KeyThread, nullptr, 0, nullptr);
    if (th) CloseHandle(th);

    dprintfA("[CALLSPLIT] ready (targets=%u, sites=%u)\n",
        (unsigned)g_targets.size(), (unsigned)g_sites.size());
}
