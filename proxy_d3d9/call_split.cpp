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
#include <cstring>
#include <algorithm>

#include "call_split.h"

// --------------------------------------------------------------------------------------
//  Call-site leading-edge throttle + signature de-dupe.
//  - First call executes immediately.
//  - Any duplicate signature within the active window is dropped (no delayed flush).
//  - Signature = { target, callsite, this/ecx, up to first 4 stack args }.
//  - Fixed window: duplicates within ~120 ms are suppressed automatically.
// --------------------------------------------------------------------------------------

static void dlog(const char* s) { OutputDebugStringA(s); }
static void dprintfA(const char* fmt, ...)
{
    char buf[512];
    va_list ap; va_start(ap, fmt);
#if _MSC_VER >= 1400
    _vsnprintf_s(buf, _TRUNCATE, fmt, ap);
#else
    _vsnprintf(buf, sizeof(buf) - 1, fmt, ap); buf[sizeof(buf) - 1] = '\0';
#endif
    va_end(ap);
    OutputDebugStringA(buf);
}

namespace
{
    static constexpr DWORD  kWindowMs       = 120;  // drop duplicates seen within this window
    static constexpr DWORD  kGateExpiryMs   = 600;  // stale signature eviction horizon

    static constexpr size_t kMaxSites       = 256;  // maximum patched callsites
    static constexpr size_t kMaxArgs        = 4;    // signature depth (extendable)
    static constexpr size_t kGateTableSize  = 512;  // must be power of two

    static const uintptr_t kSeedRetAddrs[] = {
        0x00467E64,   // dominant
        0x00466F38    // rarer
    };

    struct Site
    {
        uintptr_t ret;      // address immediately after CALL
        BYTE*     call;     // CALL opcode location
        BYTE      orig[5];
        void*     stub;
        uintptr_t target;
        uint8_t   argc;     // inferred explicit stack args (<= kMaxArgs)
        bool      armed;
    };

    struct TargetMeta
    {
        uintptr_t target;
        uint8_t   argc;
    };

    struct CallKey
    {
        uintptr_t target;
        uintptr_t callsite;
        void*     thisPtr;
        uint8_t   argc;
        uintptr_t args[kMaxArgs];
    };

    struct GateEntry
    {
        DWORD    stamp;      // last accepted tick (GetTickCount)
        bool     valid;
        CallKey  key;
    };

    static std::vector<Site>       g_sites;
    static std::vector<uintptr_t>  g_targets;
    static std::vector<TargetMeta> g_targetMeta;

    static GateEntry g_gate[kGateTableSize] = {};
    static size_t    g_gateSweep = 0;

    static DWORD NowMs()
    {
        return GetTickCount();
    }

    static bool GetTextRange(BYTE*& base, BYTE*& text, DWORD& textSize)
    {
        base = (BYTE*)GetModuleHandleA(nullptr);
        if (!base) return false;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
        {
            DWORD ch = sec->Characteristics;
            if ((ch & IMAGE_SCN_CNT_CODE) && (ch & IMAGE_SCN_MEM_EXECUTE))
            {
                text = base + sec->VirtualAddress;
                textSize = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
                return true;
            }
        }
        return false;
    }

    static inline bool IsCallE8At(BYTE* p)
    {
        return p && p[0] == 0xE8;
    }

    static bool ResolveCallFromRet(uintptr_t ret, BYTE*& callOut, uintptr_t& tgtOut)
    {
        if (ret < 5) return false;
        BYTE* call = reinterpret_cast<BYTE*>(ret - 5);
        if (!IsCallE8At(call)) return false;
        int32_t rel = *reinterpret_cast<int32_t*>(call + 1);
        uintptr_t target = (uintptr_t)(call + 5) + rel;
        callOut = call;
        tgtOut = target;
        return true;
    }

    static bool ProtWrite(void* p, const void* src, SIZE_T n)
    {
        DWORD old{};
        if (!VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, &old)) return false;
        memcpy(p, src, n);
        FlushInstructionCache(GetCurrentProcess(), p, n);
        VirtualProtect(p, n, old, &old);
        return true;
    }

    static TargetMeta* FindMeta(uintptr_t target)
    {
        for (auto& m : g_targetMeta) if (m.target == target) return &m;
        return nullptr;
    }

    static uint8_t InferArgCount(uintptr_t target)
    {
        // Scan forward for the first RET instruction. If RET imm16 encountered, derive arg bytes.
        // Bound the scan to avoid walking forever if the target is non-standard.
        constexpr size_t kMaxScan = 0x400; // 1 KB of code is plenty for prolog/epilog.
        BYTE* p = reinterpret_cast<BYTE*>(target);
        for (size_t i = 0; i < kMaxScan; ++i)
        {
            BYTE op = p[i];
            if (op == 0xC2 && i + 2 < kMaxScan) // RET imm16
            {
                uint16_t imm = *reinterpret_cast<uint16_t*>(p + i + 1);
                return static_cast<uint8_t>(std::min<size_t>(imm / 4u, kMaxArgs));
            }
            if (op == 0xC3) // plain RET (no stack args)
            {
                return 0;
            }
        }
        // Fallback if we fail to find a RET — assume four stack args (matches historic behavior).
        return static_cast<uint8_t>(kMaxArgs);
    }

    static TargetMeta* EnsureMeta(uintptr_t target)
    {
        if (auto* m = FindMeta(target)) return m;
        TargetMeta meta{};
        meta.target = target;
        meta.argc = InferArgCount(target);
        g_targetMeta.push_back(meta);
        dprintfA("[CALLGATE] target=0x%08X argc=%u\n", (unsigned)target, (unsigned)meta.argc);
        return &g_targetMeta.back();
    }

    static uint32_t HashKey(const CallKey& key)
    {
        uint32_t h = 0x811C9DC5u; // FNV-1a 32-bit
        auto mix = [&h](uintptr_t v)
        {
            for (int i = 0; i < (int)sizeof(uintptr_t); ++i)
            {
                BYTE b = static_cast<BYTE>((v >> (i * 8)) & 0xFF);
                h ^= b;
                h *= 0x01000193u;
            }
        };
        mix(key.target);
        mix(key.callsite);
        mix(reinterpret_cast<uintptr_t>(key.thisPtr));
        mix(key.argc);
        for (uint8_t i = 0; i < key.argc && i < kMaxArgs; ++i) mix(key.args[i]);
        return h;
    }

    static bool KeysEqual(const GateEntry& entry, const CallKey& key)
    {
        if (!entry.valid) return false;
        if (entry.key.target != key.target) return false;
        if (entry.key.callsite != key.callsite) return false;
        if (entry.key.thisPtr != key.thisPtr) return false;
        if (entry.key.argc != key.argc) return false;
        for (uint8_t i = 0; i < key.argc; ++i)
        {
            if (entry.key.args[i] != key.args[i]) return false;
        }
        return true;
    }

    static bool ShouldDrop(const CallKey& key, DWORD now)
    {
        const size_t mask = kGateTableSize - 1;
        size_t idx = HashKey(key) & mask;

        for (size_t probe = 0; probe < kGateTableSize; ++probe)
        {
            GateEntry& slot = g_gate[(idx + probe) & mask];

            if (slot.valid)
            {
                DWORD age = now - slot.stamp;
                if (age > kGateExpiryMs)
                {
                    memset(&slot, 0, sizeof(slot));
                    --probe; // revisit the same slot on next loop iteration
                    continue;
                }

                if (KeysEqual(slot, key))
                {
                    if (now - slot.stamp <= kWindowMs)
                    {
                        return true; // within throttle window -> drop duplicate
                    }
                    slot.stamp = now;
                    for (uint8_t i = 0; i < key.argc; ++i) slot.key.args[i] = key.args[i];
                    return false;
                }
            }
            else
            {
                slot.valid = true;
                slot.stamp = now;
                slot.key = key;
                for (uint8_t i = key.argc; i < kMaxArgs; ++i) slot.key.args[i] = 0;
                return false;
            }
        }

        // Table saturated; clobber the initial bucket.
        GateEntry& slot = g_gate[idx];
        slot.valid = true;
        slot.stamp = now;
        slot.key = key;
        for (uint8_t i = key.argc; i < kMaxArgs; ++i) slot.key.args[i] = 0;
        return false;
    }

    extern "C" __declspec(noinline) int __cdecl CallSplit_OnEnter(void* ecxThis, Site* site, const uintptr_t* argBase)
    {
        if (!site) return 1;

        CallKey key{};
        key.target = site->target;
        key.callsite = reinterpret_cast<uintptr_t>(site->call);
        key.thisPtr = ecxThis;
        key.argc = site->argc;
        if (key.argc > kMaxArgs) key.argc = kMaxArgs;

        for (uint8_t i = 0; i < key.argc; ++i)
        {
            key.args[i] = argBase ? argBase[i] : 0;
        }
        for (uint8_t i = key.argc; i < kMaxArgs; ++i) key.args[i] = 0;

        return ShouldDrop(key, NowMs()) ? 0 : 1;
    }

    static void* BuildStub(Site* site)
    {
        if (!site) return nullptr;
        BYTE code[] = {
            0x9C,                               // pushfd
            0x60,                               // pushad
            0x8B, 0x44, 0x24, 0x10,             // mov eax, [esp+0x10] (saved ESP)
            0x83, 0xC0, 0x08,                   // add eax, 8 (skip RET + saved ESP)
            0x50,                               // push eax (arg base)
            0x68, 0,0,0,0,                      // push imm32 (Site*)
            0x51,                               // push ecx (this)
            0xB8, 0,0,0,0,                      // mov eax, &CallSplit_OnEnter
            0xFF, 0xD0,                         // call eax
            0x83, 0xC4, 0x0C,                   // add esp, 12
            0x85, 0xC0,                         // test eax, eax
            0x74, 0x09,                         // jz skip
            0x61,                               // popad
            0x9D,                               // popfd
            0xB8, 0,0,0,0,                      // mov eax, target
            0xFF, 0xE0,                         // jmp eax
            0x61,                               // skip: popad
            0x9D,                               // popfd
            0xC3                                // ret
        };

        BYTE* mem = (BYTE*)VirtualAlloc(nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem) return nullptr;

        *reinterpret_cast<uintptr_t*>(code + 11) = reinterpret_cast<uintptr_t>(site);
        *reinterpret_cast<void**>(code + 17) = (void*)&CallSplit_OnEnter;
        *reinterpret_cast<uintptr_t*>(code + 33) = site->target;

        memcpy(mem, code, sizeof(code));
        FlushInstructionCache(GetCurrentProcess(), mem, sizeof(code));
        return mem;
    }

    static bool ArmSite(Site& s)
    {
        if (!s.stub) s.stub = BuildStub(&s);
        if (!s.stub) return false;

        BYTE patched[5] = { 0xE8, 0,0,0,0 };
        intptr_t rel = (intptr_t)s.stub - (intptr_t)(s.call + 5);
        *reinterpret_cast<int32_t*>(patched + 1) = static_cast<int32_t>(rel);

        if (!ProtWrite(s.call, patched, sizeof(patched))) return false;
        s.armed = true;
        dprintfA("[CALLGATE] armed call=0x%08X -> target=0x%08X argc=%u\n",
            (unsigned)(uintptr_t)s.call, (unsigned)s.target, (unsigned)s.argc);
        return true;
    }

    static void DisarmSite(Site& s)
    {
        if (!s.armed) return;
        ProtWrite(s.call, s.orig, sizeof(s.orig));
        s.armed = false;
        dprintfA("[CALLGATE] restored call=0x%08X\n", (unsigned)(uintptr_t)s.call);
    }

    static void ScanAndPatchAll()
    {
        BYTE* base = nullptr;
        BYTE* text = nullptr;
        DWORD textSize = 0;
        if (!GetTextRange(base, text, textSize))
        {
            dlog("[CALLGATE] GetTextRange failed\n");
            return;
        }

        size_t added = 0;
        for (DWORD i = 0; i + 5 <= textSize && g_sites.size() < kMaxSites; ++i)
        {
            BYTE* p = text + i;
            if (!IsCallE8At(p)) continue;

            int32_t rel = *reinterpret_cast<int32_t*>(p + 1);
            uintptr_t tgt = (uintptr_t)(p + 5) + rel;

            if (std::find(g_targets.begin(), g_targets.end(), tgt) == g_targets.end())
                continue;

            if (std::any_of(g_sites.begin(), g_sites.end(), [p](const Site& s) { return s.call == p; }))
                continue;

            TargetMeta* meta = EnsureMeta(tgt);
            Site s{};
            s.ret = (uintptr_t)(p + 5);
            s.call = p;
            memcpy(s.orig, p, sizeof(s.orig));
            s.target = tgt;
            s.stub = nullptr;
            s.argc = meta ? meta->argc : static_cast<uint8_t>(kMaxArgs);
            s.armed = false;

            g_sites.push_back(s);
            ++added;
        }

        dprintfA("[CALLGATE] scan added=%u (total=%u)\n", (unsigned)added, (unsigned)g_sites.size());
        for (auto& s : g_sites)
        {
            if (!s.armed) ArmSite(s);
        }
    }

}

void CallSplit_Init()
{
    static bool once = false;
    if (once) return;
    once = true;

    g_sites.reserve(kMaxSites);

    for (uintptr_t ret : kSeedRetAddrs)
    {
        BYTE* call = nullptr;
        uintptr_t tgt = 0;
        if (ResolveCallFromRet(ret, call, tgt))
        {
            if (std::find(g_targets.begin(), g_targets.end(), tgt) == g_targets.end())
            {
                g_targets.push_back(tgt);
                dprintfA("[CALLGATE] seed ret=0x%08X call=0x%08X target=0x%08X\n",
                    (unsigned)ret, (unsigned)(uintptr_t)call, (unsigned)tgt);
            }
        }
        else
        {
            dprintfA("[CALLGATE] seed ret=0x%08X not CALL — skipped\n", (unsigned)ret);
        }
    }

    ScanAndPatchAll();

    dprintfA("[CALLGATE] ready (targets=%u sites=%u window=%u ms)\n",
        (unsigned)g_targets.size(), (unsigned)g_sites.size(), (unsigned)kWindowMs);
}

void CallSplit_Frame()
{
    const DWORD now = NowMs();
    const DWORD expire = kWindowMs + kGateExpiryMs;

    // Sweep a handful of entries per frame to keep the table fresh without stalling.
    for (int step = 0; step < 8; ++step)
    {
        GateEntry& slot = g_gate[g_gateSweep];
        if (slot.valid && (now - slot.stamp) > expire)
        {
            memset(&slot, 0, sizeof(slot));
        }
        g_gateSweep = (g_gateSweep + 1) & (kGateTableSize - 1);
    }
}
