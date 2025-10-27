#include <windows.h>
#include <vector>
#include <unordered_set>
#include <string>

static void dbg(const char* s) { OutputDebugStringA(s); }
static void dbgline(const std::string& s) { OutputDebugStringA((s + "\n").c_str()); }

struct Sect { BYTE* base; DWORD size; };
static bool getSect(HMODULE mod, const char* name, Sect& out) {
    auto* dos = (IMAGE_DOS_HEADER*)mod;
    auto* nt = (IMAGE_NT_HEADERS*)((BYTE*)mod + dos->e_lfanew);
    auto* sh = (IMAGE_SECTION_HEADER*)(nt + 1);
    for (UINT i = 0; i < nt->FileHeader.NumberOfSections; i++, sh++) {
        char nm[9] = {}; memcpy(nm, sh->Name, 8);
        if (_stricmp(nm, name) == 0) {
            out.base = (BYTE*)mod + sh->VirtualAddress;
            out.size = sh->Misc.VirtualSize ? sh->Misc.VirtualSize : sh->SizeOfRawData;
            return true;
        }
    }
    return false;
}

static BYTE* findAscii(BYTE* hay, DWORD sz, const char* needle) {
    size_t n = strlen(needle);
    for (DWORD i = 0; i + n <= sz; i++) {
        if (memcmp(hay + i, needle, n) == 0) return hay + i;
    }
    return nullptr;
}

static BYTE* findFuncStart(BYTE* ref, BYTE* textBase) {
    // scan back up to 0x400 bytes for a standard prolog 55 8B EC
    for (int back = 0; back < 0x400; ++back) {
        BYTE* p = ref - back;
        if (p < textBase) break;
        if (p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC) return p;
    }
    return nullptr;
}

static std::string bytes24(BYTE* p, int n = 24) {
    char b[8]; std::string s;
    for (int i = 0; i < n; i++) { sprintf_s(b, "%02X", p[i]); if (i) s.push_back(' '); s += b; }
    return s;
}

void DumpSVKCandidates() {
    HMODULE mod = GetModuleHandleA(nullptr);
    Sect rdata{}, text{};
    if (!getSect(mod, ".rdata", rdata) || !getSect(mod, ".text", text)) {
        dbgline("[ClientFix][SVK] section lookup failed"); return;
    }

    const char* needle = "DBFilesClient\\SpellVisualKit.dbc";
    BYTE* s = findAscii(rdata.base, rdata.size, needle);
    if (!s) { dbgline("[ClientFix][SVK] string not found"); return; }

    char hdr[128];
    sprintf_s(hdr, "[ClientFix][SVK] string @ 0x%p (searching code refs)", s);
    dbgline(hdr);

    std::unordered_set<BYTE*> uniq;
    std::vector<BYTE*> funcs;

    // look for the 4-byte immediate equal to &string in .text
    DWORD imm = (DWORD)(uintptr_t)s;
    for (DWORD i = 0; i + 4 <= text.size; i++) {
        if (*(DWORD*)(text.base + i) == imm) {
            BYTE* ref = text.base + i;
            BYTE* f = findFuncStart(ref, text.base);
            if (f && !uniq.count(f)) {
                uniq.insert(f); funcs.push_back(f);
            }
        }
    }

    for (size_t i = 0; i < funcs.size(); ++i) {
        char line[256];
        sprintf_s(line, "[ClientFix][SVK] cand %zu: func=0x%p  bytes=%s", i, funcs[i],
            bytes24(funcs[i]).c_str());
        dbgline(line);
    }
    if (funcs.empty()) dbgline("[ClientFix][SVK] no code refs found");
}
