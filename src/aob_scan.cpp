#include <windows.h>
#include <cstdint>
#include "aob_scan.h"

static bool Match(const uint8_t* p, const uint8_t* pat, const char* mask) {
    for (; *mask; ++mask, ++p, ++pat) {
        if (*mask != 'x') continue;            // '?' means wildcard
        if (*p != *pat) return false;
    }
    return true;
}

// helper: get range of a PE section by name (e.g., ".text")
static bool GetSectionRange(HMODULE mod, const char* name, uint8_t*& base, size_t& size) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>((uint8_t*)mod + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        char nm[9] = {}; memcpy(nm, sec->Name, 8);
        if (_stricmp(nm, name) == 0) {
            base = reinterpret_cast<uint8_t*>(mod) + sec->VirtualAddress;
            size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
            return true;
        }
    }
    return false;
}

bool GetTextRange(uint8_t*& base, size_t& size)
{
    HMODULE mod = GetModuleHandleA(nullptr);
    return GetSectionRange(mod, ".text", base, size);
}

bool GetImageRange(uint8_t*& base, size_t& size)
{
    HMODULE mod = GetModuleHandleA(nullptr);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>((uint8_t*)mod + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return false;

    base = reinterpret_cast<uint8_t*>(mod);
    size = nt->OptionalHeader.SizeOfImage;
    return true;
}

// 4-arg range scanner (what you already had)
void* FindPattern(const uint8_t* pattern, const char* mask, void* start, size_t len) {
    auto* base = static_cast<uint8_t*>(start);
    size_t patlen = strlen(mask);
    if (len < patlen) return nullptr;

    size_t stop = len - patlen + 1;
    for (size_t i = 0; i < stop; ++i) {
        if (Match(base + i, pattern, mask)) return base + i;
    }
    return nullptr;
}

// 2-arg overload: scan the host module's .text
void* FindPattern(const uint8_t* pattern, const char* mask) {
    HMODULE mod = GetModuleHandleA(nullptr);
    uint8_t* base = nullptr; size_t size = 0;
    if (!GetSectionRange(mod, ".text", base, size)) return nullptr;
    return FindPattern(pattern, mask, base, size);
}
