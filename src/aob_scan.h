#pragma once
#include <cstddef>
#include <cstdint>

// Scan entire module .text for pattern+mask
void* FindPattern(const uint8_t* pattern, const char* mask);

// Low-level: scan a specific memory range
void* FindPattern(const uint8_t* pattern, const char* mask, void* start, size_t len);

// PE helpers
bool GetTextRange(uint8_t*& base, size_t& size);
bool GetImageRange(uint8_t*& base, size_t& size);
bool GetSectionRange(const char* name, uint8_t*& base, size_t& size);
