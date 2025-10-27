#pragma once
#include <cstddef>
#include <cstdint>

// Scan entire module .text for pattern+mask
void* FindPattern(const uint8_t* pattern, const char* mask);

// Low-level: scan a specific memory range
void* FindPattern(const uint8_t* pattern, const char* mask, void* start, size_t len);
