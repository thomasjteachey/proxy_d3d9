#pragma once

#include <cstdint>

// NetTrace: lightweight instrumentation for winsock recv/WSARecv callsites.
// Includes an optional WoW packet parser (3.3.5-style server header:
//   uint16 size, uint16 opcode, then payload (size-2 bytes)).
//
// Hotkeys (checked once per rendered frame):
//  - F8: dump top recv callers
//  - F9: clear caller stats
//  - F7: enable verbose opcode logging for ~10 seconds

namespace NetTrace
{
    void Init();

    // Record a recv/WSARecv call (counter-only). Kept for compatibility.
    void RecordRecv(int nbytes, int flags);

    // Record recv bytes (and attempt WoW packet parsing).
    // `sock` is SOCKET cast to uint64_t (uintptr_t -> uint64_t).
    void RecordRecv(uint64_t sock, const uint8_t* data, int len, int flags);

    // Called from the EndScene hook once per rendered frame.
    void OnFrameBoundary();

    // Convenience accessors.
    uint32_t GetFrame();

    // Debug helpers.
    void DumpTopCallers(int maxCount = 20);
    void ClearStats();
}
