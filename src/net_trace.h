#pragma once

// Drop-in: no wiring needed beyond compiling these files in your DLL.
// A background thread auto-calls OnFrameBoundary() ~60Hz.
// Press F8 to dump top network recv callers (addresses inside Wow.exe .text).

namespace NetTrace {
    void Init();                         // auto-called at DLL attach
    void RecordRecv(int nbytes, int flags);
    void OnFrameBoundary();              // also runs from the background tick thread
    void DumpTopCallers(int maxCount = 20);
}
