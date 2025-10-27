#include "timing.h"
#include <windows.h>
double NowSecondsMonotonic() {
    static LARGE_INTEGER F = []() { LARGE_INTEGER x; QueryPerformanceFrequency(&x); return x; }();
    LARGE_INTEGER t; QueryPerformanceCounter(&t);
    return double(t.QuadPart) / double(F.QuadPart);
}
