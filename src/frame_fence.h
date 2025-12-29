#pragma once
#include <cstdint>
// Initialize once (sets 1ms timer granularity)
void FrameFence_Init();

// Call exactly once per rendered frame (from your EndScene detour)
void FrameFence_Tick();

// Read current frame id (monotonic)
unsigned FrameFence_Id();

// Block this thread until the next frame is observed, or timeout (ms). Returns true if advanced.
bool FrameFence_WaitNext(unsigned maxWaitMs = 12);

// Track render thread id for diagnostics.
void FrameFence_SetRenderThreadId(uint32_t tid);
uint32_t FrameFence_RenderThreadId();
