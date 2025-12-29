#pragma once
#include <atomic>
#include <cstdint>

using SVKStarter_t = void(__thiscall*)(void* self, int a1, int a2);

void HitGate_Init();
void HitGate_ArmOneFrame();
bool HitGate_TryDeferSVK(void* self, int a1, int a2, SVKStarter_t orig);
bool HitGate_IsEnabled();
void HitGate_SetRenderThreadId(uint32_t tid);
uint32_t HitGate_GetDispatchHits();
uint32_t HitGate_GetSaw14A();
uint32_t HitGate_GetSaw14ATid();
uint32_t HitGate_GetLastOpcode();
uint32_t HitGate_GetLastDispatchTid();
