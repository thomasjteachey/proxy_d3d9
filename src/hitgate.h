#pragma once
#include <atomic>
#include <cstdint>

using SVKStarter_t = void(__thiscall*)(void* self, int a1, int a2);

void HitGate_Init();
void HitGate_ArmOneFrame();
bool HitGate_TryDeferSVK(void* self, int a1, int a2, SVKStarter_t orig);
bool HitGate_IsEnabled();
