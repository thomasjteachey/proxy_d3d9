#pragma once

// Simple low-latency toggle (F9 in-game)
void Latency_Init();            // safe to call more than once
void Latency_Enable(bool on);   // you can also flip it from your code
bool Latency_IsEnabled();
