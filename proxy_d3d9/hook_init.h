#pragma once
#include <d3d9.h>

// One-time initialization (MinHook, pattern scanning; safe to call multiple times).
void InitHooksOnce();

// Install CreateDevice/Ex hooks on the *returned* D3D9 objects so we can hook EndScene lazily.
void InstallCreateDeviceHooks(IDirect3D9* d3d9);
void InstallCreateDeviceExHooks(IDirect3D9Ex* d3d9ex);
