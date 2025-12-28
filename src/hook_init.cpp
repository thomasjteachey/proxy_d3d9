#include "hook_init.h"
#include <windows.h>
#include <d3d9.h>
#include <mutex>
#include <atomic>
#include "MinHook.h"
#include "hooks.h"   // InstallEndSceneHook, InstallCombatHooks
#include "svk_scan.h"
#include "net_trace.h"

static std::once_flag gOnce;
static std::atomic<bool> gEndSceneHooked{ false };

// ---- CreateDevice hooks ----
using CreateDevice_t = HRESULT(STDMETHODCALLTYPE*)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS*, IDirect3DDevice9**);
static CreateDevice_t oCreateDevice = nullptr;

static HRESULT STDMETHODCALLTYPE hkCreateDevice(IDirect3D9* self, UINT a, D3DDEVTYPE b, HWND c, DWORD d,
    D3DPRESENT_PARAMETERS* pp, IDirect3DDevice9** out)
{
    HRESULT hr = oCreateDevice(self, a, b, c, d, pp, out);
    if (SUCCEEDED(hr) && out && *out && !gEndSceneHooked.exchange(true)) {
        InstallEndSceneHook(*out);   // hook EndScene on the first real device
        OutputDebugStringA("[ClientFix] EndScene hook installed (CreateDevice)\n");
    }
    return hr;
}


static HRESULT STDMETHODCALLTYPE hkCreateDeviceEx(IDirect3D9Ex* self, UINT a, D3DDEVTYPE b, HWND c, DWORD d,
    D3DPRESENT_PARAMETERS* pp, D3DDISPLAYMODEEX* md, IDirect3DDevice9Ex** out)
{
    HRESULT hr = oCreateDeviceEx(self, a, b, c, d, pp, md, out);
    if (SUCCEEDED(hr) && out && *out && !gEndSceneHooked.exchange(true)) {
        InstallEndSceneHook(reinterpret_cast<IDirect3DDevice9*>(*out));
        OutputDebugStringA("[ClientFix] EndScene hook installed (CreateDeviceEx)\n");
    }
    return hr;
}

void InitHooksOnce()
{
    std::call_once(gOnce, [] {
        MH_Initialize();
        Latency_Init();   // <-- add this line
        CallSplit_Init();   // <-- add this
        NetTrace::Init();
        NetSplit_Init();
        // Pattern-scan & attach combat hooks (safe if patterns not set—they’ll just no-op).
        InstallCombatHooks();
        OutputDebugStringA("[ClientFix] InitHooksOnce()\n");
    });
}

void InstallCreateDeviceHooks(IDirect3D9* d3d9)
{
    if (!d3d9) return;
    void** vt = *reinterpret_cast<void***>(d3d9);
    void* target = vt[16];                 // IDirect3D9::CreateDevice
    MH_CreateHook(target, hkCreateDevice, reinterpret_cast<void**>(&oCreateDevice));
    MH_EnableHook(target);
    OutputDebugStringA("[ClientFix] Hooked IDirect3D9::CreateDevice\n");
}

void InstallCreateDeviceExHooks(IDirect3D9Ex* d3d9ex)
{
    if (!d3d9ex) return;
    void** vt = *reinterpret_cast<void***>(d3d9ex);
    // IDirect3D9Ex vtable: CreateDeviceEx is typically index 20
    void* target = vt[20];
    MH_CreateHook(target, hkCreateDeviceEx, reinterpret_cast<void**>(&oCreateDeviceEx));
    MH_EnableHook(target);
    OutputDebugStringA("[ClientFix] Hooked IDirect3D9Ex::CreateDeviceEx\n");
}
