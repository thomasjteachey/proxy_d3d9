// d3d9_proxy.cpp — D3D9 proxy that forwards to system d3d9.dll and initializes our hooks lazily.

#include <windows.h>
#include <d3d9.h>
#include <wchar.h>
#include "hook_init.h"

static HMODULE gRealD3D9 = nullptr;

using PFN_D3D9 = IDirect3D9 * (WINAPI*)(UINT);
using PFN_D3D9E = HRESULT(WINAPI*)(UINT, IDirect3D9Ex**);

static PFN_D3D9  pDirect3DCreate9 = nullptr;
static PFN_D3D9E pDirect3DCreate9Ex = nullptr;

static void LoadRealD3D9()
{
    if (gRealD3D9) return;
    wchar_t sysPath[MAX_PATH] = {};
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\d3d9.dll");
    gRealD3D9 = LoadLibraryW(sysPath);
    if (!gRealD3D9) return;
    pDirect3DCreate9 = reinterpret_cast<PFN_D3D9>(GetProcAddress(gRealD3D9, "Direct3DCreate9"));
    pDirect3DCreate9Ex = reinterpret_cast<PFN_D3D9E>(GetProcAddress(gRealD3D9, "Direct3DCreate9Ex"));
}

// Let hook_init call the *real* creators if it ever needs to (we don’t for lazy init, but keep them)
extern "C" __declspec(dllexport) PFN_D3D9  __cdecl GetReal_Direct3DCreate9() { LoadRealD3D9(); return pDirect3DCreate9; }
extern "C" __declspec(dllexport) PFN_D3D9E __cdecl GetReal_Direct3DCreate9Ex() { LoadRealD3D9(); return pDirect3DCreate9Ex; }

// ----- Proxy exports -----
// We initialize MinHook + our pattern scanners, then hook CreateDevice on the returned D3D9 object.

extern "C" IDirect3D9* WINAPI Direct3DCreate9(UINT sdk)
{
    LoadRealD3D9();
    IDirect3D9* d3d = pDirect3DCreate9 ? pDirect3DCreate9(sdk) : nullptr;
    if (d3d) {
        InitHooksOnce();                 // MinHook init + (harmless) combat pattern scan
        InstallCreateDeviceHooks(d3d);   // hook IDirect3D9::CreateDevice (lazy EndScene hook later)
    }
    return d3d;
}

extern "C" HRESULT WINAPI Direct3DCreate9Ex(UINT sdk, IDirect3D9Ex** out)
{
    LoadRealD3D9();
    HRESULT hr = pDirect3DCreate9Ex ? pDirect3DCreate9Ex(sdk, out) : E_NOTIMPL;
    if (SUCCEEDED(hr) && out && *out) {
        InitHooksOnce();
        InstallCreateDeviceExHooks(*out);   // hook IDirect3D9Ex::CreateDeviceEx too
        // Many clients still call base CreateDevice; install both hooks.
        InstallCreateDeviceHooks(reinterpret_cast<IDirect3D9*>(*out));
    }
    return hr;
}

// ----- Forward the other common D3D9 exports some clients call early -----
template <typename T> static T Real(const char* name) {
    LoadRealD3D9(); return reinterpret_cast<T>(gRealD3D9 ? GetProcAddress(gRealD3D9, name) : nullptr);
}
extern "C" int   WINAPI D3DPERF_BeginEvent(D3DCOLOR c, LPCWSTR s) { using F = int(WINAPI*)(D3DCOLOR, LPCWSTR); auto f = Real<F>("D3DPERF_BeginEvent"); return f ? f(c, s) : 0; }
extern "C" int   WINAPI D3DPERF_EndEvent() { using F = int(WINAPI*)();                 auto f = Real<F>("D3DPERF_EndEvent");    return f ? f() : 0; }
extern "C" DWORD WINAPI D3DPERF_GetStatus() { using F = DWORD(WINAPI*)();               auto f = Real<F>("D3DPERF_GetStatus");   return f ? f() : 0; }
extern "C" BOOL  WINAPI D3DPERF_QueryRepeatFrame() { using F = BOOL(WINAPI*)();                auto f = Real<F>("D3DPERF_QueryRepeatFrame"); return f ? f() : FALSE; }
extern "C" void  WINAPI D3DPERF_SetMarker(D3DCOLOR c, LPCWSTR s) { using F = void(WINAPI*)(D3DCOLOR, LPCWSTR); if (auto f = Real<F>("D3DPERF_SetMarker")) f(c, s); }
extern "C" void  WINAPI D3DPERF_SetOptions(DWORD o) { using F = void(WINAPI*)(DWORD);            if (auto f = Real<F>("D3DPERF_SetOptions")) f(o); }
extern "C" void  WINAPI D3DPERF_SetRegion(D3DCOLOR c, LPCWSTR s) { using F = void(WINAPI*)(D3DCOLOR, LPCWSTR); if (auto f = Real<F>("D3DPERF_SetRegion")) f(c, s); }
extern "C" LPVOID WINAPI Direct3DShaderValidatorCreate9() { using F = LPVOID(WINAPI*)();               auto f = Real<F>("Direct3DShaderValidatorCreate9"); return f ? f() : nullptr; }
extern "C" void  WINAPI PSGPSampleTexture() { using F = void(WINAPI*)();                 if (auto f = Real<F>("PSGPSampleTexture")) f(); }

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }
