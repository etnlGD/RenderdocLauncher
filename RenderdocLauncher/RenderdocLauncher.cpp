#include "RenderdocLauncher.h"

#include <cstdio>
#include <d3d11.h>

#include "PolyHook/PolyHook.hpp"
#include <vector>
#include <string>

#define LogDebug(x) printf(x)

int WINAPI CreateDirect3D11DeviceFromDXGIDevice() { printf("CreateDirect3D11DeviceFromDXGIDevice"); return 0; }
int WINAPI CreateDirect3D11SurfaceFromDXGISurface() { printf("CreateDirect3D11SurfaceFromDXGISurface"); return 0; }
int WINAPI D3D11CoreCreateDevice() { printf("D3D11CoreCreateDevice"); return 0; }
int WINAPI D3D11CoreCreateLayeredDevice() { printf("D3D11CoreCreateLayeredDevice"); return 0; }
int WINAPI D3D11CoreGetLayeredDeviceSize() { printf("D3D11CoreGetLayeredDeviceSize"); return 0; }
int WINAPI D3D11CoreRegisterLayers() { printf("D3D11CoreRegisterLayers"); return 0; }
int WINAPI D3D11CreateDevice() { printf("D3D11CreateDevice"); return 0; }
int WINAPI D3D11CreateDeviceAndSwapChain() { printf("D3D11CreateDeviceAndSwapChain"); return 0; }
int WINAPI D3D11CreateDeviceForD3D12() { printf("D3D11CreateDeviceForD3D12"); return 0; }
int WINAPI D3D11On12CreateDevice() { printf("D3D11On12CreateDevice"); return 0; }
int WINAPI D3DKMTCloseAdapter() { printf("D3DKMTCloseAdapter"); return 0; }
int WINAPI D3DKMTCreateAllocation() { printf("D3DKMTCreateAllocation"); return 0; }
int WINAPI D3DKMTCreateContext() { printf("D3DKMTCreateContext"); return 0; }
int WINAPI D3DKMTCreateDevice() { printf("D3DKMTCreateDevice"); return 0; }
int WINAPI D3DKMTCreateSynchronizationObject() { printf("D3DKMTCreateSynchronizationObject"); return 0; }
int WINAPI D3DKMTDestroyAllocation() { printf("D3DKMTDestroyAllocation"); return 0; }
int WINAPI D3DKMTDestroyContext() { printf("D3DKMTDestroyContext"); return 0; }
int WINAPI D3DKMTDestroyDevice() { printf("D3DKMTDestroyDevice"); return 0; }
int WINAPI D3DKMTDestroySynchronizationObject() { printf("D3DKMTDestroySynchronizationObject"); return 0; }
int WINAPI D3DKMTEscape() { printf("D3DKMTEscape"); return 0; }
int WINAPI D3DKMTGetContextSchedulingPriority() { printf("D3DKMTGetContextSchedulingPriority"); return 0; }
int WINAPI D3DKMTGetDeviceState() { printf("D3DKMTGetDeviceState"); return 0; }
int WINAPI D3DKMTGetDisplayModeList() { printf("D3DKMTGetDisplayModeList"); return 0; }
int WINAPI D3DKMTGetMultisampleMethodList() { printf("D3DKMTGetMultisampleMethodList"); return 0; }
int WINAPI D3DKMTGetRuntimeData() { printf("D3DKMTGetRuntimeData"); return 0; }
int WINAPI D3DKMTGetSharedPrimaryHandle() { printf("D3DKMTGetSharedPrimaryHandle"); return 0; }
int WINAPI D3DKMTLock() { printf("D3DKMTLock"); return 0; }
int WINAPI D3DKMTOpenAdapterFromHdc() { printf("D3DKMTOpenAdapterFromHdc"); return 0; }
int WINAPI D3DKMTOpenResource() { printf("D3DKMTOpenResource"); return 0; }
int WINAPI D3DKMTPresent() { printf("D3DKMTPresent"); return 0; }
int WINAPI D3DKMTQueryAdapterInfo() { printf("D3DKMTQueryAdapterInfo"); return 0; }
int WINAPI D3DKMTQueryAllocationResidency() { printf("D3DKMTQueryAllocationResidency"); return 0; }
int WINAPI D3DKMTQueryResourceInfo() { printf("D3DKMTQueryResourceInfo"); return 0; }
int WINAPI D3DKMTRender() { printf("D3DKMTRender"); return 0; }
int WINAPI D3DKMTSetAllocationPriority() { printf("D3DKMTSetAllocationPriority"); return 0; }
int WINAPI D3DKMTSetContextSchedulingPriority() { printf("D3DKMTSetContextSchedulingPriority"); return 0; }
int WINAPI D3DKMTSetDisplayMode() { printf("D3DKMTSetDisplayMode"); return 0; }
int WINAPI D3DKMTSetDisplayPrivateDriverFormat() { printf("D3DKMTSetDisplayPrivateDriverFormat"); return 0; }
int WINAPI D3DKMTSetGammaRamp() { printf("D3DKMTSetGammaRamp"); return 0; }
int WINAPI D3DKMTSetVidPnSourceOwner() { printf("D3DKMTSetVidPnSourceOwner"); return 0; }
int WINAPI D3DKMTSignalSynchronizationObject() { printf("D3DKMTSignalSynchronizationObject"); return 0; }
int WINAPI D3DKMTUnlock() { printf("D3DKMTUnlock"); return 0; }
int WINAPI D3DKMTWaitForSynchronizationObject() { printf("D3DKMTWaitForSynchronizationObject"); return 0; }
int WINAPI D3DKMTWaitForVerticalBlankEvent() { printf("D3DKMTWaitForVerticalBlankEvent"); return 0; }
int WINAPI D3DPerformance_BeginEvent() { printf("D3DPerformance_BeginEvent"); return 0; }
int WINAPI D3DPerformance_EndEvent() { printf("D3DPerformance_EndEvent"); return 0; }
int WINAPI D3DPerformance_GetStatus() { printf("D3DPerformance_GetStatus"); return 0; }
int WINAPI D3DPerformance_SetMarker() { printf("D3DPerformance_SetMarker"); return 0; }
int WINAPI EnableFeatureLevelUpgrade() { printf("EnableFeatureLevelUpgrade"); return 0; }
int WINAPI OpenAdapter10() { printf("OpenAdapter10"); return 0; }
int WINAPI OpenAdapter10_2() { printf("OpenAdapter10_2"); return 0; }

static HMODULE hD3D11 = 0;
static HMODULE hCurrentModule = 0;
static HMODULE hRenderdoc = 0;
static HMODULE hDXGI = 0;

struct DetourHookInfo
{
public:
	HMODULE hTargetModule;
	LPCSTR  sTargetFunc;
	HMODULE hSourceModule;
	LPCSTR  sSourceFunc;
	PLH::Detour* m_pDetour;
	bool m_bInstalledHook;

public:
	DetourHookInfo(HMODULE targetModule, LPCSTR targetFunc, HMODULE sourceModule, LPCSTR sourceFunc = NULL) :
		hTargetModule(targetModule), sTargetFunc(targetFunc),
		hSourceModule(sourceModule), sSourceFunc(sourceFunc ? sourceFunc : targetFunc),
		m_pDetour(new PLH::Detour), m_bInstalledHook(false)
	{
	}

	void HackOverwatch()
	{
		if (hTargetModule == hD3D11)
		{
			HMODULE hModule = GetModuleHandle(NULL);
			WCHAR moduelFilename[MAX_PATH];
			GetModuleFileName(hModule, moduelFilename, MAX_PATH);

			bool hookOverwatch = false;

			if (strcmp(sTargetFunc, "D3D11CreateDevice") == 0)
			{
				m_pDetour->m_PreserveSize = 32;

				uint8_t codeBytes[] = {
					0x48, 0x83, 0xC4, 0x78, // add rsp, 78h
					0x41, 0x5F, // pop r15
					0x41, 0x5E, // pop r14
					0x41, 0x5D, // pop r13
					0x41, 0x5C, // pop r12
					0x5F,		// pop rdi
					0x5E,		// pop rsi
					0x5B,		// pop rbx
					0x5D,		// pop rbp
				};

				m_pDetour->m_RestoreCode = new uint8_t[sizeof(codeBytes)];
				memcpy(m_pDetour->m_RestoreCode, codeBytes, sizeof(codeBytes));
				m_pDetour->m_RestoreCodeSize = sizeof(codeBytes);
			}
			else if (strcmp(sTargetFunc, "D3D11CreateDeviceAndSwapChain") == 0)
			{
				m_pDetour->m_PreserveSize = 32;

				uint8_t codeBytes[] = {
					0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00, // add rsp, 88h
					0x41, 0x5F, // pop r15
					0x41, 0x5E, // pop r14
					0x41, 0x5D, // pop r13
					0x41, 0x5C, // pop r12
					0x5F,		// pop rdi
					0x5E,		// pop rsi
					0x5B,		// pop rbx
					0x5D,		// pop rbp
				};

				m_pDetour->m_RestoreCode = new uint8_t[sizeof(codeBytes)];
				memcpy(m_pDetour->m_RestoreCode, codeBytes, sizeof(codeBytes));
				m_pDetour->m_RestoreCodeSize = sizeof(codeBytes);
			}
		}
	}

	bool InstallHook()
	{
		uint8_t* pTargetFunc = (uint8_t*)GetProcAddress(hTargetModule, sTargetFunc);
		uint8_t* pSourceFunc = (uint8_t*)GetProcAddress(hSourceModule, sSourceFunc);

		if (pTargetFunc == NULL || pSourceFunc == NULL)
			return false;

		wchar_t curFile[512];
		GetModuleFileNameW(NULL, curFile, 512);
		std::wstring f(curFile);
		transform(f.begin(), f.end(), f.begin(), towlower);

		// Overwatch checks top 32 bytes of these functions, so do some hack.
		if (f.find(L"overwatch.exe") != std::wstring::npos)
			HackOverwatch();
		
		m_pDetour->SetupHook(pTargetFunc, pSourceFunc);
		m_bInstalledHook = m_pDetour->Hook();
		return m_bInstalledHook;
	}

	FARPROC GetOriginal()
	{
		return m_bInstalledHook ? 
			m_pDetour->GetOriginal<FARPROC>() : GetProcAddress(hTargetModule, sTargetFunc);
	}
};
std::vector<DetourHookInfo> sDetourHooks;

// // 保证 Renderdoc 始终调用真正的 d3d11 API
static PLH::IATHook* pGetProcAddressHook;
static FARPROC WINAPI Hooked_GetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName)
{
	if (hModule == hCurrentModule)
	{
		hModule = hD3D11;
	}

	for (auto it = sDetourHooks.begin(); it != sDetourHooks.end(); ++it)
	{
		if (hModule == it->hTargetModule && strcmp(it->sTargetFunc, lpProcName) == 0)
			return it->GetOriginal();
	}

	return GetProcAddress(hModule, lpProcName);
}

static void InstallRenderdocIATHook()
{
	// 保证 Renderdoc 始终调用真正的 d3d11 API
	pGetProcAddressHook = new PLH::IATHook;
	pGetProcAddressHook->SetupHook("kernel32.dll", "GetProcAddress",
									(uint8_t*)&Hooked_GetProcAddress, "renderdoc.dll");
	if (pGetProcAddressHook->Hook())
		LogDebug("Hook renderdoc.dll GetProcAddress failed.\n");

	typedef void (__cdecl *tRENDERDOC_CreateHooks) (UINT Flags);

	tRENDERDOC_CreateHooks pfnCreateHooks = 
		(tRENDERDOC_CreateHooks) GetProcAddress(hRenderdoc, "RENDERDOC_CreateHooks");

	pfnCreateHooks(1);
}


HRESULT WINAPI RENDERDOC_CreateWrappedD3D11DeviceAndSwapChain(
	_In_opt_ IDXGIAdapter* pAdapter,
	D3D_DRIVER_TYPE DriverType,
	HMODULE Software,
	UINT Flags,
	_In_reads_opt_(FeatureLevels) CONST D3D_FEATURE_LEVEL* pFeatureLevels,
	UINT FeatureLevels,
	UINT SDKVersion,
	_In_opt_ CONST DXGI_SWAP_CHAIN_DESC* pSwapChainDesc,
	_Out_opt_ IDXGISwapChain** ppSwapChain,
	_Out_opt_ ID3D11Device** ppDevice,
	_Out_opt_ D3D_FEATURE_LEVEL* pFeatureLevel,
	_Out_opt_ ID3D11DeviceContext** ppImmediateContext)
{
	PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN pfn = (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN) Hooked_GetProcAddress(hD3D11, "D3D11CreateDeviceAndSwapChain");
	Software = NULL;
	return pfn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
}

HRESULT WINAPI RENDERDOC_CreateWrappedD3D11Device(
	_In_opt_ IDXGIAdapter* pAdapter,
	D3D_DRIVER_TYPE DriverType,
	HMODULE Software,
	UINT Flags,
	_In_reads_opt_(FeatureLevels) CONST D3D_FEATURE_LEVEL* pFeatureLevels,
	UINT FeatureLevels,
	UINT SDKVersion,
	_Out_opt_ ID3D11Device** ppDevice,
	_Out_opt_ D3D_FEATURE_LEVEL* pFeatureLevel,
	_Out_opt_ ID3D11DeviceContext** ppImmediateContext)
{
	PFN_D3D11_CREATE_DEVICE pfn = (PFN_D3D11_CREATE_DEVICE) Hooked_GetProcAddress(hD3D11, "D3D11CreateDevice");
	Software = NULL;
	return pfn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
}

bool InitD3D11AndRenderdoc(HMODULE currentModule)
{
	hCurrentModule = currentModule;

	WCHAR fullPath[MAX_PATH];
	UINT ret = GetSystemDirectoryW(fullPath, MAX_PATH);
	if (ret != 0 && ret < MAX_PATH) 
	{
		wcscat_s(fullPath, MAX_PATH, L"\\d3d11.dll");
		hD3D11 = LoadLibraryEx(fullPath, NULL, 0);
	}

	hRenderdoc =  LoadLibrary(L"renderdoc.dll");
	hDXGI =  LoadLibrary(L"dxgi.dll");
	if (hD3D11 == NULL || hRenderdoc == NULL || hDXGI == NULL)
	{
		LogDebug("Fetal error: load librarys failed.\n");
		return false; 
	}

// 	sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDeviceAndSwapChain", hCurrentModule, "RENDERDOC_CreateWrappedD3D11DeviceAndSwapChain"));
// 	sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDevice", hCurrentModule, "RENDERDOC_CreateWrappedD3D11Device"));

	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDeviceAndSwapChain", hRenderdoc, "RENDERDOC_CreateWrappedD3D11DeviceAndSwapChain"));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDevice", hRenderdoc, "RENDERDOC_CreateWrappedD3D11Device"));
	sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDeviceAndSwapChain", hRenderdoc, "RENDERDOC_CreateWrappedD3D11DeviceAndSwapChain"));
	sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDevice", hRenderdoc, "RENDERDOC_CreateWrappedD3D11Device"));
	sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory"));
	sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory1", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory1"));
	sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory2", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory2"));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "CreateDirect3D11DeviceFromDXGIDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "CreateDirect3D11SurfaceFromDXGISurface", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CoreCreateDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CoreCreateLayeredDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CoreGetLayeredDeviceSize", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CoreRegisterLayers", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDeviceForD3D12", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11On12CreateDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCloseAdapter", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCreateAllocation", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCreateContext", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCreateDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCreateSynchronizationObject", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTDestroyAllocation", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTDestroyContext", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTDestroyDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTDestroySynchronizationObject", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTEscape", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetContextSchedulingPriority", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetDeviceState", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetDisplayModeList", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetMultisampleMethodList", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetRuntimeData", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetSharedPrimaryHandle", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTLock", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTOpenAdapterFromHdc", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTOpenResource", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTPresent", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTQueryAdapterInfo", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTQueryAllocationResidency", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTQueryResourceInfo", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTRender", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetAllocationPriority", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetContextSchedulingPriority", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetDisplayMode", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetDisplayPrivateDriverFormat", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetGammaRamp", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetVidPnSourceOwner", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSignalSynchronizationObject", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTUnlock", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTWaitForSynchronizationObject", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTWaitForVerticalBlankEvent", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DPerformance_BeginEvent", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DPerformance_EndEvent", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DPerformance_GetStatus", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DPerformance_SetMarker", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "EnableFeatureLevelUpgrade", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "OpenAdapter10", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "OpenAdapter10_2", hD3D11));
	
	for (auto it = sDetourHooks.begin(); it != sDetourHooks.end(); ++it)
	{
		it->InstallHook();
	}

	InstallRenderdocIATHook();

	return true;
}
