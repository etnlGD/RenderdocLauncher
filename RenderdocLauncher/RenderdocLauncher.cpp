#include "RenderdocLauncher.h"
#include "CommonUtils.h"

#include <cstdio>
#include <d3d11.h>

#include "PolyHook/PolyHook.hpp"
#include <vector>
#include <string>
#include <stdint.h>
#include <map>
#include <ShlObj.h>

static bool g_RenderdocMode = false;

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
static std::wstring g_HookedProcessName;

struct DetourHookInfo
{
public:
	HMODULE hTargetModule;
	LPCSTR  sTargetFunc;
	FARPROC m_pSourceFunc;
	PLH::Detour* m_pDetour;
	bool m_bInstalledHook;

public:
	DetourHookInfo(HMODULE targetModule, LPCSTR targetFunc, 
				   HMODULE sourceModule, LPCSTR sourceFunc = NULL) :
		hTargetModule(targetModule), sTargetFunc(targetFunc),
		m_pDetour(new PLH::Detour), m_bInstalledHook(false)
	{
		if (sourceFunc == NULL)
			sourceFunc = targetFunc;

		m_pSourceFunc = (FARPROC)GetProcAddress(sourceModule, sourceFunc);
	}

	DetourHookInfo(HMODULE targetModule, LPCSTR targetFunc,
				   FARPROC pSourceFunc) :
				   hTargetModule(targetModule), sTargetFunc(targetFunc),
				   m_pSourceFunc(pSourceFunc),
				   m_pDetour(new PLH::Detour), m_bInstalledHook(false)
	{
	}

	void HackOverwatch()
	{
		if (hTargetModule == hD3D11)
		{
			if (strcmp(sTargetFunc, "D3D11CreateDevice") == 0)
			{
				m_pDetour->m_PreserveSize = 32;

				uint8_t codeBytes[] = {
#if 0
					0x48, 0x83, 0xC4, 0x78, // add rsp, 78h
#else 
					0x4D, 0x8B, 0xC7,	// mov r8, r15
					0x48, 0x83, 0xC4, 0x68, // add rsp, 68h
#endif
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
#if 0
					0x48, 0x81, 0xC4, 0x88, 0x00, 0x00, 0x00, // add rsp, 88h
#else
					0x48, 0x83, 0xC4, 0x78, // add rsp, 78h
#endif
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

		WCHAR targetModulePath[MAX_PATH];
		GetModuleFileName(hTargetModule, targetModulePath, MAX_PATH);
		if (pTargetFunc == NULL)
		{
			g_Logger->warn("can't find proc address of {}!{}", w2s(targetModulePath), sTargetFunc);
			return false;
		}

		if (m_pSourceFunc == NULL)
		{
			return false;
		}

		// Overwatch checks top 32 bytes of these functions, so do some hack.
		if (g_HookedProcessName.find(L"overwatch.exe") != std::wstring::npos)
			HackOverwatch();
		
		m_pDetour->SetupHook(pTargetFunc, (uint8_t*) m_pSourceFunc);
		m_bInstalledHook = m_pDetour->Hook();
		if (!m_bInstalledHook)
		{
			g_Logger->warn("Detour function {}!{} from {:p} to {:p} failed",
						   w2s(targetModulePath), sTargetFunc, 
						   (void*) pTargetFunc, (void*) m_pSourceFunc);
		}
		else
		{
			g_Logger->debug("Detour function {}!{} from {:p} to {:p} succeed",
						    w2s(targetModulePath), sTargetFunc,
						    (void*)pTargetFunc, (void*)m_pSourceFunc);
		}

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

static bool InstallRenderdocIATHook()
{
	// 保证 Renderdoc 始终调用真正的 d3d11 API
	pGetProcAddressHook = new PLH::IATHook;
	pGetProcAddressHook->SetupHook("kernel32.dll", "GetProcAddress",
								   (uint8_t*)&Hooked_GetProcAddress, "renderdoc.dll");
	if (pGetProcAddressHook->Hook())
	{
		g_Logger->error("Hook renderdoc.dll GetProcAddress failed");
		return false;
	}

	typedef void (__cdecl *tRENDERDOC_CreateHooks) (UINT Flags);

	tRENDERDOC_CreateHooks pfnCreateHooks = 
		(tRENDERDOC_CreateHooks) GetProcAddress(hRenderdoc, "RENDERDOC_CreateHooks");

	if (pfnCreateHooks == NULL)
	{
		g_Logger->error("GetProcAddress: RENDERDOC_CreateHooks failed, are you using official renderdoc ?");
		return false;
	}
	else
	{
		pfnCreateHooks(1);
	}

	return true;
}

std::map<ID3D11DeviceContext*, PLH::Detour*> ContextUsingDetours;
std::vector<PLH::Detour*> AllDrawIndexedDetours;
typedef void (STDMETHODCALLTYPE *tDrawIndexed) (ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);
typedef void (STDMETHODCALLTYPE *tOMSetDepthStencilState) (ID3D11DeviceContext* pContext, ID3D11DepthStencilState *pDepthStencilState, UINT StencilRef);
typedef void (STDMETHODCALLTYPE *tSetPredication) (ID3D11DeviceContext* pContext, ID3D11Predicate *pPredicate, BOOL PredicateValue);

static void HookD3D11DeviceContext(ID3D11DeviceContext* pContext);

static void STDMETHODCALLTYPE Hooked_DrawIndexed(ID3D11DeviceContext* pContext, 
		UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation)
{
	bool isOutlinePass = false;
	UINT stencilRef = 0;
	ID3D11DepthStencilState* pDepthStencilState = NULL;

	if (g_HookedProcessName.find(L"overwatch.exe") != std::wstring::npos)
	{
		pContext->OMGetDepthStencilState(&pDepthStencilState, &stencilRef);
		if (pDepthStencilState != NULL && stencilRef == 0x10)
		{
			D3D11_DEPTH_STENCIL_DESC Desc;
			pDepthStencilState->GetDesc(&Desc);
			if (Desc.DepthEnable == TRUE && Desc.DepthFunc == D3D11_COMPARISON_LESS_EQUAL &&
				Desc.StencilEnable == TRUE && Desc.StencilWriteMask == 0x10 &&
				Desc.StencilReadMask == 0x00 &&
				Desc.FrontFace.StencilFunc == D3D11_COMPARISON_ALWAYS &&
				Desc.BackFace.StencilFunc == D3D11_COMPARISON_ALWAYS)
			{
				isOutlinePass = true;

				Desc.DepthFunc = D3D11_COMPARISON_ALWAYS;

				ID3D11Device* pDevice;
				ID3D11DepthStencilState* pHackedDepthStencilState;
				pContext->GetDevice(&pDevice);
				pDevice->CreateDepthStencilState(&Desc, &pHackedDepthStencilState);

				pContext->OMSetDepthStencilState(pHackedDepthStencilState, stencilRef);

				pHackedDepthStencilState->Release();
				pDevice->Release();
			}
		}
	}
	
	auto itContext = ContextUsingDetours.find(pContext);
	if (itContext == ContextUsingDetours.end())
	{
		HookD3D11DeviceContext(pContext);
		itContext = ContextUsingDetours.find(pContext);
	}

	tDrawIndexed pfnOriginalDrawIndexed = itContext->second->GetOriginal<tDrawIndexed>();
	pfnOriginalDrawIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation);

	// restore depth stencil state.
	if (isOutlinePass)
		pContext->OMSetDepthStencilState(pDepthStencilState, stencilRef);

	if (pDepthStencilState != NULL)
		pDepthStencilState->Release();
}

static void HookD3D11DeviceContext(ID3D11DeviceContext* pContext)
{
	if (ContextUsingDetours.find(pContext) == ContextUsingDetours.end())
	{
		const int DrawIndexed_VTABLE_INDEX = 12;
		uint8_t** vtable = *((uint8_t***)pContext);
		uint8_t* pSourceFunc = vtable[DrawIndexed_VTABLE_INDEX];
		for (auto it = AllDrawIndexedDetours.begin(); it != AllDrawIndexedDetours.end(); ++it)
		{
			if ((*it)->GetSourcePtr<uint8_t*>() == pSourceFunc)
			{
				// already hooked for other instance.
				ContextUsingDetours[pContext] = *it;
				pContext->AddRef();
				return;
			}
		}

		PLH::Detour* DrawIndexedDetour = new PLH::Detour;
		DrawIndexedDetour->m_PreserveSize = 32;
		uint8_t codeBytes[] = {
#if 0
#else
			0x48, 0x8B, 0x5C, 0x24, 0x30,		// mov rbx,qword ptr [rsp+30h]
			0x48, 0x8B, 0x6C, 0x24, 0x38,		// mov rbp,qword ptr [rsp+38h]  
			0x48, 0x8B, 0x74, 0x24, 0x40,		// mov rsi,qword ptr [rsp+40h]
			0x48, 0x8B, 0x7C, 0x24, 0x48,		// mov rdi,qword ptr [rsp+48h]
			0x48, 0x83, 0xC4, 0x20,				// add rsp, 20h
			0x41, 0x5E,							// pop r14
#endif
		};

		DrawIndexedDetour->m_RestoreCode = new uint8_t[sizeof(codeBytes)];
		memcpy(DrawIndexedDetour->m_RestoreCode, codeBytes, sizeof(codeBytes));
		DrawIndexedDetour->m_RestoreCodeSize = sizeof(codeBytes);

		DrawIndexedDetour->SetupHook(pSourceFunc, (uint8_t*) &Hooked_DrawIndexed);
		if (!DrawIndexedDetour->Hook())
		{
			g_Logger->warn("Detour virtual function {} at {:p} for object {:p} failed",
						   "ID3D11DeviceContext::DrawIndex", pSourceFunc, (void*) pContext);
		}
		else
		{
			g_Logger->debug("Detour virtual function {} at {:p} for object {:p} succeed",
						    "ID3D11DeviceContext::DrawIndex", pSourceFunc, (void*)pContext);
		}

		ContextUsingDetours[pContext] = DrawIndexedDetour;
		pContext->AddRef();

		AllDrawIndexedDetours.push_back(DrawIndexedDetour);
	}
}

static void HookD3D11Device(ID3D11Device** ppDevice)
{
	if (ppDevice == NULL || *ppDevice == NULL)
		return;

	ID3D11DeviceContext* pContext;
	(*ppDevice)->GetImmediateContext(&pContext);
	if (pContext == NULL)
	{
		g_Logger->warn("GetImmediateContext from device {} returns null", (void*) ppDevice);
		return;
	}

	HookD3D11DeviceContext(pContext);
	pContext->Release();
}

HRESULT WINAPI CreateDerivedD3D11DeviceAndSwapChain(
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
	g_Logger->info("{:*^50}", "D3D11CreateDeviceAndSwapChain");
	g_Logger->info("pAdater: {}", (void*) pAdapter);
	g_Logger->info("DriverType: {}", (UINT)DriverType);
	g_Logger->info("Software: {}", (void*) Software);
	g_Logger->info("Flags: {}", Flags);
	g_Logger->info("pFeatureLevels: {}", pFeatureLevels && FeatureLevels > 0 ? (UINT) pFeatureLevels[0] : 0);
	g_Logger->info("FeatureLevels: {}", FeatureLevels);
	g_Logger->info("SDKVersion: {}", SDKVersion);
	g_Logger->info("pSwapChainDesc: {}", (void*) pSwapChainDesc);
	if (pSwapChainDesc)
	{
		DXGI_MODE_DESC b = pSwapChainDesc->BufferDesc;
		g_Logger->info("\t\tWidth: {}, Height: {}, RefreshDenomiator: {}, RefreshNumerator: {}, "
					   "Format: {}, ScanlineOrdering: {}, Scaling: {}",
					   b.Width, b.Height, b.RefreshRate.Denominator, b.RefreshRate.Numerator,
					   (UINT) b.Format, (UINT) b.ScanlineOrdering, (UINT) b.Scaling);

		g_Logger->info("\t\tSampleQuality: {}, SampleCount: {}, BufferUsage: {}, BufferCount: {}, "
					   "OutputWindow: {}, Windowed: {}, SwapEffect: {}, Flags: {}",
					   pSwapChainDesc->SampleDesc.Quality, pSwapChainDesc->SampleDesc.Count,
					   (UINT) pSwapChainDesc->BufferUsage, pSwapChainDesc->BufferCount, 
					   (void*) pSwapChainDesc->OutputWindow, pSwapChainDesc->Windowed, 
					   (UINT) pSwapChainDesc->SwapEffect, pSwapChainDesc->Flags);
	}
	g_Logger->info("ppSwapChain: {}", (void*) ppSwapChain);
	g_Logger->info("ppDevice: {}", (void*) ppDevice);
	g_Logger->info("pFeatureLevel: {}", (void*) pFeatureLevel);
	g_Logger->info("ppImmediateContext: {}", (void*) ppImmediateContext);
	g_Logger->info("{:*^50}", "");

	PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN pfn = (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN) Hooked_GetProcAddress(hD3D11, "D3D11CreateDeviceAndSwapChain");
	D3D_FEATURE_LEVEL selected;
	HRESULT res = pfn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, pSwapChainDesc, 
					  ppSwapChain, ppDevice, &selected, ppImmediateContext);

	if (SUCCEEDED(res))
	{
		g_Logger->debug("D3D11CreateDeviceAndSwapChain succeed with feature level {}", selected);
	}
	else
	{
		g_Logger->warn("D3D11CreateDeviceAndSwapChain failed with retcode {}", res);
	}


	if (pFeatureLevel)
		*pFeatureLevel = selected;

	HookD3D11Device(ppDevice);
	return res;
}

HRESULT WINAPI CreateDerivedD3D11Device(
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
	return CreateDerivedD3D11DeviceAndSwapChain(pAdapter, DriverType, Software, Flags,
												pFeatureLevels, FeatureLevels, SDKVersion,
												NULL, NULL, ppDevice, pFeatureLevel, 
												ppImmediateContext);
}

std::wstring GetLoggerFilename()
{
	char filename[128];
	{
		time_t timer;
		time(&timer);

		struct tm tm_info;
		localtime_s(&tm_info, &timer);

		strftime(filename, 128, "RDL_log_%Y.%m.%d_%H.%M.%S.log", &tm_info);
	}

	WCHAR DocumentPath[MAX_PATH];
	SHGetFolderPath(NULL, CSIDL_MYDOCUMENTS, NULL, SHGFP_TYPE_CURRENT, DocumentPath);

	return std::wstring(DocumentPath) + s2w(std::string(filename));
}


bool InitD3D11AndRenderdoc(HMODULE currentModule)
{
	g_Logger = spdlog::basic_logger_mt("logger", GetLoggerFilename());
	spdlog::set_level(spdlog::level::debug);

	hCurrentModule = currentModule;

	{
		WCHAR curFile[MAX_PATH];
		GetModuleFileName(NULL, curFile, MAX_PATH);
		std::wstring f(curFile);
		g_Logger->info("Hooked into process {}", w2s(f));

		transform(f.begin(), f.end(), f.begin(), towlower);
		g_HookedProcessName = f;
	}
	
	WCHAR fullPath[MAX_PATH];
	UINT ret = GetSystemDirectoryW(fullPath, MAX_PATH);
	if (ret != 0 && ret < MAX_PATH)
	{
		wcscat_s(fullPath, MAX_PATH, L"\\d3d11.dll");
		hD3D11 = LoadLibraryEx(fullPath, NULL, 0);
	}

	hDXGI = LoadLibrary(L"dxgi.dll");
	if (hD3D11 == NULL || hDXGI == NULL)
	{
		g_Logger->error("load librarys {} and dxgi.dll failed.\n", w2s(fullPath));
		return false;
	}

	if (g_RenderdocMode)
	{
		hRenderdoc = LoadLibrary(L"renderdoc.dll");
		if (hRenderdoc == NULL)
		{
			g_Logger->error("load renderdoc.dll failed.\n");
			return false;
		}
	}

	// 	sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDeviceAndSwapChain", hCurrentModule, "RENDERDOC_CreateWrappedD3D11DeviceAndSwapChain"));
	// 	sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDevice", hCurrentModule, "RENDERDOC_CreateWrappedD3D11Device"));

	if (hRenderdoc != NULL)
	{
		sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDeviceAndSwapChain", hRenderdoc, "RENDERDOC_CreateWrappedD3D11DeviceAndSwapChain"));
		sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDevice", hRenderdoc, "RENDERDOC_CreateWrappedD3D11Device"));
		sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDeviceAndSwapChain", hRenderdoc, "RENDERDOC_CreateWrappedD3D11DeviceAndSwapChain"));
		sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDevice", hRenderdoc, "RENDERDOC_CreateWrappedD3D11Device"));
		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory"));
		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory1", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory1"));
		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory2", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory2"));
	}
	else
	{
		sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDeviceAndSwapChain", (FARPROC)&CreateDerivedD3D11DeviceAndSwapChain));
		sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDevice", (FARPROC)&CreateDerivedD3D11Device));
		sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDeviceAndSwapChain", (FARPROC)&CreateDerivedD3D11DeviceAndSwapChain));
		sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDevice", (FARPROC)&CreateDerivedD3D11Device));
	}

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

	if (g_RenderdocMode)
	{
		InstallRenderdocIATHook();
		return false;
	}

	return true;
}
