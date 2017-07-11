#include "RenderdocLauncher.h"
#include "CommonUtils.h"

#include <cstdio>
#include <d3d11.h>

#include <vector>
#include <string>
#include <stdint.h>
#include <map>
#include <ShlObj.h>
#include "DeviceContextState.h"

#include "AsmCommon.h"
#include "HookUtil.h"
#include "AutoAimAnalyzer.h"
#include "shader_obj/DrawTargetVS.h"
#include "shader_obj/DrawTargetPS.h"

static bool g_RenderdocMode = false;
extern bool g_DebugMode = false;

extern std::wstring g_HookedProcessName = L"";
extern HMODULE hD3D11 = 0;
extern HMODULE hCurrentModule = 0;
extern HMODULE hRenderdoc = 0;
extern HMODULE hDXGI = 0;

std::vector<DetourHookInfo> sDetourHooks;

// // 保证 Renderdoc 始终调用真正的 d3d11 API
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

static void* pIATHook;
static bool InstallRenderdocIATHook()
{
	// 保证 Renderdoc 始终调用真正的 d3d11 API
	pIATHook = CreateIATHook("kernel32.dll", "GetProcAddress", 
							 (uint8_t*)&Hooked_GetProcAddress, "renderdoc.dll");

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

// std::map<ID3D11DeviceContext*, PLH::Detour*> ContextUsingDetours;
static VTableHook* g_DrawIndexedHook;

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

	if (g_DebugMode || g_HookedProcessName.find(L"overwatch.exe") != std::wstring::npos)
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
	
	tDrawIndexed pfnOriginal = (tDrawIndexed) g_DrawIndexedHook->GetOriginalPtr(pContext);
	pfnOriginal(pContext, IndexCount, StartIndexLocation, BaseVertexLocation);

	// restore depth stencil state.
	if (isOutlinePass)
		pContext->OMSetDepthStencilState(pDepthStencilState, stencilRef);

	if (pDepthStencilState != NULL)
		pDepthStencilState->Release();
}

static void HookD3D11DeviceContext(ID3D11DeviceContext* pContext)
{
	if (g_DrawIndexedHook == NULL)
	{
		const int DrawIndexed_VTABLE_INDEX = 12;
		g_DrawIndexedHook = new VTableHook(DrawIndexed_VTABLE_INDEX, &Hooked_DrawIndexed,
										   "ID3D11DeviceContext::DrawIndexed(UINT, UINT, UINT)", 
										   0);
	}

	g_DrawIndexedHook->HookObject(pContext);
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

struct SD3D11DeviceAddOn
{
	ID3D11Device* pDevice;
	ID3D11DeviceContext* pContext;
	ID3D11VertexShader* pVSDrawTarget;
	ID3D11PixelShader* pPSDrawTarget;
	ID3D11Buffer* pCB;
	std::map<IDXGISwapChain*, ID3D11RenderTargetView*> pSwapChains;

	void AddSwapChain(IDXGISwapChain* pSwapChain) // invoke from IDXGIFactory::CreateSwapChain
	{
		pSwapChain->AddRef();
		pSwapChains[pSwapChain] = NULL;
	}
	
	ID3D11RenderTargetView* GetRTVForBackbuffer(IDXGISwapChain* pSwapChain)
	{
		ID3D11Texture2D* pBackBuffer;
		pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&pBackBuffer);
		if (pBackBuffer == NULL)
			return NULL;

		if (pSwapChains.find(pSwapChain) == pSwapChains.end())
		{
			SAFE_RELEASE(pBackBuffer);
			return NULL;
		}

		ID3D11RenderTargetView* pOldRTV = pSwapChains[pSwapChain];
		if (pOldRTV != NULL)
		{
			ID3D11Resource* pOldBackBuffer;
			pOldRTV->GetResource(&pOldBackBuffer);
			if (pOldBackBuffer != NULL && 
				pOldBackBuffer == static_cast<ID3D11Resource*>(pBackBuffer))
			{
				SAFE_RELEASE(pBackBuffer);
				SAFE_RELEASE(pOldBackBuffer);
				return pOldRTV;
			}

			SAFE_RELEASE(pOldBackBuffer);
		}

		SAFE_RELEASE(pOldRTV);

		D3D11_TEXTURE2D_DESC texDesc;
		pBackBuffer->GetDesc(&texDesc);

		D3D11_RENDER_TARGET_VIEW_DESC rtvDesc;
		rtvDesc.Format = texDesc.Format;
		rtvDesc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
		rtvDesc.Texture2D.MipSlice = 0;

		ID3D11RenderTargetView* pRTV;
		pDevice->CreateRenderTargetView(pBackBuffer, &rtvDesc, &pRTV);
		SAFE_RELEASE(pBackBuffer);

		pSwapChains[pSwapChain] = pRTV;
		return pRTV;
	}

	void OnRenderEnd(IDXGISwapChain* pSwapChain) // invoke from IDXGISwapChain::Present
	{
		rdcboost::SDeviceContextState contextState;
		contextState.GetFromContext(pContext, NULL);
// 		{
// 			ID3D11RenderTargetView* pRTV = GetRTVForBackbuffer(pSwapChain);
// 
// 			DXGI_SWAP_CHAIN_DESC swapchainDesc;
// 			pSwapChain->GetDesc(&swapchainDesc);
// 
// 			pContext->ClearState();
// 
// 			D3D11_MAPPED_SUBRESOURCE subres;
// 			pContext->Map(pCB, 0, D3D11_MAP_WRITE, 0, &subres);
// 			subres.pData->;
// 			pContext->Unmap(pCB, 0);
// 
// 			pContext->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
// 			pContext->VSSetConstantBuffers(0, 1, &pCB);
// 			pContext->VSSetShader(pVSDrawTarget, NULL, 0);
// 			D3D11_VIEWPORT viewport;
// 			viewport.TopLeftX = 0;
// 			viewport.TopLeftY = 0;
// 			viewport.Width = swapchainDesc.BufferDesc.Width;
// 			viewport.Height = swapchainDesc.BufferDesc.Height;
// 			viewport.MinDepth = 0;
// 			viewport.MaxDepth = 1;
// 			pContext->RSSetViewports(1, &viewport);
// 			pContext->PSSetShader(pPSDrawTarget, NULL, 0);
// 			pContext->OMSetRenderTargets(1, &pRTV, NULL);
// 			pContext->Draw(, 0);
// 		}
		contextState.SetToContext(pContext);
	}
};

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


// 	if (*ppDevice)
// 	{ // create resource
// 		ID3D11Device* pDevice = *ppDevice;
// 		SD3D11DeviceAddOn* pData;
// 
// 		pDevice->CreateVertexShader(g_VSDrawTarget, sizeof(g_VSDrawTarget), NULL, &pData->pVSDrawTarget);
// 		pDevice->CreatePixelShader(g_PSDrawTarget, sizeof(g_PSDrawTarget), NULL, &pData->pPSDrawTarget);
// 
// 		D3D11_BUFFER_DESC CBDesc;
// 		CBDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
// 		CBDesc.ByteWidth = 2048;
// 		CBDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
// 		CBDesc.MiscFlags = 0;
// 		CBDesc.StructureByteStride = 0;
// 		CBDesc.Usage = D3D11_USAGE_DYNAMIC;
// 		pDevice->CreateBuffer(&CBDesc, NULL, &pData->pCB);
// 
// 		pDevice->GetImmediateContext(&pData->pContext);
// 		
// 		pData->OnRenderEnd();
// 	}
	

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

typedef HRESULT (WINAPI *tCreateDXGIFactory)(REFIID, void**);
HRESULT WINAPI Hooked_CreateDXGIFactory(REFIID riid, _Out_ void **ppFactory)
{
	tCreateDXGIFactory pfn = (tCreateDXGIFactory)Hooked_GetProcAddress(hDXGI, "D3D11CreateDeviceAndSwapChain");
	HRESULT res = pfn(riid, ppFactory);
	if (ppFactory && *ppFactory)
	{

	}
}


HRESULT WINAPI Hooked_CreateDXGIFactory1(REFIID riid, _Out_ void **ppFactory)
{
}

HRESULT WINAPI Hooked_CreateDXGIFactory2(UINT Flags, REFIID riid, _Out_ void **ppFactory)
{

}


void initGlobalLog()
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

	std::wstring logDir = std::wstring(DocumentPath) + L"\\RenderdocLauncher\\";
	if (!CreateDirectory(logDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
		logDir = DocumentPath;

	g_Logger = spdlog::basic_logger_mt("logger", logDir + s2w(filename));
	spdlog::set_level(spdlog::level::debug);
	g_Logger->flush_on(spdlog::level::debug);
}

bool InitD3D11AndRenderdoc(HMODULE currentModule)
{
	initGlobalLog();

	g_JIT = new asmjit::JitRuntime;

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
// 		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory"));
// 		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory1", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory1"));
// 		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory2", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory2"));
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

	if (g_RenderdocMode && !InstallRenderdocIATHook())
	{
		return false;
	}

	return true;
}
