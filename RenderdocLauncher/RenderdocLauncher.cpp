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
#include <set>

#include "PolyHook/PolyHookTools.hpp"
#include <Psapi.h>
#include "NTPClient.h"
#include "AutoAimPerformer.h"

static bool g_RenderdocMode = true;
extern bool g_DebugMode = false;

extern std::wstring g_HookedProcessName = L"";
extern HMODULE hD3D11 = 0;
extern HMODULE hCurrentModule = 0;
extern HMODULE hRenderdoc = 0;
extern HMODULE hDXGI = 0;
extern WORD g_ShootKey = VK_MBUTTON;

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

static VTableHook* g_DrawIndexedHook;
static VTableHook* g_DrawHook;

typedef void (STDMETHODCALLTYPE *tDrawIndexed) (ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);
typedef void (STDMETHODCALLTYPE *tDraw) (ID3D11DeviceContext* pContext, UINT VertexCount, UINT StartVertexLocation);
typedef void (STDMETHODCALLTYPE *tOMSetDepthStencilState) (ID3D11DeviceContext* pContext, ID3D11DepthStencilState *pDepthStencilState, UINT StencilRef);
typedef void (STDMETHODCALLTYPE *tSetPredication) (ID3D11DeviceContext* pContext, ID3D11Predicate *pPredicate, BOOL PredicateValue);

static void HookD3D11DeviceContext(ID3D11DeviceContext* pContext);

static void STDMETHODCALLTYPE Hooked_DrawIndexed(ID3D11DeviceContext* pContext,
												 UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);

static void LogInstructions(uint8_t* pAddr, csh handle)
{
	cs_insn* pInstructions;
	size_t count = cs_disasm(handle, pAddr, 0x100, (uint64_t)pAddr, 0, &pInstructions);

	g_Logger->info("Log chunk instructions:");
	for (size_t i = 0; i < count; ++i)
	{
		LogInstructionDetail(spdlog::level::info, &pInstructions[i]);
	}
}

static AutoAimAnalyzer* g_AutoAimAnalyzer;
static AutoAimPerformer* g_AutoAimPerformer;
struct KeyState 
{
	enum {
		KEY_UP, KEY_DOWN, KEY_PRESSING
	};
	KeyState(int vKey) : vKey(vKey), keyState(KEY_UP) {}

	int update()
	{
		bool KeyDown = GetAsyncKeyState(vKey) != 0;
		if (KeyDown && keyState == 0)
			keyState = KEY_DOWN; // down
		else if (KeyDown && keyState == 1)
			keyState = KEY_PRESSING; // pressing
		else if (!KeyDown && keyState > 0)
			keyState = KEY_UP; // up

		return keyState;
	}

private:
	int vKey;
	int keyState; // up
};

struct SD3D11DeviceAddOn
{
	ID3D11Device* pDevice;
	ID3D11DeviceContext* pContext;
	ID3D11VertexShader* pVSDrawTarget;
	ID3D11PixelShader* pPSDrawTarget;
	ID3D11Buffer* pCB;
	ID3D11RasterizerState* pRS;
	std::map<IDXGISwapChain*, ID3D11RenderTargetView*> pSwapChains;
	int CBSize;

	SD3D11DeviceAddOn(ID3D11Device* pDevice) : pDevice(pDevice)
	{
		pDevice->CreateVertexShader(g_VSDrawTarget, sizeof(g_VSDrawTarget), NULL, &pVSDrawTarget);
		pDevice->CreatePixelShader(g_PSDrawTarget, sizeof(g_PSDrawTarget), NULL, &pPSDrawTarget);

		CBSize = 2048;
		D3D11_BUFFER_DESC CBDesc;
		CBDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
		CBDesc.ByteWidth = CBSize;
		CBDesc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
		CBDesc.MiscFlags = 0;
		CBDesc.StructureByteStride = 0;
		CBDesc.Usage = D3D11_USAGE_DYNAMIC;
		pDevice->CreateBuffer(&CBDesc, NULL, &pCB);


		D3D11_RASTERIZER_DESC RSDesc;
		RSDesc.FillMode = D3D11_FILL_SOLID;
		RSDesc.CullMode = D3D11_CULL_NONE;
		RSDesc.FrontCounterClockwise = FALSE;
		RSDesc.DepthBias = 0;
		RSDesc.DepthBiasClamp = 0;
		RSDesc.SlopeScaledDepthBias = 0;
		RSDesc.DepthClipEnable = TRUE;
		RSDesc.ScissorEnable = FALSE;
		RSDesc.MultisampleEnable = FALSE;
		RSDesc.AntialiasedLineEnable = FALSE;
		pDevice->CreateRasterizerState(&RSDesc, &pRS);
		pDevice->GetImmediateContext(&pContext);
	}

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

	void OnRenderEnd(ID3D11RenderTargetView* pRTV, HWND OutputWnd)
	{
		static bool dotShootMode = true;
		static KeyState _0KeyState('0');
		static KeyState _9KeyState('9');
		if (_0KeyState.update() == KeyState::KEY_DOWN)
		{
			dotShootMode = true;
			printf("MCCREE mode\n");
		}

		if (_9KeyState.update() == KeyState::KEY_DOWN)
		{
			dotShootMode = false;
			printf("Soldier_76 mode\n");
		}

		rdcboost::SDeviceContextState contextState;
		contextState.GetFromContext(pContext, NULL);

		const std::vector<AutoAimAnalyzer::SAimResult>* pResult = NULL;
		if (g_AutoAimAnalyzer != NULL)
		{
			const float minRatio = 0.7f, maxRatio = 0.9f;

			g_AutoAimAnalyzer->SetShootPosRatio(0.7f);
			g_AutoAimAnalyzer->OnFrameEnd();
			pResult = &g_AutoAimAnalyzer->GetResult();
		}

		UINT BackBufferWidth, BackBufferHeight;
		{
			ID3D11Resource* pBackBuffer = NULL;
			pRTV->GetResource(&pBackBuffer);
			D3D11_TEXTURE2D_DESC BackBufferDesc;
			static_cast<ID3D11Texture2D*>(pBackBuffer)->GetDesc(&BackBufferDesc);
			SAFE_RELEASE(pBackBuffer);

			BackBufferWidth = BackBufferDesc.Width;
			BackBufferHeight = BackBufferDesc.Height;
		}

// 		static KeyState middleKeyState(VK_MBUTTON);
// 		if (middleKeyState.update() == KeyState::KEY_DOWN)
// 		{
// 			INPUT mouseMove;
// 			mouseMove.type = INPUT_MOUSE;
// 			mouseMove.mi.dx = 2250;// (LONG)((x - 0.5f) * (wndRect.right - wndRect.left));// targetPt.x - mousePt.x;
// 			mouseMove.mi.dy = 0;
// 			mouseMove.mi.mouseData = 0;
// 			mouseMove.mi.dwFlags = MOUSEEVENTF_MOVE;
// 			mouseMove.mi.time = 0;
// 			mouseMove.mi.dwExtraInfo = NULL;
// 			SendInput(1, &mouseMove, sizeof(INPUT));
// 		}

		static KeyState fKeyState('F');
		static int aimbotState = 0;
		if (fKeyState.update() == KeyState::KEY_DOWN)
		{
			aimbotState = (aimbotState + 1) % 2;
			printf("AIMBOT: %s\n", aimbotState ? "ON" : "OFF");
		}

		bool enableAimbot = false;
		if (dotShootMode)
		{
			if (aimbotState != 0)
			{
				const int INVALID_AIM_FRAMES = -1000;
				static KeyState leftKeyState(VK_LBUTTON);
				static int aimFrames = INVALID_AIM_FRAMES;
				int lbuttonState = leftKeyState.update();
				if (lbuttonState == KeyState::KEY_DOWN)
				{
					if (aimFrames == INVALID_AIM_FRAMES)
						aimFrames = 6;
				}

				if (aimFrames > 0)
				{
					enableAimbot = true;
					--aimFrames;
				}
				else if (aimFrames == 0)
				{
					INPUT shootDown;
					shootDown.type = INPUT_MOUSE;
					memset(&shootDown.mi, 0, sizeof(shootDown.mi));
					shootDown.mi.dwFlags = MOUSEEVENTF_MIDDLEDOWN;
					SendInput(1, &shootDown, sizeof(INPUT));
					--aimFrames;
				}

				if (lbuttonState == KeyState::KEY_UP && aimFrames == -1)
				{
					INPUT shootDown;
					shootDown.type = INPUT_MOUSE;
					memset(&shootDown.mi, 0, sizeof(shootDown.mi));
					shootDown.mi.dwFlags = MOUSEEVENTF_MIDDLEUP;
					SendInput(1, &shootDown, sizeof(INPUT));
					aimFrames = INVALID_AIM_FRAMES;
				}
			}
		}
		else
		{
			static int lButtonFrames = 0;
			if (aimbotState == 0)
			{
				lButtonFrames = 0;
			}
			else
			{
				if (GetAsyncKeyState(VK_LBUTTON) != 0)
					lButtonFrames = 30;
				else
					--lButtonFrames;

				enableAimbot = lButtonFrames > 0;
			}
		}
		
		if (pResult && !pResult->empty() && aimbotState != 0)
		{
			if (g_AutoAimPerformer == NULL)
				g_AutoAimPerformer = new AutoAimPerformer;

			g_AutoAimPerformer->SetOutputWnd(OutputWnd);
			size_t selectedId = g_AutoAimPerformer->ProcessResults(enableAimbot, pResult);

			pContext->ClearState();

			enum { MAX_RESULT_SIZE = 64 };
			D3D11_MAPPED_SUBRESOURCE subres;
			HRESULT res = pContext->Map(pCB, 0, D3D11_MAP_WRITE_DISCARD, 0, &subres);
			if (SUCCEEDED(res))
			{
				memset(subres.pData, 0, CBSize);
				size_t idx = 0;
				for (auto it = pResult->begin(); it != pResult->end(); ++it, ++idx)
				{
					if (idx >= MAX_RESULT_SIZE)
					{
						g_Logger->error("Too many result found by AutoAim");
						break;
					}

					((float*)subres.pData)[idx * 4 + 0] = it->onScreenPos.x;
					((float*)subres.pData)[idx * 4 + 1] = it->onScreenPos.y;
				}

				((float*)subres.pData)[MAX_RESULT_SIZE * 4 + 0] = 5.0f; // triangle size
				((float*)subres.pData)[MAX_RESULT_SIZE * 4 + 1] = (float) BackBufferWidth; 
				((float*)subres.pData)[MAX_RESULT_SIZE * 4 + 2] = (float) BackBufferHeight;
				((uint32_t*)subres.pData)[MAX_RESULT_SIZE * 4 + 3] = (uint32_t)selectedId;

				pContext->Unmap(pCB, 0);
			}
			else
			{
				g_Logger->error("Map CB for write failed {} {}", res, (void*) pCB);
			}
			
			pContext->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
			pContext->VSSetConstantBuffers(0, 1, &pCB);
			pContext->PSSetConstantBuffers(0, 1, &pCB);
			pContext->VSSetShader(pVSDrawTarget, NULL, 0);

			D3D11_VIEWPORT viewport;
			viewport.TopLeftX = 0;
			viewport.TopLeftY = 0;
			viewport.Width = (FLOAT)BackBufferWidth;
			viewport.Height = (FLOAT)BackBufferHeight;
			viewport.MinDepth = 0;
			viewport.MaxDepth = 1;
			pContext->RSSetViewports(1, &viewport);
			pContext->RSSetState(pRS);
			pContext->PSSetShader(pPSDrawTarget, NULL, 0);
			pContext->OMSetRenderTargets(1, &pRTV, NULL);

			if (!dotShootMode)
				pContext->Draw((UINT)pResult->size() * 3, 0);

		}
		contextState.SetToContext(pContext);
	}

	void OnRenderEnd(IDXGISwapChain* pSwapChain) // invoke from IDXGISwapChain::Present
	{
		ID3D11RenderTargetView* pRTV = GetRTVForBackbuffer(pSwapChain);
		if (pRTV == NULL)
		{
			g_Logger->critical("GetRTVForBackbuffer failed {}", (void*) pSwapChain);
			return;
		}

		DXGI_SWAP_CHAIN_DESC SwapChainDesc;
		pSwapChain->GetDesc(&SwapChainDesc);

		OnRenderEnd(pRTV, SwapChainDesc.OutputWindow);
	}
};

std::map<ID3D11Device*, SD3D11DeviceAddOn*> g_D3D11AddonDatas;
static void STDMETHODCALLTYPE Hooked_Draw(ID3D11DeviceContext* pContext,
										  UINT VertexCount, UINT StartVertexLocation)
{
	if (g_DebugMode || g_HookedProcessName.find(L"overwatch.exe") != std::wstring::npos)
	{
		if (VertexCount == 144)
		{
			UINT stencilRef;
			ID3D11DepthStencilState* pDepthStencilState;
			pContext->OMGetDepthStencilState(&pDepthStencilState, &stencilRef);

			if (pDepthStencilState != NULL)
			{
				D3D11_DEPTH_STENCIL_DESC dsDesc;
				pDepthStencilState->GetDesc(&dsDesc);
				D3D11_DEPTH_STENCIL_DESC targetDSDesc;
				targetDSDesc.DepthEnable = TRUE;
				targetDSDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
				targetDSDesc.DepthFunc = D3D11_COMPARISON_LESS;
				targetDSDesc.StencilEnable = TRUE;
				targetDSDesc.StencilWriteMask = 1;
				targetDSDesc.StencilReadMask = 1;
				targetDSDesc.FrontFace.StencilFunc = D3D11_COMPARISON_LESS;
				targetDSDesc.FrontFace.StencilFailOp = D3D11_STENCIL_OP_ZERO;
				targetDSDesc.FrontFace.StencilDepthFailOp = D3D11_STENCIL_OP_ZERO;
				targetDSDesc.FrontFace.StencilPassOp = D3D11_STENCIL_OP_ZERO;
				targetDSDesc.BackFace.StencilFunc = D3D11_COMPARISON_LESS_EQUAL;
				targetDSDesc.BackFace.StencilFailOp = D3D11_STENCIL_OP_KEEP;
				targetDSDesc.BackFace.StencilDepthFailOp = D3D11_STENCIL_OP_INCR_SAT;
				targetDSDesc.BackFace.StencilPassOp = D3D11_STENCIL_OP_KEEP;
				if (memcmp(&dsDesc, &targetDSDesc, sizeof(D3D11_DEPTH_STENCIL_DESC)) == 0 && stencilRef == 0)
				{
					if (g_AutoAimAnalyzer == NULL)
						g_AutoAimAnalyzer = new AutoAimAnalyzer(pContext);

					g_AutoAimAnalyzer->OnDrawAllyArrow(VertexCount, StartVertexLocation);
				}
				SAFE_RELEASE(pDepthStencilState);
			}
		}
	}
	
	tDraw pfnOriginal = (tDraw)g_DrawHook->BeginInvokeOriginal(pContext);
	if (pfnOriginal != NULL)
	{
		pfnOriginal(pContext, VertexCount, StartVertexLocation);
		g_DrawHook->EndInvokeOriginal(pfnOriginal);
	}
	else
	{
		g_Logger->critical("no original Draw functions {} {}", (void*)pContext,
						   (void*)g_DrawHook->GetVTableFuncPtr(pContext));
	}

}

static void STDMETHODCALLTYPE Hooked_DrawIndexed(ID3D11DeviceContext* pContext, 
		UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation)
{
	static int i = 0;
// 	printf("Hooked_DrawIndexed(%06d %03d)\n", i++, GetCurrentThreadId());
	bool changedDS = false;
	UINT stencilRef = 0;
	ID3D11DepthStencilState* pDepthStencilState = NULL;

// 	void** pStack = (void**) &pContext;
// 	void* pRetAddr = pStack[-1];
// 	if (DrawIndexedRetAddr.find(pRetAddr) == DrawIndexedRetAddr.end())
// 	{
// 		g_Logger->debug("DrawIndexed Callstack RetAddr: {}", pRetAddr);
// 		DrawIndexedRetAddr.insert(pRetAddr);
// 
// // 		DetourDrawIndexedRetAddr(&pStack[-1]);
// 	}

	if (g_DebugMode || g_HookedProcessName.find(L"overwatch.exe") != std::wstring::npos)
	{
// 		static bool b = false;
// 		if (b == false)
// 		{
// 			uint8_t* pJmpDrawIndexedAddr = (uint8_t*)pRetAddr + (0x7ff722e3b1d7 - 0x7ff722e22898 - 5);
// 			if (DrawIndexedTailJmps.find(pJmpDrawIndexedAddr) == DrawIndexedTailJmps.end())
// 				DetourCaller(NULL, pJmpDrawIndexedAddr, 4, true);
// 			b = true;
// 		}
		
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
				if (g_AutoAimAnalyzer == NULL)
					g_AutoAimAnalyzer = new AutoAimAnalyzer(pContext);

				if (g_AutoAimAnalyzer != NULL)
					g_AutoAimAnalyzer->OnDrawEnemyPart(IndexCount, StartIndexLocation, BaseVertexLocation);

				Desc.DepthFunc = D3D11_COMPARISON_ALWAYS;

				ID3D11Device* pDevice;
				ID3D11DepthStencilState* pHackedDepthStencilState = NULL;
				pContext->GetDevice(&pDevice);
				if (pDevice == NULL)
				{
					g_Logger->critical("No device retrived from context {}", (void*) pContext);
				}
				else
				{
					pDevice->CreateDepthStencilState(&Desc, &pHackedDepthStencilState);
					pContext->OMSetDepthStencilState(pHackedDepthStencilState, stencilRef);
					changedDS = true;
				}
				
				SAFE_RELEASE(pHackedDepthStencilState);
				SAFE_RELEASE(pDevice);
			}
		}
	}
	
	tDrawIndexed pfnOriginal = (tDrawIndexed) g_DrawIndexedHook->BeginInvokeOriginal(pContext);
	if (pfnOriginal != NULL)
	{
		pfnOriginal(pContext, IndexCount, StartIndexLocation, BaseVertexLocation);
		g_DrawIndexedHook->EndInvokeOriginal(pfnOriginal);
	}
	else
	{
		g_Logger->critical("no original DrawIndexed functions {} {} ImmediateCtx: {}", 
						   (void*) pContext, (void*) g_DrawIndexedHook->GetVTableFuncPtr(pContext), 
						   pContext->GetType());

	}

	// restore depth stencil state.
	if (changedDS)
	{
		pContext->OMSetDepthStencilState(pDepthStencilState, stencilRef);
	}

	SAFE_RELEASE(pDepthStencilState);
}

static void HookD3D11DeviceContext(ID3D11DeviceContext* pContext)
{
	if (g_DrawIndexedHook == NULL)
	{
		const int DrawIndexed_VTABLE_INDEX = 12;
		g_DrawIndexedHook = new VTableHook(DrawIndexed_VTABLE_INDEX, &Hooked_DrawIndexed,
										   "ID3D11DeviceContext::DrawIndexed(UINT, UINT, UINT)", 32);
	}

	g_DrawIndexedHook->HookObject(pContext);

	if (g_DrawHook == NULL)
	{
		const int Draw_VTABLE_INDEX = 13;
		g_DrawHook = new VTableHook(Draw_VTABLE_INDEX, &Hooked_Draw,
									"ID3D11DeviceContext::Draw(UINT, UINT)", 32);
	}

	g_DrawHook->HookObject(pContext);
}

static void HookD3D11Device(ID3D11Device** ppDevice)
{
	if (ppDevice == NULL || *ppDevice == NULL)
		return;

	if (g_D3D11AddonDatas.find(*ppDevice) != g_D3D11AddonDatas.end())
		return;

	g_D3D11AddonDatas[*ppDevice] = new SD3D11DeviceAddOn(*ppDevice);
	(*ppDevice)->AddRef();

	ID3D11DeviceContext* pContext;
	(*ppDevice)->GetImmediateContext(&pContext);
	if (pContext == NULL)
	{
		g_Logger->warn("GetImmediateContext from device {} returns null", (void*)ppDevice);
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
// 	GetTimeFromNTPServer();

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

typedef HRESULT(WINAPI *tCreateDXGIFactory)(REFIID, void**);
typedef HRESULT(WINAPI *tCreateDXGIFactory1)(REFIID, void**);
typedef HRESULT(WINAPI *tCreateDXGIFactory2)(UINT, REFIID, void**);
static VTableHook* g_DXGIFactory_CreateSwapChainHook;
static VTableHook* g_SwapChain_PresentHook;

typedef HRESULT(STDMETHODCALLTYPE *tPresent)(
	IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags);

static HRESULT STDMETHODCALLTYPE Hooked_Present(
	IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
{
	// 	g_Logger->debug("hooked_present");
	ID3D11Device* pD3DDevice;
	pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pD3DDevice);
	if (pD3DDevice != NULL)
	{
		auto it = g_D3D11AddonDatas.find(pD3DDevice);
		if (it == g_D3D11AddonDatas.end())
		{
			g_Logger->error("no addon data created for d3d device {}", (void*)pD3DDevice);
		}
		else
		{
			it->second->OnRenderEnd(pSwapChain);
		}
		SAFE_RELEASE(pD3DDevice);
	}
	else
	{
		g_Logger->error("GetDevice from swapchain failed {}", (void*)pSwapChain);
	}

	tPresent pfn = (tPresent)g_SwapChain_PresentHook->BeginInvokeOriginal(pSwapChain);
	if (pfn != NULL)
	{
		HRESULT res = pfn(pSwapChain, SyncInterval, Flags);
		g_SwapChain_PresentHook->EndInvokeOriginal(pfn);
		return res;
	}
	else
	{
		g_Logger->critical("no original Present function found {} {}", (void*) pSwapChain,
						   (void*) g_SwapChain_PresentHook->GetVTableFuncPtr(pSwapChain));
		return S_OK;
	}
}

static void HookSwapChain(IDXGISwapChain* pSwapChain)
{
	if (g_SwapChain_PresentHook == NULL)
	{
		const int PRESENT_VTABLE_INDEX = 8;
		g_SwapChain_PresentHook = new VTableHook(PRESENT_VTABLE_INDEX, &Hooked_Present, 
												 "IDXGISwapChain::Present(UINT, UINT)", 32);
	}

	g_SwapChain_PresentHook->HookObject(pSwapChain);
}

typedef HRESULT(STDMETHODCALLTYPE *tCreateSwapChain)(
	IDXGIFactory* pFactory, IUnknown *pDevice,
	DXGI_SWAP_CHAIN_DESC *pDesc, IDXGISwapChain **ppSwapChain);

static HRESULT STDMETHODCALLTYPE Hooked_CreateSwapChain(
	IDXGIFactory* pFactory, IUnknown *pDevice, 
	DXGI_SWAP_CHAIN_DESC *pDesc, IDXGISwapChain **ppSwapChain)
{
	g_Logger->debug("IDXGIFactory::CreateSwapChain");
	tCreateSwapChain pfn = (tCreateSwapChain)g_DXGIFactory_CreateSwapChainHook->BeginInvokeOriginal(pFactory);

	HRESULT res;
	if (pfn != NULL)
	{
		res = pfn(pFactory, pDevice, pDesc, ppSwapChain);
		g_DXGIFactory_CreateSwapChainHook->EndInvokeOriginal(pfn);
	}
	else
	{
		res = E_INVALIDARG;
		g_Logger->critical("no original CreateSwapChain function {} {}", (void*)pFactory,
						   (void*)g_DXGIFactory_CreateSwapChainHook->GetVTableFuncPtr(pFactory));
	}

	if (pDevice != NULL && ppSwapChain != NULL && *ppSwapChain != NULL)
	{
		ID3D11Device* pD3D11Device = NULL;
		pDevice->QueryInterface(__uuidof(ID3D11Device), (void**)&pD3D11Device);
		if (pD3D11Device == NULL)
		{
			g_Logger->error("QueryInterface ID3D11Device returns null");
		}
		else
		{
			HookD3D11Device(&pD3D11Device);
			g_D3D11AddonDatas[pD3D11Device]->AddSwapChain(*ppSwapChain);
			SAFE_RELEASE(pD3D11Device);

			HookSwapChain(*ppSwapChain);
		}
	}

	return res;
}

static void HookDXGIFactory(void** ppFactory)
{
	if (ppFactory && *ppFactory)
	{
		g_Logger->debug("Hooked_CreateDXGIFactory");
		if (g_DXGIFactory_CreateSwapChainHook == NULL)
		{
			const int CreateSwapChain_VTABLE_INDEX = 10;
			g_DXGIFactory_CreateSwapChainHook = 
				new VTableHook(CreateSwapChain_VTABLE_INDEX, &Hooked_CreateSwapChain, 
							   "IDXGIFactory::CreateSwapChain(REFIID, void**)", 32);
		}

		g_DXGIFactory_CreateSwapChainHook->HookObject(*ppFactory);
	}
}

HRESULT WINAPI Hooked_CreateDXGIFactory(REFIID riid, _Out_ void **ppFactory)
{
	tCreateDXGIFactory pfn = (tCreateDXGIFactory)Hooked_GetProcAddress(hDXGI, "CreateDXGIFactory");
	HRESULT res = pfn(riid, ppFactory);
	HookDXGIFactory(ppFactory);
	return res;
}


HRESULT WINAPI Hooked_CreateDXGIFactory1(REFIID riid, _Out_ void **ppFactory)
{
	tCreateDXGIFactory1 pfn = (tCreateDXGIFactory1)Hooked_GetProcAddress(hDXGI, "CreateDXGIFactory1");
	HRESULT res = pfn(riid, ppFactory);
	HookDXGIFactory(ppFactory);
	return res;
}

HRESULT WINAPI Hooked_CreateDXGIFactory2(UINT Flags, REFIID riid, _Out_ void **ppFactory)
{
	tCreateDXGIFactory2 pfn = (tCreateDXGIFactory2)Hooked_GetProcAddress(hDXGI, "CreateDXGIFactory2");
	HRESULT res = pfn(Flags, riid, ppFactory);
	HookDXGIFactory(ppFactory);
	return res;
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

// typedef DWORD(WINAPI *tGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
// typedef DWORD(WINAPI *tGetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
// 
// DWORD WINAPI Hooked_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
// {
// 	if (hCurrentModule == hModule)
// 	{
// 		hModule = hD3D11;
// 		g_Logger->info("GetModuleFileNameW with current module");
// 	}
// 
// 	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
// 	return ((tGetModuleFileNameW) Hooked_GetProcAddress(hKernel32, "GetModuleFileNameW"))(hModule, lpFilename, nSize);
// }
// 
// DWORD WINAPI Hooked_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
// {
// 	if (hCurrentModule == hModule)
// 	{
// 		hModule = hD3D11;
// 		g_Logger->info("GetModuleFileNameA with current module");
// 	}
// 
// 	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
// 	return ((tGetModuleFileNameA)Hooked_GetProcAddress(hKernel32, "GetModuleFileNameA"))(hModule, lpFilename, nSize);
// }
// 

static BOOL WINAPI Hooked_VirtualProtect(
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD  flNewProtect,
	_Out_ PDWORD lpflOldProtect
	)
{

}


static BOOL WINAPI Hooked_VirtualProtectEx(
	_In_  HANDLE hProcess,
	_In_  LPVOID lpAddress,
	_In_  SIZE_T dwSize,
	_In_  DWORD  flNewProtect,
	_Out_ PDWORD lpflOldProtect
	)
{

}


EXTERN_C IMAGE_DOS_HEADER __ImageBase;
bool InitD3D11AndRenderdoc(HMODULE currentModule)
{
	AllocConsole();
	freopen("CONOUT$", "wt", stdout);
	freopen("CONIN$", "rt", stdin);

	initGlobalLog();

	// 	csh handle;
	// 	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	// 	LogInstructions(*(uint8_t**)(0x7ffd079d2ef8 + 0xccfb8), handle);
	// 	LogInstructions(*(uint8_t**)(0x7ffd079d4e05 + 0xcb0ab), handle);
	// 	cs_close(&handle);

	{
		HMODULE hMods[1024];
		DWORD cbNeeded;
		HANDLE hProcess = GetCurrentProcess();
		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			for (uint32_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				TCHAR szModName[MAX_PATH];

				// Get the full path to the module's file.
				if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
					sizeof(szModName) / sizeof(TCHAR)))
				{
					// Print the module name and handle value.
					g_Logger->info("Loaded Module: {}", w2s(szModName));
				}
			}
		}
	}

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

		{
			HMODULE hD3D11 = GetModuleHandle(fullPath);
			if (hD3D11 != NULL)
			{
				g_Logger->critical("{} has already been loaded into process", w2s(fullPath));
			}
		}

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
		g_Logger->info("start loading renderdoc.dll");
		hRenderdoc = LoadLibrary(L"renderdoc.dll");
		if (hRenderdoc == NULL)
		{
			g_Logger->error("not found renderdoc.dll, try searching renderdoc.dll in DllPath.");
			WCHAR DllPath[MAX_PATH] = { 0 };
			GetModuleFileNameW((HINSTANCE)&__ImageBase, DllPath, _countof(DllPath));
			std::wstring currDllPath(DllPath);

			std::wstring renderdocDllPath = 
				currDllPath.substr(0, currDllPath.find_last_of(L"/\\") + 1) + L"renderdoc.dll";

			hRenderdoc = LoadLibrary(renderdocDllPath.c_str());

			if (hRenderdoc == NULL)
			{
				g_Logger->error("load renderdoc.dll failed.\n");
				return false;
			}
		}
	}

// 	HMODULE hKernel32 = LoadLibrary(L"kernel32.dll");
// 	sDetourHooks.push_back(DetourHookInfo(hKernel32, "GetModuleFileNameW", (FARPROC)&Hooked_GetModuleFileNameW));
// 	sDetourHooks.push_back(DetourHookInfo(hKernel32, "GetModuleFileNameA", (FARPROC)&Hooked_GetModuleFileNameA));


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
		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory", (FARPROC)&Hooked_CreateDXGIFactory));
		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory1", (FARPROC)&Hooked_CreateDXGIFactory1));
		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory2", (FARPROC)&Hooked_CreateDXGIFactory2));
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
