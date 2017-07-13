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

static VTableHook* g_DrawIndexedHook;
static VTableHook* g_DrawHook;

typedef void (STDMETHODCALLTYPE *tDrawIndexed) (ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);
typedef void (STDMETHODCALLTYPE *tDraw) (ID3D11DeviceContext* pContext, UINT VertexCount, UINT StartVertexLocation);
typedef void (STDMETHODCALLTYPE *tOMSetDepthStencilState) (ID3D11DeviceContext* pContext, ID3D11DepthStencilState *pDepthStencilState, UINT StencilRef);
typedef void (STDMETHODCALLTYPE *tSetPredication) (ID3D11DeviceContext* pContext, ID3D11Predicate *pPredicate, BOOL PredicateValue);

static void HookD3D11DeviceContext(ID3D11DeviceContext* pContext);

static void STDMETHODCALLTYPE Hooked_DrawIndexed(ID3D11DeviceContext* pContext,
												 UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);

static size_t FindPrevCall(uint8_t* pRetAddr, csh handle)
{
	for (size_t callInstSize = 1; callInstSize <= 16; ++callInstSize)
	{
		const uint8_t* pCode = (uint8_t*)pRetAddr - callInstSize;
		cs_insn* pInstructions;
		size_t count = cs_disasm(handle, pCode, callInstSize, (uint64_t)pCode, 0, &pInstructions);
		if (count == 1 && pInstructions[0].size == callInstSize &&
			strcmp(pInstructions[0].mnemonic, "call") == 0)
		{
			g_Logger->info("++ find call/jmp instruction before retAddr: ");
			LogInstructionDetail(spdlog::level::info, &pInstructions[0]);
			cs_free(pInstructions, count);
			return callInstSize;
		}
		cs_free(pInstructions, count);
	}

	return 0;	// not found.
}

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

std::set<void*> DrawIndexedRetAddr;
std::set<void*> DrawIndexedTailJmps;
static uint8_t* DetourCaller(csh* pHandle, uint8_t* pCaller, size_t callInstSize, bool tailJmp)
{
	csh handle;
	if (pHandle == NULL)
	{
		cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
		if (err != CS_ERR_OK)
		{
			g_Logger->error("Capstone initialize failed {}", err);
			return NULL;
		}
	}
	else
	{
		handle = *pHandle;
	}
	
	uint8_t* pTrampoline;
	do { // allocate trampoline
		size_t trampolineSize = 64;
		size_t delta;
		pTrampoline = (uint8_t*)PLH::Tools::AllocateWithin2GB(pCaller, trampolineSize, delta);
		if (pTrampoline == NULL)
		{
			g_Logger->error("Diff between pCaller({}) and Hooked_DrawIndexed({}) is too long, "
							"and attempt to allocate within 2GB failed",
							(void*)pCaller, (void*)&Hooked_DrawIndexed);

			return NULL;
		}

		DWORD oldProtection;
		VirtualProtect(pTrampoline, trampolineSize, PAGE_EXECUTE_READWRITE, &oldProtection);

		uint8_t detour[] = {
			0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
			0xFF, 0x15, 0xF2, 0xFF, 0xFF, 0xFF,			// call hooked function
			0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
			0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,			// jmp back to original function
			0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		};

		if (tailJmp)
			detour[9] = 0x25; // change 'call' to 'jmp'

		memcpy(pTrampoline, detour, sizeof(detour));
		*(uintptr_t*)&pTrampoline[0] = (uintptr_t)&Hooked_DrawIndexed;

		if (!tailJmp)
			DrawIndexedRetAddr.insert(pTrampoline + 14);
		else
			DrawIndexedTailJmps.insert(pCaller);
// 		VirtualProtect(pTrampoline, trampolineSize, oldProtection, &oldProtection);
	} while (0);


	do { // log call/jmp instruction
		cs_insn* pInstructions;
		size_t count = cs_disasm(handle, pCaller, callInstSize, (uint64_t)pCaller, 0, &pInstructions);
		g_Logger->info("++ detour call/jmp instruction: ");
		LogInstructionDetail(spdlog::level::info, &pInstructions[0]);
		cs_free(pInstructions, count);
	} while (0);


	uint8_t jmpCode[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	const size_t jmpCodeLen = sizeof(jmpCode);

	// patch relative address of jmp to trampoline
	*(int32_t*)&jmpCode[1] = (int32_t)((pTrampoline + 8) - (pCaller + jmpCodeLen));

	uint8_t* pRetAddr = pCaller + callInstSize;

	size_t relocSrcSize = 0;
	if (jmpCodeLen > callInstSize)
	{ // relocate rest affected code
		cs_insn* pInstructions;
		size_t count = cs_disasm(handle, (uint8_t*)pRetAddr,
									(jmpCodeLen - callInstSize) + 16,
									(uint64_t)pRetAddr, 0, &pInstructions);

		g_Logger->info(tailJmp ? "++ override instructions" : "++ relocating instructions:");
		for (size_t i = 0; i < count; ++i)
		{
			relocSrcSize += pInstructions[i].size;
			LogInstructionDetail(spdlog::level::info, &pInstructions[i]);
			if ((relocSrcSize + callInstSize) >= jmpCodeLen)
			{
				memcpy(pTrampoline + 14, pRetAddr, relocSrcSize);

				// TODO relocate these code
				break;
			}
		}

		cs_free(pInstructions, count);
	}

	size_t hookSrcLen = callInstSize + relocSrcSize;

	// patch trampoline return address
	*(uintptr_t*)&pTrampoline[36] = (uintptr_t)pRetAddr + relocSrcSize;

	do { // change original function call
		DWORD oldProtection;

		MEMORY_BASIC_INFORMATION bi;
		size_t queryRes = VirtualQuery(pCaller, &bi, sizeof(MEMORY_BASIC_INFORMATION));
		g_Logger->info("VQ: {} {} {} {} {} {} {} {}", queryRes, bi.BaseAddress, bi.AllocationBase, 
					   bi.AllocationProtect, bi.RegionSize, bi.State, bi.Protect, bi.Type);

		BOOL b = VirtualProtect(pCaller, hookSrcLen, PAGE_READONLY, &oldProtection);

		g_Logger->info("{} {} {} {} {}", hookSrcLen, jmpCodeLen, b, oldProtection, GetLastError());
		memcpy(pCaller, jmpCode, jmpCodeLen);
		g_Logger->info("1");

		// fill with nop
		for (size_t rest = jmpCodeLen; rest < hookSrcLen; ++rest)
			pCaller[rest] = 0x90;
		g_Logger->info("1");

		VirtualProtect(pCaller, callInstSize, oldProtection, &oldProtection);
	} while (0);

	{ // log modified instructions
		cs_insn* pInstructions;
		size_t count = cs_disasm(handle, pCaller, hookSrcLen, (uint64_t)pCaller, 0, &pInstructions);
		g_Logger->info("++ modified call instructions: ");
		for (size_t i = 0; i < count; ++i)
			LogInstructionDetail(spdlog::level::info, &pInstructions[i]);
		cs_free(pInstructions, count);
	}

	{ // log trampoline instructions
		cs_insn* pInstructions;
		size_t count = cs_disasm(handle, pTrampoline + 8, tailJmp ? 6 : 28, 
								 (uint64_t)pTrampoline + 8, 0, &pInstructions);
		g_Logger->info("++ generated trampoline instructions: ");
		for (size_t i = 0; i < count; ++i)
			LogInstructionDetail(spdlog::level::info, &pInstructions[i]);
		cs_free(pInstructions, count);
	}

	return pTrampoline;
}

static void DetourDrawIndexedRetAddr(void** ppRetAddr)
{
	void* pRetAddr = *ppRetAddr;

	csh handle;
	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	if (err != CS_ERR_OK)
	{
		g_Logger->error("Capstone initialize failed {}", err);
		return;
	}

	// find last call instruction
	size_t callInstSize = FindPrevCall((uint8_t*)pRetAddr, handle);
	if (callInstSize <= 0)
	{
		g_Logger->error("DrawIndexed: can't find call instruction before retAddr");
		return;
	}

	uint8_t* pPrevCall = (uint8_t*)pRetAddr - callInstSize;
	uint8_t* pTrampoline = DetourCaller(&handle, pPrevCall, callInstSize, false);

	if (pTrampoline)
		*ppRetAddr = pTrampoline + 14;
}

static AutoAimAnalyzer* g_AutoAimAnalyzer;

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

	void SetCursorPosF(HWND hwnd, float x, float y)
	{
		RECT wndRect;
		GetWindowRect(hwnd, &wndRect);

// 		POINT targetPt;
// 		targetPt.x = (LONG) ((wndRect.right - wndRect.left) * x);
// 		targetPt.y = (LONG) ((wndRect.bottom - wndRect.top) * y);
// 
// 		ClientToScreen(hwnd, &targetPt);
// 
// 		POINT mousePt;
// 		GetCursorPos(&mousePt);

		INPUT mouseMove;
		mouseMove.type = INPUT_MOUSE;
		mouseMove.mi.dx = (LONG) ((x - 0.5f) * (wndRect.right - wndRect.left));// targetPt.x - mousePt.x;
		mouseMove.mi.dy = (LONG)((y - 0.5f) * (wndRect.bottom - wndRect.top)); // targetPt.y - mousePt.y;
		mouseMove.mi.mouseData = 0;
		mouseMove.mi.dwFlags = MOUSEEVENTF_MOVE;
		mouseMove.mi.time = 0;
		mouseMove.mi.dwExtraInfo = NULL;
		SendInput(1, &mouseMove, sizeof(INPUT));
	}

	void OnRenderEnd(ID3D11RenderTargetView* pRTV, HWND OutputWnd)
	{
		rdcboost::SDeviceContextState contextState;
		contextState.GetFromContext(pContext, NULL);

		const std::vector<Vec2>* pResult = NULL;
		if (g_AutoAimAnalyzer != NULL)
		{
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

		if (pResult && !pResult->empty())
		{
			static float prevMinDist = FLT_MAX;
			float minDistToCenter = FLT_MAX;
			Vec2 targetPos;
			for (auto it = pResult->begin(); it != pResult->end(); ++it)
			{
				float dist = sqrt(pow(it->x - 0.5f, 2.0f) + pow(it->y - 0.5f, 2.0f));
				if (minDistToCenter > dist)
				{
					minDistToCenter = dist;
					targetPos = *it;
				}
			}

			if (minDistToCenter < 0.1f && minDistToCenter > 0.001f)
			{
				Vec2 vec;
				vec.x = targetPos.x - 0.5f;
				vec.y = targetPos.y - 0.5f;
				vec.x /= minDistToCenter;
				vec.y /= minDistToCenter;

				vec.x *= std::min(minDistToCenter * 0.4f, 0.01f);
				vec.y *= std::min(minDistToCenter * 0.4f, 0.01f);

				vec.x += 0.5f;
				vec.y += 0.5f;
				SetCursorPosF(OutputWnd, vec.x, vec.y);
			}

			pContext->ClearState();

			D3D11_MAPPED_SUBRESOURCE subres;
			HRESULT res = pContext->Map(pCB, 0, D3D11_MAP_WRITE_DISCARD, 0, &subres);
			if (SUCCEEDED(res))
			{
				memset(subres.pData, 0, CBSize);
				size_t idx = 0;
				for (auto it = pResult->begin(); it != pResult->end(); ++it, ++idx)
				{
					if (idx * 16 >= CBSize)
					{
						g_Logger->error("Too many result found by AutoAim");
						break;
					}

					((float*)subres.pData)[idx * 4 + 0] = it->x;
					((float*)subres.pData)[idx * 4 + 1] = it->y;
				}
				pContext->Unmap(pCB, 0);
			}
			else
			{
				g_Logger->error("Map CB for write failed {} {}", res, (void*) pCB);
			}
			
			pContext->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
			pContext->VSSetConstantBuffers(0, 1, &pCB);
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
	tDraw pfnOriginal = (tDraw)g_DrawHook->GetOriginalPtr(pContext);
	pfnOriginal(pContext, VertexCount, StartVertexLocation);
}

static void STDMETHODCALLTYPE Hooked_DrawIndexed(ID3D11DeviceContext* pContext, 
		UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation)
{
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
	
	tDrawIndexed pfnOriginal = (tDrawIndexed) g_DrawIndexedHook->GetOriginalPtr(pContext);
	if (pfnOriginal != NULL)
	{
		pfnOriginal(pContext, IndexCount, StartIndexLocation, BaseVertexLocation);
	}
	else
	{
		g_Logger->critical("no original DrawIndexed functions {} {}", (void*) pContext, 
						   (void*) g_DrawIndexedHook->GetVTableFuncPtr(pContext));

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
										   "ID3D11DeviceContext::DrawIndexed(UINT, UINT, UINT)",
										   32);
	}

	g_DrawIndexedHook->HookObject(pContext);

// 	if (g_DrawHook == NULL)
// 	{
// 		const int Draw_VTABLE_INDEX = 13;
// 		g_DrawHook = new VTableHook(Draw_VTABLE_INDEX, &Hooked_Draw,
// 									"ID3D11DeviceContext::Draw(UINT, UINT)", 32);
// 	}
// 
// 	g_DrawHook->HookObject(pContext);
}

static void HookD3D11Device(ID3D11Device** ppDevice)
{
	if (ppDevice == NULL || *ppDevice == NULL)
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

	tPresent pfn = (tPresent)g_SwapChain_PresentHook->GetOriginalPtr(pSwapChain);
	if (pfn != NULL)
	{
		return pfn(pSwapChain, SyncInterval, Flags);
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
	tCreateSwapChain pfn = (tCreateSwapChain)g_DXGIFactory_CreateSwapChainHook->GetOriginalPtr(pFactory);

	HRESULT res;
	if (pfn != NULL)
	{
		res = pfn(pFactory, pDevice, pDesc, ppSwapChain);
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
							   "IDXGIFactory::CreateDXGIFactory(REFIID, void**)", 32);
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
		hRenderdoc = LoadLibrary(L"renderdoc.dll");
		if (hRenderdoc == NULL)
		{
			g_Logger->error("load renderdoc.dll failed.\n");
			return false;
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
