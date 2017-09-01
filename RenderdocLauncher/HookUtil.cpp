#include "HookUtil.h"
#include "PolyHook/PolyHook.hpp"
#include "CommonUtils.h"
#include "AsmCommon.h"

DetourHookInfo::DetourHookInfo(HMODULE targetModule, LPCSTR targetFunc, 
							   HMODULE sourceModule, LPCSTR sourceFunc) :
							   hTargetModule(targetModule), sTargetFunc(targetFunc),
							   m_pDetour(new PLH::Detour), m_bInstalledHook(false)
{
	if (sourceFunc == NULL)
		sourceFunc = targetFunc;

	m_pSourceFunc = (FARPROC)GetProcAddress(sourceModule, sourceFunc);
}

DetourHookInfo::DetourHookInfo(HMODULE targetModule, LPCSTR targetFunc, FARPROC pSourceFunc) :
	hTargetModule(targetModule), sTargetFunc(targetFunc),
	m_pSourceFunc(pSourceFunc),
	m_pDetour(new PLH::Detour), m_bInstalledHook(false)
{
}

bool DetourHookInfo::InstallHook()
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
	if (g_DebugMode || g_HookedProcessName.find(L"overwatch.exe") != std::wstring::npos)
		HackOverwatch(pTargetFunc);

	PLH::Detour* pDetour = static_cast<PLH::Detour*>(m_pDetour);
	pDetour->SetupHook(pTargetFunc, (uint8_t*)m_pSourceFunc);
	m_bInstalledHook = pDetour->Hook();
	if (!m_bInstalledHook)
	{
		g_Logger->warn("Detour function {}!{} from {:p} to {:p} failed",
					   w2s(targetModulePath), sTargetFunc,
					   (void*)pTargetFunc, (void*)m_pSourceFunc);
	}
	else
	{
		g_Logger->debug("Detour function {}!{} from {:p} to {:p} succeed",
						w2s(targetModulePath), sTargetFunc,
						(void*)pTargetFunc, (void*)m_pSourceFunc);
	}

	return m_bInstalledHook;
}

FARPROC DetourHookInfo::GetOriginal()
{
	PLH::Detour* pDetour = static_cast<PLH::Detour*>(m_pDetour);
	return m_bInstalledHook ?
			pDetour->GetOriginal<FARPROC>() : GetProcAddress(hTargetModule, sTargetFunc);
}

void DetourHookInfo::HackOverwatch(uint8_t* pTargetFunc)
{
	if (hTargetModule == hD3D11 || hTargetModule == hDXGI)
	{
		uint8_t* restoreCode;
		uint32_t restoreCodeSize;
		GenerateRestoreCode(pTargetFunc, 32, NULL, &restoreCode, &restoreCodeSize, NULL);

		PLH::Detour* pDetour = static_cast<PLH::Detour*>(m_pDetour);
		pDetour->m_PreserveSize = 32;
		pDetour->m_RestoreCode = restoreCode;
		pDetour->m_RestoreCodeSize = restoreCodeSize;
	}
}

VTableHook::VTableHook(int vtableIndex, void* pFuncPtr, 
					   const char* pFuncName, uint32_t preserveSize) :
						VTableIndex(vtableIndex), HookFuncPtr((uint8_t*)pFuncPtr),
						FuncName(pFuncName), PreserveSize(preserveSize)
{
}

VTableHook::~VTableHook()
{
	for (auto it = AllDetours.begin(); it != AllDetours.end(); ++it)
	{
		PLH::Detour* pDetour = static_cast<PLH::Detour*>(it->second.detour);
		delete pDetour;
	}
}

void VTableHook::HookObject(void* pObject)
{
	if (pObject == NULL)
		return;

	uint8_t** vtable = *((uint8_t***)pObject);
	uint8_t* pSourceFunc = vtable[VTableIndex];
	if (AllDetours.find(pSourceFunc) == AllDetours.end())
	{
		HookData hookData;
		uint8_t* restoreCode = NULL;
		uint32_t restoreCodeSize = 0;
		if (PreserveSize > 0)
		{
			GenerateRestoreCode(pSourceFunc, PreserveSize, HookFuncPtr,
								&restoreCode, &restoreCodeSize, &hookData.jmpPatch);
		}

		if (hookData.jmpPatch.jmpTargetAddr == NULL) // no jmp or call in function prologue, as usual
		{
			PLH::Detour* pDetour = new PLH::Detour;
			pDetour->m_RestoreCode = restoreCode;
			pDetour->m_RestoreCodeSize = restoreCodeSize;
			pDetour->m_PreserveSize = PreserveSize;
			pDetour->SetupHook(pSourceFunc, HookFuncPtr);
			if (!pDetour->Hook())
			{
				g_Logger->warn("Detour virtual function {} @ {} from {} to {} failed",
							   FuncName, VTableIndex, (void*)pSourceFunc, (void*)HookFuncPtr);
			}
			else
			{
				g_Logger->debug("Detour virtual function {} @ {} from {} to {} succeed",
								FuncName, VTableIndex, (void*)pSourceFunc, (void*)HookFuncPtr);
			}

			hookData.detour = pDetour;

			DWORD oldProtection;
			VirtualProtect(pSourceFunc, 32, PAGE_EXECUTE, &oldProtection);
			printf("oldProtection: %d\n", oldProtection);
		}
		else
		{
			PLH::MemoryProtect memProtect(hookData.jmpPatch.jmpTargetAddr, sizeof(uint64_t), PAGE_EXECUTE_READWRITE);
			*hookData.jmpPatch.jmpTargetAddr = hookData.jmpPatch.newJmpTarget;
			printf("Detour function with jmp/call in prologue: %s\n", FuncName.c_str());
			g_Logger->debug("Detour virtual function {} @ {} from {} to {} succeed (jmp info {} {})",
							FuncName, VTableIndex, (void*)pSourceFunc, (void*)HookFuncPtr, 
							(void*)hookData.jmpPatch.oldJmpTarget, (void*)hookData.jmpPatch.newJmpTarget);

		}
		
		AllDetours[pSourceFunc] = hookData;
	}
}

uint8_t* VTableHook::BeginInvokeOriginal(void* pObject)
{
	uint8_t* pSourceFunc = GetVTableFuncPtr(pObject);
	if (pSourceFunc == NULL)
		return NULL;

	auto it = AllDetours.find(pSourceFunc);
	if (it != AllDetours.end())
	{
		PLH::Detour* pDetour = static_cast<PLH::Detour*>(it->second.detour);
		if (pDetour != NULL)
			return pDetour->GetOriginal<uint8_t*>();

		// remove jmp patch, and return source func ptr.
		PLH::MemoryProtect memProtect(it->second.jmpPatch.jmpTargetAddr, sizeof(uint64_t), PAGE_EXECUTE_READWRITE);
		*it->second.jmpPatch.jmpTargetAddr = it->second.jmpPatch.oldJmpTarget;
		return it->first;
	}

	return NULL;
}

void VTableHook::EndInvokeOriginal(void* pSourceFunc)
{
	// add jmp patch
	auto it = AllDetours.find((uint8_t*)pSourceFunc);
	if (it != AllDetours.end() && it->second.jmpPatch.jmpTargetAddr != NULL)
	{
		PLH::MemoryProtect memProtect(it->second.jmpPatch.jmpTargetAddr, sizeof(uint64_t), PAGE_EXECUTE_READWRITE);
		*it->second.jmpPatch.jmpTargetAddr = it->second.jmpPatch.newJmpTarget;
	}
}

uint8_t* VTableHook::GetVTableFuncPtr(void* pObject)
{
	if (pObject == NULL)
		return NULL;

	uint8_t** vtable = *((uint8_t***)pObject);
	return vtable[VTableIndex];
}

void* CreateIATHook(const char* LibraryName, const char* SrcFunc, uint8_t* Dest, const char* Module)
{
	PLH::IATHook* pIATHook = new PLH::IATHook;
	pIATHook->SetupHook(LibraryName, SrcFunc, Dest, Module);
	if (!pIATHook->Hook())
	{
		g_Logger->error("IAT Hook from {}!{} to {} failed", LibraryName, SrcFunc, (void*)Dest);
		delete pIATHook;
		return NULL;
	}

	return pIATHook;
}

void ReleaseIATHook(void* p)
{
	if (p)
	{
		PLH::IATHook* pIATHook = static_cast<PLH::IATHook*>(p);
		delete pIATHook;
	}
}
