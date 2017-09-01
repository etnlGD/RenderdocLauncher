#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <map>
#include "AsmCommon.h"

struct DetourHookInfo
{
public:
	HMODULE hTargetModule;
	LPCSTR  sTargetFunc;
	FARPROC m_pSourceFunc;
	bool	m_bInstalledHook;

private:
	void*	m_pDetour;

public:
	DetourHookInfo(HMODULE targetModule, LPCSTR targetFunc,
				   HMODULE sourceModule, LPCSTR sourceFunc = NULL);

	DetourHookInfo(HMODULE targetModule, LPCSTR targetFunc, FARPROC pSourceFunc);

	bool InstallHook();

	FARPROC GetOriginal();

private:
	void HackOverwatch(uint8_t* pTargetFunc);
};

struct VTableHook
{
public:
	int			VTableIndex;
	uint8_t*	HookFuncPtr;
	uint8_t*	SourceFuncPtr;
	std::string	FuncName;
	uint32_t	PreserveSize;

	VTableHook(int vtableIndex, void* pFuncPtr, const char* pFuncName = "",
			   uint32_t preserveSize = 0);

	~VTableHook();

	void HookObject(void* pObject);

	uint8_t* BeginInvokeOriginal(void* pObject);
	void EndInvokeOriginal(void* pSourceFunc);

	uint8_t* GetVTableFuncPtr(void* pObject);

private:
	struct HookData 
	{
		void* detour;
		PrologueJmpPatch jmpPatch;
		HookData() : detour(NULL) {}
	};
	std::map<uint8_t*, HookData> AllDetours;
};

void* CreateIATHook(const char* LibraryName, const char* SrcFunc, uint8_t* Dest, const char* Module);

void  ReleaseIATHook(void* pIATHookHandle);
