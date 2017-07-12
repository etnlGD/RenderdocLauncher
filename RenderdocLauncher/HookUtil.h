#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <map>

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

	uint8_t* GetOriginalPtr(void* pObject);

private:
	std::map<uint8_t*, void*> AllDetours;
};

void* CreateIATHook(const char* LibraryName, const char* SrcFunc, uint8_t* Dest, const char* Module);

void  ReleaseIATHook(void* pIATHookHandle);
