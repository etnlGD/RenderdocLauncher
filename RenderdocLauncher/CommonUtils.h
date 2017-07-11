#pragma once
#include <string>

std::wstring s2w(const std::string& s);

std::string w2s(const std::wstring& s);


#define SPDLOG_WCHAR_FILENAMES
#include <spdlog/spdlog.h>		// log
extern std::shared_ptr<spdlog::logger> g_Logger;


#ifndef SAFE_RELEASE
#define SAFE_RELEASE(p) { if (p) { (p)->Release(); (p) = nullptr; } }
#endif

extern std::wstring g_HookedProcessName;
extern bool g_DebugMode;
extern HMODULE hD3D11;
extern HMODULE hCurrentModule;
extern HMODULE hRenderdoc;
extern HMODULE hDXGI;
