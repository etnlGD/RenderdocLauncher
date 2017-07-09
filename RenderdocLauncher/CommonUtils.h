#pragma once
#include <string>

std::wstring s2w(const std::string& s);

std::string w2s(const std::wstring& s);


#define SPDLOG_WCHAR_FILENAMES
#include <spdlog/spdlog.h>		// log
extern std::shared_ptr<spdlog::logger> g_Logger;

