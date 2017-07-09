#include "CommonUtils.h"
#include <locale>
#include <codecvt>

std::shared_ptr<spdlog::logger> g_Logger;

std::wstring s2w(const std::string& s)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return converter.from_bytes(s);
}

std::string w2s(const std::wstring& s)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return converter.to_bytes(s);
}
