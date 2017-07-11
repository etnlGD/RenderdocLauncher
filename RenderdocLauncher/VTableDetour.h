#pragma once
#include "PolyHook/PolyHook.hpp"
#include <map>

class VTableDetour
{
public:
private:
	std::map<uint8_t*, PLH::Detour*> m_AllDetours;
};

