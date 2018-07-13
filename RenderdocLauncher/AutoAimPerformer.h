#pragma once
#include <cstdint>
#include "AutoAimAnalyzer.h"

class AutoAimPerformer
{
public:
	void SetOutputWnd(HWND OutputWnd);

	size_t ProcessResults(bool enableAimbot, const std::vector<AutoAimAnalyzer::SAimResult>* pResult);

private:
	void SetCursorPosF(HWND hwnd, float x, float y);

	void AimTarget(Vec2 targetTex, float minDistToCenter);
	
private:
	int skipState = 0;
	const float nearToY = 1.41411f;
	const float xToY = 16.0f / 9.0f;

	HWND OutputWnd;
	UINT wndWidth;
	UINT wndHeight;
};

