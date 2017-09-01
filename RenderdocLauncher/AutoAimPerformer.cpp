#include "AutoAimPerformer.h"
#include <winuser.h>

void AutoAimPerformer::SetOutputWnd(HWND OutputWnd)
{
	RECT wndRect;
	GetClientRect(OutputWnd, &wndRect);
	wndWidth = (wndRect.right - wndRect.left);
	wndHeight = (wndRect.bottom - wndRect.top);
	this->OutputWnd = OutputWnd;
}

size_t AutoAimPerformer::ProcessResults(bool enableAimbot,
									    const std::vector<AutoAimAnalyzer::SAimResult>* pResult)
{
	float minDistToCenter = FLT_MAX;

	size_t selectedIdx = -1;
	Vec2 targetTex;
	for (auto it = pResult->begin(); it != pResult->end(); ++it)
	{
// 		if (!it->isAlly())
// 			continue;

		Vec2 point = { it->onScreenPos.x * wndWidth, it->onScreenPos.y * wndHeight, };
		float dist = sqrt(pow(point.x - wndWidth / 2.0f, 2.0f) +
						  pow(point.y - wndHeight / 2.0f, 2.0f));

		if (minDistToCenter > dist)
		{
			minDistToCenter = dist;
			targetTex = it->onScreenPos;
			selectedIdx = it - pResult->begin();
		}
	}

	bool setCursor = false;
	if (enableAimbot && minDistToCenter < 100.0f && minDistToCenter >= 5.0f)
	{
		AimTarget(targetTex, minDistToCenter);
		++skipState;
		return selectedIdx;
	}

	skipState = 0;
	return -1;
}



void AutoAimPerformer::AimTarget(Vec2 targetTex, float minDistToCenter)
{
	Vec2 targetPos = { targetTex.x * wndWidth, targetTex.y * wndHeight };

	Vec2 vec;
	vec.x = targetPos.x - wndWidth / 2.0f;
	vec.y = targetPos.y - wndHeight / 2.0f;
	vec.x /= minDistToCenter;
	vec.y /= minDistToCenter; // normalized vec

	Vec3 viewPos;
	viewPos.x = (targetTex.x * 2.0f - 1.0f) * xToY;
	viewPos.y = (1.0f - targetTex.y) * 2.0f - 1.0f;
	viewPos.z = nearToY;

	float rayLen = sqrt(viewPos.x * viewPos.x + viewPos.y * viewPos.y + viewPos.z * viewPos.z);
	viewPos.x /= rayLen;
	viewPos.y /= rayLen;
	viewPos.z /= rayLen;

	float dotZAxis = viewPos.z; // dot(viewPos, float3(0, 0, 1))
	float deltaAngle = acos(dotZAxis);

	float speed = 6.6666f;
	vec.x *= deltaAngle / 3.1415926f * 180.0f * speed;
	vec.y *= deltaAngle / 3.1415926f * 180.0f * speed;

	vec.x += wndWidth / 2.0f;
	vec.y += wndHeight / 2.0f; // convert from vector to point

	if (!(skipState == 1 || skipState == 2))
	{
		SetCursorPosF(OutputWnd, vec.x / wndWidth, vec.y / wndHeight);
	}
}

void AutoAimPerformer::SetCursorPosF(HWND hwnd, float x, float y)
{
	RECT wndRect;
	GetWindowRect(hwnd, &wndRect);

// 	POINT targetPt;
// 	targetPt.x = (LONG) ((wndRect.right - wndRect.left) * x);
// 	targetPt.y = (LONG) ((wndRect.bottom - wndRect.top) * y);
// 
// 	ClientToScreen(hwnd, &targetPt);
// 
// 	POINT mousePt;
// 	GetCursorPos(&mousePt);

	INPUT mouseMove;
	mouseMove.type = INPUT_MOUSE;
	mouseMove.mi.dx = (LONG)((x - 0.5f) * (wndRect.right - wndRect.left));// targetPt.x - mousePt.x;
	mouseMove.mi.dy = (LONG)((y - 0.5f) * (wndRect.bottom - wndRect.top)); // targetPt.y - mousePt.y;
	mouseMove.mi.mouseData = 0;
	mouseMove.mi.dwFlags = MOUSEEVENTF_MOVE;
	mouseMove.mi.time = 0;
	mouseMove.mi.dwExtraInfo = NULL;
	SendInput(1, &mouseMove, sizeof(INPUT));
}