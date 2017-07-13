#pragma once
#include <d3d11.h>
#include <vector>
#include "asmjit/asmjit_build.h"
#include <map>

struct Vec2
{
	float x, y;
};

struct Vec3
{
	float x, y, z;
};

struct Vec4
{
	float x, y, z, w;
};

class AutoAimAnalyzer
{
private:
	struct SCachedBufferData
	{
		ID3D11Buffer* pStageBuffer;
	};

	struct SDrawData
	{
		ID3D11Buffer*		pObjectCB;
		SCachedBufferData*  pCachedVB;
		SCachedBufferData*  pCachedIB;
		DXGI_FORMAT			ibFormat;
		UINT				ibOffset;
		UINT				indexCount;
		UINT				startIndex;
		UINT				baseVertex;
	};

	struct SVertData 
	{
		Vec3	pos;
		uint8_t indices[4];
		float   weights[4];

		SVertData(const char* pRawVertData);
	};

public:
	AutoAimAnalyzer(ID3D11DeviceContext* pContext);

	virtual ~AutoAimAnalyzer();

	virtual void OnDrawEnemyPart(UINT indexCount, UINT startIndex, UINT baseVertex);

	virtual void OnFrameEnd();

	virtual const std::vector<Vec2>& GetResult() { return m_TargetPos; }

private:
	void ClearFrameData();

	ID3D11Buffer* CopyBufferToCpu(ID3D11Buffer* pBuffer);

	SCachedBufferData* GetCachedBufferData(ID3D11Buffer* pVB);

	void MapBuffer(ID3D11Buffer* pStageBuffer, void** ppData, UINT* pByteWidth);

	void UnmapBuffer(ID3D11Buffer* pStageBuffer);

	bool GetReferenceVert(const std::vector<SDrawData>& drawcalls, void* pRefVert);

	Vec3 SkinVert(const SVertData& vert, float* pTexBuffer, int pTexBufferOffset);

	Vec2 TransformVertToScreenSpace(const Vec3& v, ID3D11Buffer* pObjectCB, float* pFrameCB);

private:
	ID3D11Device* m_pDevice;
	ID3D11DeviceContext* m_pContext;

	ID3D11Buffer* m_pCurFrameCB;
	ID3D11Buffer* m_pCurFrameTexBuffer;
	std::vector<SDrawData> m_CurFrameDrawDatas;

	std::vector<Vec2> m_TargetPos;

	std::map<ID3D11Buffer*, SCachedBufferData> m_CachedVBData;
};

