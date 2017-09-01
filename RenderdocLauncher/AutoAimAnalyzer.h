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

// Grab enemy information from d3d11.
class AutoAimAnalyzer
{
private:
	struct SCachedBufferData
	{
		size_t lastAccessFrame;
		ID3D11Buffer* pStageBuffer;
	};

	struct SEnemyDrawData
	{
		ID3D11Buffer*		pObjectCB;
		SCachedBufferData*  pCachedVB;
		SCachedBufferData*  pCachedIB;
		DXGI_FORMAT			ibFormat;
		uint32_t			ibOffset;
		uint32_t			indexCount;
		uint32_t			startIndex;
		uint32_t			baseVertex;
	};

	struct SAllyFrameData
	{

	};

	struct SAllyArrowDrawData
	{
		uint32_t vertexOffset;
		uint32_t vbOffset;
		ID3D11Buffer* pCachedVB;
		ID3D11Buffer* pCachedTB;
	};

	struct SVertData 
	{
		Vec3	pos;
		uint8_t indices[4];
		float   weights[4];

		SVertData(const char* pRawVertData);
	};

public:
	struct SAimResult 
	{
		Vec2 onScreenPos;
		Vec3 offsetToCamera;
		uint32_t id;

		bool isAlly() const { return id == -1; }
	};

public:
	AutoAimAnalyzer(ID3D11DeviceContext* pContext);

	virtual ~AutoAimAnalyzer();

	virtual void OnDrawEnemyPart(uint32_t indexCount, uint32_t startIndex, uint32_t baseVertex);

	virtual void OnDrawAllyArrow(uint32_t vertexCount, uint32_t vertexOffset);

	virtual void OnFrameEnd();

	virtual const std::vector<SAimResult>& GetResult() { return m_TargetPos; }

	void SetShootPosRatio(float r) { m_fShootPosRatio = r; }

private:
	void ClearFrameData();

	ID3D11Buffer* CopyBufferToCpu(ID3D11Buffer* pBuffer);

	SCachedBufferData* GetCachedBufferData(ID3D11Buffer* pVB);

	ID3D11Buffer* GetFrameCachedBufferData(ID3D11Buffer* pVB);

	void MapBuffer(ID3D11Buffer* pStageBuffer, void** ppData, uint32_t* pByteWidth);

	void UnmapBuffer(ID3D11Buffer* pStageBuffer);

	bool GetReferenceVert(const std::vector<SEnemyDrawData>& drawcalls, void* pRefVert, Vec3* pAABB);

	Vec3 SkinVert(const SVertData& vert, float* pTexBuffer, int pTexBufferOffset);

	void TransformVertToScreenSpace(const Vec3& v, ID3D11Buffer* pObjectCB, float* pFrameCB, SAimResult* pRes);

	void AnalyseEnemyData();

private:
	float m_fShootPosRatio;

	size_t m_CurrFrame;
	ID3D11Device* m_pDevice;
	ID3D11DeviceContext* m_pContext;

	// enemy data
	ID3D11Buffer* m_pCurFrameCB;
	ID3D11Buffer* m_pCurFrameTexBuffer;
	std::vector<SEnemyDrawData> m_CurFrameEnemyDatas;

	// ally data
	std::vector<SAllyArrowDrawData> m_CurFrameAllyDatas;

	// long time cached buffer
	std::map<ID3D11Buffer*, SCachedBufferData> m_CachedVBData;

	// frame cached buffer
	std::map<ID3D11Buffer*, ID3D11Buffer*> m_FrameCachedVBData;

	// analyse result
	std::vector<SAimResult> m_TargetPos;
};

