#include "AutoAimAnalyzer.h"
#include "CommonUtils.h"

#define OBJECT_VB_STRIDE 20

AutoAimAnalyzer::SVertData::SVertData(const char* pRawVertData)
{
	pos.x = *(float*)&pRawVertData[0];
	pos.y = *(float*)&pRawVertData[4];
	pos.z = *(float*)&pRawVertData[8];

	indices[0] = *(uint8_t*)&pRawVertData[12];
	indices[1] = *(uint8_t*)&pRawVertData[13];
	indices[2] = *(uint8_t*)&pRawVertData[14];
	indices[3] = *(uint8_t*)&pRawVertData[15];

	weights[0] = (*(uint8_t*)&pRawVertData[16]) / 255.0f;
	weights[1] = (*(uint8_t*)&pRawVertData[17]) / 255.0f;
	weights[2] = (*(uint8_t*)&pRawVertData[18]) / 255.0f;
	weights[3] = (*(uint8_t*)&pRawVertData[19]) / 255.0f;
}

AutoAimAnalyzer::AutoAimAnalyzer(ID3D11DeviceContext* pContext) : 
	m_pDevice(NULL), m_pContext(NULL), m_pCurFrameCB(NULL), m_pCurFrameTexBuffer(NULL)
{
	m_pContext = pContext;
	m_pContext->AddRef();

	pContext->GetDevice(&m_pDevice);
}

AutoAimAnalyzer::~AutoAimAnalyzer()
{
	SAFE_RELEASE(m_pDevice);
	SAFE_RELEASE(m_pContext);

	ClearFrameData();

	for (auto it = m_CachedVBData.begin(); it != m_CachedVBData.end(); ++it)
	{
		it->first->Release();
		SAFE_RELEASE(it->second.pStageBuffer);
	}
}

void AutoAimAnalyzer::OnDrawEnemyPart(UINT indexCount, UINT startIndex, UINT baseVertex)
{
	SDrawData d;
	d.indexCount = indexCount;
	d.startIndex = startIndex;
	d.baseVertex = baseVertex;

	ID3D11Buffer *pObjectCB, *pPosAndSkinVB, *pIndexBuffer;
	UINT stride, vbOffset;

	m_pContext->VSGetConstantBuffers(7, 1, &pObjectCB);
	m_pContext->IAGetVertexBuffers(0, 1, &pPosAndSkinVB, &stride, &vbOffset);
	m_pContext->IAGetIndexBuffer(&pIndexBuffer, &d.ibFormat, &d.ibOffset);
	if (pObjectCB == NULL || pPosAndSkinVB == NULL || stride != OBJECT_VB_STRIDE || vbOffset != 0 ||
		pIndexBuffer == NULL)
	{
		g_Logger->warn("AutoAimAnalyzer: current state not match "
					   "cb7 {} vb0 {} ib {} stride {} offset {}",
					   (void*) pObjectCB, (void*)pPosAndSkinVB, (void*) pIndexBuffer, stride, vbOffset);

		SAFE_RELEASE(pObjectCB);
		SAFE_RELEASE(pPosAndSkinVB);
		SAFE_RELEASE(pIndexBuffer);
		return;
	}

	d.pObjectCB = CopyBufferToCpu(pObjectCB);
	d.pCachedVB = GetCachedBufferData(pPosAndSkinVB);
	d.pCachedIB = GetCachedBufferData(pIndexBuffer);
	SAFE_RELEASE(pObjectCB);
	SAFE_RELEASE(pPosAndSkinVB);
	SAFE_RELEASE(pIndexBuffer);

// TODO_wzq verify input layout
// 	ID3D11InputLayout* pInputLayout;
// 	m_pContext->IAGetInputLayout(&pInputLayout);

	m_CurFrameDrawDatas.push_back(d);

	if (m_pCurFrameCB == NULL)
	{
		ID3D11Buffer* pFrameCB;
		m_pContext->VSGetConstantBuffers(9, 1, &pFrameCB);
		if (pFrameCB != NULL)
		{
			m_pCurFrameCB = CopyBufferToCpu(pFrameCB);
		}
		else
		{
			g_Logger->warn("AutoAimAnalyzer: Frame CB is not set");
		}
		SAFE_RELEASE(pFrameCB);
	}

	if (m_pCurFrameTexBuffer == NULL)
	{
		ID3D11ShaderResourceView* pTexBufferSRV;
		m_pContext->VSGetShaderResources(0, 1, &pTexBufferSRV);
		if (pTexBufferSRV != NULL)
		{
			ID3D11Resource* pTexBufferRes;
			pTexBufferSRV->GetResource(&pTexBufferRes);

			D3D11_RESOURCE_DIMENSION resType;
			pTexBufferRes->GetType(&resType);
			if (resType == D3D11_RESOURCE_DIMENSION_BUFFER)
			{
				ID3D11Buffer* pTexBuffer = static_cast<ID3D11Buffer*>(pTexBufferRes);
				m_pCurFrameTexBuffer = CopyBufferToCpu(pTexBuffer);
			}
			else
			{
				g_Logger->warn("AutoAimAnalyzer: resource at skin tbuffer slot is not a buffer");
			}

			SAFE_RELEASE(pTexBufferRes);
		}
		else
		{
			g_Logger->warn("AutoAimAnalyzer: skin tbuffer is not set");
		}
		SAFE_RELEASE(pTexBufferSRV);
	}
}

bool AutoAimAnalyzer::GetReferenceVert(const std::vector<SDrawData>& drawcalls, void* pRefVert)
{
	float maxY = -FLT_MAX, maxX = -FLT_MAX, maxZ = -FLT_MAX;
	float minY = FLT_MAX, minX = FLT_MAX, minZ = FLT_MAX;
	for (auto it = drawcalls.begin(); it != drawcalls.end(); ++it)
	{
		char *pRawIB, *pRawVB;
		MapBuffer(it->pCachedIB->pStageBuffer, (void**)&pRawIB, NULL);
		MapBuffer(it->pCachedVB->pStageBuffer, (void**)&pRawVB, NULL);

		// ib format only supports uint32 and uint16
		int ibStride = (it->ibFormat == DXGI_FORMAT_R32_UINT) ? 4 : 2;

		// optimize: only process first vert in tri
		for (UINT i = 0; i < it->indexCount; i += 3)
		{
			char* ibOff = &pRawIB[(i + it->startIndex) * ibStride];

			UINT vbIdx = it->baseVertex;
			if (ibStride == 4)
				vbIdx += *((uint32_t*) ibOff);
			else 
				vbIdx += *((uint16_t*) ibOff);

			float* pVert = reinterpret_cast<float*>(&pRawVB[vbIdx * OBJECT_VB_STRIDE]);
			maxY = (std::max)(maxY, pVert[1]); // pVert[1] -> pos.y
			maxX = (std::max)(maxX, pVert[0]); // pVert[0] -> pos.x
			maxZ = (std::max)(maxZ, pVert[2]); // pVert[2] -> pos.z

			minY = (std::min)(minY, pVert[1]); // pVert[1] -> pos.y
			minX = (std::min)(minX, pVert[0]); // pVert[0] -> pos.x
			minZ = (std::min)(minZ, pVert[2]); // pVert[2] -> pos.z
		}

		UnmapBuffer(it->pCachedIB->pStageBuffer);
		UnmapBuffer(it->pCachedVB->pStageBuffer);
	}

	if (maxY - minY < 0.75f || maxZ - minZ < 0.1f || maxX - minX < 0.1f) // maybe a weapon
		return false;

	if (maxX - minX > 3.0f || maxZ - minZ > 3.0f) // maybe the car
		return false;

#define TARGET_POS_RATIO 0.9f
	float targetX = 0, targetY = maxY * TARGET_POS_RATIO, targetZ = 0;
	float minDist2ToTarget = FLT_MAX;

	for (auto it = drawcalls.begin(); it != drawcalls.end(); ++it)
	{
		char *pRawIB, *pRawVB;
		MapBuffer(it->pCachedIB->pStageBuffer, (void**)&pRawIB, NULL);
		MapBuffer(it->pCachedVB->pStageBuffer, (void**)&pRawVB, NULL);

		// ib format only supports uint32 and uint16
		int ibStride = (it->ibFormat == DXGI_FORMAT_R32_UINT) ? 4 : 2;
		for (UINT i = 0; i < it->indexCount; i += 3)
		{
			char* ibOff = &pRawIB[(i + it->startIndex) * ibStride];

			UINT vbIdx = it->baseVertex;
			if (ibStride == 4)
				vbIdx += *((uint32_t*)ibOff);
			else
				vbIdx += *((uint16_t*)ibOff);

			float* pVert = reinterpret_cast<float*>(&pRawVB[vbIdx * OBJECT_VB_STRIDE]);
			float dx = pVert[0] - targetX;
			float dy = pVert[1] - targetY;
			float dz = pVert[2] - targetZ;
			float dist2 = dx * dx + dy * dy + dz * dz;
			if (dist2 < minDist2ToTarget)
			{
				memcpy(pRefVert, pVert, OBJECT_VB_STRIDE);
				minDist2ToTarget = dist2;
			}
		}

		UnmapBuffer(it->pCachedIB->pStageBuffer);
		UnmapBuffer(it->pCachedVB->pStageBuffer);
	}

	return true;
}

static Vec4 Vec4MulMat4x4(const Vec4& v, float(*mat4x4)[4])
{
	Vec4 o;
	o.x = v.x * mat4x4[0][0] + v.y * mat4x4[1][0] + v.z * mat4x4[2][0] + v.w * mat4x4[3][0];
	o.y = v.x * mat4x4[0][1] + v.y * mat4x4[1][1] + v.z * mat4x4[2][1] + v.w * mat4x4[3][1];
	o.z = v.x * mat4x4[0][2] + v.y * mat4x4[1][2] + v.z * mat4x4[2][2] + v.w * mat4x4[3][2];
	o.w = v.x * mat4x4[0][3] + v.y * mat4x4[1][3] + v.z * mat4x4[2][3] + v.w * mat4x4[3][3];
	return o;
}

static Vec4 Vec3MulMat4x4(const Vec3& v, float(*mat4x4)[4])
{
	Vec4 o;
	o.x = v.x * mat4x4[0][0] + v.y * mat4x4[1][0] + v.z * mat4x4[2][0] + mat4x4[3][0];
	o.y = v.x * mat4x4[0][1] + v.y * mat4x4[1][1] + v.z * mat4x4[2][1] + mat4x4[3][1];
	o.z = v.x * mat4x4[0][2] + v.y * mat4x4[1][2] + v.z * mat4x4[2][2] + mat4x4[3][2];
	o.w = v.x * mat4x4[0][3] + v.y * mat4x4[1][3] + v.z * mat4x4[2][3] + mat4x4[3][3];
	return o;
}

static Vec3 Vec3MulMat4x3(const Vec3& v, float (*mat4x3)[3])
{
	Vec3 o;
	o.x = v.x * mat4x3[0][0] + v.y * mat4x3[1][0] + v.z * mat4x3[2][0] + mat4x3[3][0];
	o.y = v.x * mat4x3[0][1] + v.y * mat4x3[1][1] + v.z * mat4x3[2][1] + mat4x3[3][1];
	o.z = v.x * mat4x3[0][2] + v.y * mat4x3[1][2] + v.z * mat4x3[2][2] + mat4x3[3][2];
	return o;
}

Vec3 AutoAimAnalyzer::SkinVert(const SVertData& vert, float* pTexBuffer, int pTexBufferOffset)
{
	Vec3 skined = { 0, 0, 0 };
	for (int i = 0; i < 4; ++i)
	{
		int idx = (vert.indices[i] + pTexBufferOffset) * 3;

		float skinMatrix[4][3];
		skinMatrix[0][0] = pTexBuffer[idx * 4 + 0];
		skinMatrix[0][1] = pTexBuffer[idx * 4 + 1];
		skinMatrix[0][2] = pTexBuffer[idx * 4 + 2];

		skinMatrix[1][0] = pTexBuffer[idx * 4 + 4];
		skinMatrix[1][1] = pTexBuffer[idx * 4 + 5];
		skinMatrix[1][2] = pTexBuffer[idx * 4 + 6];

		skinMatrix[2][0] = pTexBuffer[idx * 4 + 8];
		skinMatrix[2][1] = pTexBuffer[idx * 4 + 9];
		skinMatrix[2][2] = pTexBuffer[idx * 4 + 10];

		skinMatrix[3][0] = pTexBuffer[idx * 4 + 3];
		skinMatrix[3][1] = pTexBuffer[idx * 4 + 7];
		skinMatrix[3][2] = pTexBuffer[idx * 4 + 11];

		Vec3 o = Vec3MulMat4x3(vert.pos, skinMatrix);
		skined.x += o.x * vert.weights[i];
		skined.y += o.y * vert.weights[i];
		skined.z += o.z * vert.weights[i];
	}

	return skined;
}

Vec2 AutoAimAnalyzer::TransformVertToScreenSpace(const Vec3& v, ID3D11Buffer* pObjectCB, 
												 float* pFrameCB)
{
	float matWorldView[4][4];
	{
		float* cb7;
		MapBuffer(pObjectCB, (void**)&cb7, NULL);
		memcpy(matWorldView, &cb7[0], sizeof(matWorldView));
		UnmapBuffer(pObjectCB);
	}
	
	Vec4 vWorldView = Vec3MulMat4x4(v, matWorldView);

	float matProj[4][4];
	{
		memcpy(matProj, &pFrameCB[0], sizeof(matProj));
		matProj[0][3] = 0;
	}

	Vec4 vClip = Vec4MulMat4x4(vWorldView, matProj);

	Vec2 o;
	o.x = vClip.x / vClip.w * 0.5f + 0.5f;
	o.y = 1.0f - (vClip.y / vClip.w * 0.5f + 0.5f);
	return o;
}

void AutoAimAnalyzer::OnFrameEnd()
{
	m_TargetPos.clear();

	if (m_pCurFrameCB == NULL || m_pCurFrameTexBuffer == NULL)
	{
		ClearFrameData();
		return;
	}

	UINT skinTBSize;
	float *pSkinTexBuffer, *pFrameCB;
	MapBuffer(m_pCurFrameTexBuffer, (void**)&pSkinTexBuffer, &skinTBSize);
	MapBuffer(m_pCurFrameCB, (void**)&pFrameCB, NULL);


	// 1. group enemy parts into character according cb7_v16.z
	std::multimap<int, int> enemyParts;
	for (auto it = m_CurFrameDrawDatas.begin(); it != m_CurFrameDrawDatas.end(); ++it)
	{
		uint32_t cbSize;
		int* pResData;
		MapBuffer(it->pObjectCB, (void**) &pResData, &cbSize);

		// tbufferOffset is unique for a character, so this can group character parts
		int tbufferOffset = pResData[16 * 4 + 2];

		int partIndex = (int)(it - m_CurFrameDrawDatas.begin());
		if (tbufferOffset >= 0 && (tbufferOffset * 12) < (int) skinTBSize)
		{
			enemyParts.insert(std::make_pair(tbufferOffset, partIndex));
		}
		else
		{
			g_Logger->error("base skin position out of tbuffer bounds {}:", tbufferOffset);
			for (uint32_t i = 0; (i + 15) < cbSize; i += 16)
			{
				float* pFloat4 = (float*)&((uint8_t*)pResData)[i];
				g_Logger->error("\t\tv{}: {}, {}, {}, {}", i / 16, pFloat4[0], pFloat4[1], pFloat4[2], pFloat4[3]);
			}
		}

		UnmapBuffer(it->pObjectCB);
	}

	// 2. find target pos for each enemy
	for (auto itFirst = enemyParts.begin(); itFirst != enemyParts.end(); )
	{
		auto range = enemyParts.equal_range(itFirst->first);

		UINT totalIndexCount = 0;
		std::vector<SDrawData> drawcalls;
		for (auto it = range.first; it != range.second; ++it)
		{
			totalIndexCount += m_CurFrameDrawDatas[it->second].indexCount;
			drawcalls.push_back(m_CurFrameDrawDatas[it->second]);
		}

		if (drawcalls.size() > 1 && totalIndexCount >= 3000)
		{ // reject enemy equipment
			char refVertRaw[OBJECT_VB_STRIDE];
			if (GetReferenceVert(drawcalls, refVertRaw))
			{
				SVertData vert(refVertRaw);
				Vec3 skinedVert = SkinVert(vert, pSkinTexBuffer, itFirst->first);

				ID3D11Buffer* pObjectCB = m_CurFrameDrawDatas[itFirst->second].pObjectCB;

				Vec2 targetPos = TransformVertToScreenSpace(skinedVert, pObjectCB, pFrameCB);
				m_TargetPos.push_back(targetPos);
			}
		}

		itFirst = range.second;
	}

	UnmapBuffer(m_pCurFrameTexBuffer);
	UnmapBuffer(m_pCurFrameCB);

	ClearFrameData();
}

void AutoAimAnalyzer::ClearFrameData()
{
	SAFE_RELEASE(m_pCurFrameTexBuffer);
	SAFE_RELEASE(m_pCurFrameCB);
	for (auto it = m_CurFrameDrawDatas.begin(); it != m_CurFrameDrawDatas.end(); ++it)
	{
		SAFE_RELEASE(it->pObjectCB);
	}
	m_CurFrameDrawDatas.clear();

	// TODO_wzq clear CachedVBData.
}

ID3D11Buffer* AutoAimAnalyzer::CopyBufferToCpu(ID3D11Buffer* pBuffer)
{
	D3D11_BUFFER_DESC CBDesc;
	pBuffer->GetDesc(&CBDesc);

	ID3D11Buffer* pStageBuffer = NULL;
	{ // create shadow buffer.
		D3D11_BUFFER_DESC desc;
		desc.BindFlags = 0;
		desc.ByteWidth = CBDesc.ByteWidth;
		desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
		desc.MiscFlags = 0;
		desc.StructureByteStride = 0;
		desc.Usage = D3D11_USAGE_STAGING;

		if (FAILED(m_pDevice->CreateBuffer(&desc, NULL, &pStageBuffer)))
		{
			g_Logger->error("CreateBuffer failed when CopyBufferToCpu {}", CBDesc.ByteWidth);
		}
	}
	
	if (pStageBuffer != NULL)
		m_pContext->CopyResource(pStageBuffer, pBuffer);

	return pStageBuffer;
}

AutoAimAnalyzer::SCachedBufferData* AutoAimAnalyzer::GetCachedBufferData(ID3D11Buffer* pVB)
{
	if (m_CachedVBData.find(pVB) == m_CachedVBData.end())
	{
		ID3D11Buffer* pStageVB = CopyBufferToCpu(pVB);

		SCachedBufferData cacheData;
		cacheData.pStageBuffer = pStageVB;
		m_CachedVBData[pVB] = cacheData;
		pVB->AddRef();
	}

	return &m_CachedVBData[pVB];
}

void AutoAimAnalyzer::MapBuffer(ID3D11Buffer* pStageBuffer, void** ppData, UINT* pByteWidth)
{
	D3D11_MAPPED_SUBRESOURCE subRes;
	HRESULT res = m_pContext->Map(pStageBuffer, 0, D3D11_MAP_READ, 0, &subRes);

	D3D11_BUFFER_DESC desc;
	pStageBuffer->GetDesc(&desc);

	if (FAILED(res))
	{
		g_Logger->error("Map stage buffer failed {} {} {} {} {}", 
						(void*) pStageBuffer, desc.ByteWidth, desc.BindFlags, 
						desc.CPUAccessFlags, desc.Usage);
	}

	*ppData = subRes.pData;

	if (pByteWidth)
		*pByteWidth = desc.ByteWidth;
}

void AutoAimAnalyzer::UnmapBuffer(ID3D11Buffer* pStageBuffer)
{
	m_pContext->Unmap(pStageBuffer, 0);
}
