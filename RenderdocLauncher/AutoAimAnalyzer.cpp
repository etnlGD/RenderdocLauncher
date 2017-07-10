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
		SAFE_RELEASE(it->second.pStageVB);
	}
	m_CachedVBData.clear();
}

void AutoAimAnalyzer::OnDrawEnemyPart(UINT indexCount)
{
	ID3D11Buffer* pObjectCB;
	m_pContext->VSGetConstantBuffers(7, 1, &pObjectCB);
	if (pObjectCB == NULL)
	{
		g_Logger->warn("AutoAimAnalyzer: Object CB not set");
		return;
	}

	ID3D11Buffer* pPosAndSkinVB;
	UINT stride, offset;
	m_pContext->IAGetVertexBuffers(0, 1, &pPosAndSkinVB, &stride, &offset);
	if (pPosAndSkinVB == NULL || stride != OBJECT_VB_STRIDE || offset != 0)
	{
		g_Logger->warn("AutoAimAnalyzer: vb0 is null or buffer stride or offset not match "
					   "pBuffer {} stride {} offset {}",
					   (void*)pPosAndSkinVB, stride, offset);

		SAFE_RELEASE(pObjectCB);
		SAFE_RELEASE(pPosAndSkinVB);
		return;
	}

	ID3D11Buffer* pObjectStageCB = CopyBufferToCpu(pObjectCB);
	SAFE_RELEASE(pObjectCB);

	SVBCachedData* pCachedVB = GetCachedVBData(pPosAndSkinVB);
	SAFE_RELEASE(pPosAndSkinVB);

	m_CurFrameDrawDatas.push_back(SDrawData{ pObjectStageCB, pCachedVB, indexCount });

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

void AutoAimAnalyzer::GetReferenceVert(const std::vector<SVBCachedData*>& pVBs, void* pRefVert)
{
	float maxY = 0;
	for (auto it = pVBs.begin(); it != pVBs.end(); ++it)
	{
		maxY = (std::max)(maxY, (*it)->maxY);
	}

#define TARGET_POS_RATIO 0.8f
	float targetX = 0, targetY = maxY * TARGET_POS_RATIO, targetZ = 0;
	float minDist2ToTarget = FLT_MAX;
	for (auto it = pVBs.begin(); it != pVBs.end(); ++it)
	{
		char* pData;
		UINT byteWidth;
		MapBuffer((*it)->pStageVB, (void**) &pData, &byteWidth);

		for (UINT i = 0; i < byteWidth; i += OBJECT_VB_STRIDE)
		{
			float* pVert = reinterpret_cast<float*>(&pData[i]);
			float dx = pVert[0] - targetX;
			float dy = pVert[1] - targetY;
			float dz = pVert[2] - targetZ;
			float dist2 = dx * dx + dy * dy + dz * dz;
			if (dist2 < minDist2ToTarget)
			{
				memcpy(pRefVert, &pData[i], OBJECT_VB_STRIDE);
				minDist2ToTarget = dist2;
			}
		}

		UnmapBuffer((*it)->pStageVB);
	}
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
	o.x = vClip.x / vClip.w;
	o.y = vClip.y / vClip.w;
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


	// 1. group enemy parts into character according vb7_v16.z
	std::multimap<int, int> enemyParts;
	for (auto it = m_CurFrameDrawDatas.begin(); it != m_CurFrameDrawDatas.end(); ++it)
	{
		int* pResData;
		MapBuffer(it->pObjectCB, (void**) &pResData, NULL);

		// tbufferOffset is unique for a character, so this can group character parts
		int tbufferOffset = pResData[16 * 4 + 3];

		int partIndex = (int)(it - m_CurFrameDrawDatas.begin());
		enemyParts.insert(std::make_pair(tbufferOffset, partIndex));

		UnmapBuffer(it->pObjectCB);
	}

	float *pSkinTexBuffer, *pFrameCB;
	MapBuffer(m_pCurFrameTexBuffer, (void**)&pSkinTexBuffer, NULL);
	MapBuffer(m_pCurFrameCB, (void**)&pFrameCB, NULL);

	// 2. find target pos for each enemy
	for (auto itFirst = enemyParts.begin(); itFirst != enemyParts.end(); )
	{
		auto range = enemyParts.equal_range(itFirst->first);

		UINT totalIndexCount = 0;
		std::vector<SVBCachedData*> vbs;
		for (auto it = range.first; it != range.second; ++it)
		{
			totalIndexCount += m_CurFrameDrawDatas[it->second].indexCount;
			vbs.push_back(m_CurFrameDrawDatas[it->second].pCachedVB);
		}

		if (vbs.size() > 1 && totalIndexCount >= 3000)
		{ // reject enemy equipment
			char refVertRaw[OBJECT_VB_STRIDE];
			GetReferenceVert(vbs, refVertRaw);

			SVertData vert(refVertRaw);
			Vec3 skinedVert = SkinVert(vert, pSkinTexBuffer, itFirst->first);

			ID3D11Buffer* pObjectCB = m_CurFrameDrawDatas[itFirst->second].pObjectCB;
			Vec2 targetPos = TransformVertToScreenSpace(skinedVert, pObjectCB, pFrameCB);
			m_TargetPos.push_back(targetPos);
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

		m_pDevice->CreateBuffer(&desc, NULL, &pStageBuffer);
	}
	
	m_pContext->CopyResource(pStageBuffer, pBuffer);
	return pStageBuffer;
}

AutoAimAnalyzer::SVBCachedData* AutoAimAnalyzer::GetCachedVBData(ID3D11Buffer* pVB)
{
	if (m_CachedVBData.find(pVB) == m_CachedVBData.end())
	{
		ID3D11Buffer* pStageVB = CopyBufferToCpu(pVB);

		char* pData;
		UINT byteWidth;
		MapBuffer(pStageVB, (void**) &pData, &byteWidth);

		float maxY = 0;
		for (UINT i = 0; i < byteWidth; i += OBJECT_VB_STRIDE)
		{
			float* vertOff = reinterpret_cast<float*>(&pData[i]);
			float localY = vertOff[1];
			maxY = (std::max)(localY, maxY);
		}

		UnmapBuffer(pStageVB);

		SVBCachedData cacheData;
		cacheData.maxY = maxY;
		cacheData.pStageVB = pStageVB;
		m_CachedVBData[pVB] = cacheData;
		pVB->AddRef();
	}

	return &m_CachedVBData[pVB];
}

void AutoAimAnalyzer::MapBuffer(ID3D11Buffer* pStageBuffer, void** ppData, UINT* pByteWidth)
{
	D3D11_MAPPED_SUBRESOURCE subRes;
	m_pContext->Map(pStageBuffer, 0, D3D11_MAP_READ, 0, &subRes);

	D3D11_BUFFER_DESC desc;
	pStageBuffer->GetDesc(&desc);

	*ppData = subRes.pData;

	if (pByteWidth)
		*pByteWidth = desc.ByteWidth;
}

void AutoAimAnalyzer::UnmapBuffer(ID3D11Buffer* pStageBuffer)
{
	m_pContext->Unmap(pStageBuffer, 0);
}
