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
	m_pDevice(NULL), m_pContext(NULL), m_pCurFrameCB(NULL), m_pCurFrameTexBuffer(NULL),
	m_CurrFrame(0)
{
	m_pContext = pContext;
	m_pContext->AddRef();

	m_fShootPosRatio = 0.9f;

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

void AutoAimAnalyzer::OnDrawEnemyPart(uint32_t indexCount, uint32_t startIndex, uint32_t baseVertex)
{
	SEnemyDrawData d;
	d.indexCount = indexCount;
	d.startIndex = startIndex;
	d.baseVertex = baseVertex;

	ID3D11Buffer *pObjectCB, *pPosAndSkinVB, *pIndexBuffer;
	uint32_t stride, vbOffset;

	m_pContext->VSGetConstantBuffers(7, 1, &pObjectCB);
	m_pContext->IAGetVertexBuffers(0, 1, &pPosAndSkinVB, &stride, &vbOffset);
	m_pContext->IAGetIndexBuffer(&pIndexBuffer, &d.ibFormat, &d.ibOffset);
	if (pObjectCB == NULL || pPosAndSkinVB == NULL || stride != OBJECT_VB_STRIDE || vbOffset != 0 ||
		pIndexBuffer == NULL)
	{
// 		g_Logger->warn("AutoAimAnalyzer: current state not match "
// 					   "cb7 {} vb0 {} ib {} stride {} offset {}",
// 					   (void*) pObjectCB, (void*)pPosAndSkinVB, (void*) pIndexBuffer, stride, vbOffset);

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

	m_CurFrameEnemyDatas.push_back(d);

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

#define ALLY_VB_STRIDE 16
#define ALLY_TEX1_VB_OFFSET 8
void AutoAimAnalyzer::OnDrawAllyArrow(uint32_t vertexCount, uint32_t vertexOffset)
{
	if (vertexCount == 0)
		return;

	ID3D11Buffer* pVB;
	uint32_t stride, offset;
	m_pContext->IAGetVertexBuffers(0, 1, &pVB, &stride, &offset);

	ID3D11ShaderResourceView* pVSTexBufferView;
	m_pContext->VSGetShaderResources(0, 1, &pVSTexBufferView);

	D3D11_SHADER_RESOURCE_VIEW_DESC viewDesc;
	viewDesc.ViewDimension = D3D11_SRV_DIMENSION_UNKNOWN;
	if (pVSTexBufferView)
		pVSTexBufferView->GetDesc(&viewDesc);

	if (pVB == NULL || stride != ALLY_VB_STRIDE || pVSTexBufferView == NULL || 
		viewDesc.ViewDimension != D3D11_SRV_DIMENSION_BUFFER || 
		viewDesc.Buffer.ElementOffset != 0)
	{
		SAFE_RELEASE(pVB);
		SAFE_RELEASE(pVSTexBufferView);
		g_Logger->error("AutoAimAnalyser::OnDrawAllyArrow: state not match {} {} {} {}",
						(void*) pVSTexBufferView, (void*) pVB, stride, offset);
		return;
	}

	ID3D11Resource* pResource;
	pVSTexBufferView->GetResource(&pResource);
	SAFE_RELEASE(pVSTexBufferView);

	if (pResource == NULL)
	{
		SAFE_RELEASE(pVB);
		return;
	}

	ID3D11Buffer* pTexBuffer = static_cast<ID3D11Buffer*>(pResource);
	{
		static bool logOnce = true;
		if (logOnce)
		{
			D3D11_BUFFER_DESC tbDesc, vbDesc;
			pTexBuffer->GetDesc(&tbDesc);
			pVB->GetDesc(&vbDesc);

			g_Logger->info("AutoAimAnalyser: VB({} {}), TB({}) TBView({} {} {})",
						   vbDesc.Usage, vbDesc.CPUAccessFlags, tbDesc.StructureByteStride,
						   (uint32_t) viewDesc.Format, viewDesc.Buffer.FirstElement, viewDesc.Buffer.NumElements);
			logOnce = false;
		}
	}

	SAllyArrowDrawData drawData;
	drawData.vertexOffset = vertexOffset;
	drawData.vbOffset = offset;
	drawData.pCachedVB = GetFrameCachedBufferData(pVB);
	drawData.pCachedTB = GetFrameCachedBufferData(pTexBuffer);
	m_CurFrameAllyDatas.push_back(drawData);
}

bool AutoAimAnalyzer::GetReferenceVert(const std::vector<SEnemyDrawData>& drawcalls, void* pRefVert, Vec3* pAABB)
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
		for (uint32_t i = 0; i < it->indexCount; i += 3)
		{
			char* ibOff = &pRawIB[(i + it->startIndex) * ibStride];

			uint32_t vbIdx = it->baseVertex;
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

	pAABB->x = maxX - minX;
	pAABB->y = maxY - minY;
	pAABB->z = maxZ - minZ;

	if (pAABB->y < 0.75f || pAABB->z < 0.1f || pAABB->x < 0.1f) // maybe a weapon
		return false;

	if (pAABB->x > 3.0f || pAABB->z > 3.0f) // maybe the car
		return false;

	float targetX = 0, targetY = maxY * m_fShootPosRatio, targetZ = 0;
	float minDist2ToTarget = FLT_MAX;

	for (auto it = drawcalls.begin(); it != drawcalls.end(); ++it)
	{
		char *pRawIB, *pRawVB;
		MapBuffer(it->pCachedIB->pStageBuffer, (void**)&pRawIB, NULL);
		MapBuffer(it->pCachedVB->pStageBuffer, (void**)&pRawVB, NULL);

		// ib format only supports uint32 and uint16
		int ibStride = (it->ibFormat == DXGI_FORMAT_R32_UINT) ? 4 : 2;
		for (uint32_t i = 0; i < it->indexCount; i += 3)
		{
			char* ibOff = &pRawIB[(i + it->startIndex) * ibStride];

			uint32_t vbIdx = it->baseVertex;
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

void AutoAimAnalyzer::TransformVertToScreenSpace(const Vec3& v, ID3D11Buffer* pObjectCB, 
												 float* pFrameCB, SAimResult* pRes)
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
	pRes->onScreenPos = o;

	pRes->offsetToCamera.x = matWorldView[3][0];
	pRes->offsetToCamera.x = matWorldView[3][1];
	pRes->offsetToCamera.x = matWorldView[3][2];
}

void AutoAimAnalyzer::AnalyseEnemyData()
{
	if (m_pCurFrameCB == NULL || m_pCurFrameTexBuffer == NULL)
	{
		return;
	}

	uint32_t skinTBSize;
	float *pSkinTexBuffer, *pFrameCB;
	MapBuffer(m_pCurFrameTexBuffer, (void**)&pSkinTexBuffer, &skinTBSize);
	MapBuffer(m_pCurFrameCB, (void**)&pFrameCB, NULL);


	// 1. group enemy parts into character according cb7_v16.z
	std::multimap<int, int> enemyParts;
	for (auto it = m_CurFrameEnemyDatas.begin(); it != m_CurFrameEnemyDatas.end(); ++it)
	{
		uint32_t cbSize;
		int* pResData;
		MapBuffer(it->pObjectCB, (void**)&pResData, &cbSize);

		// tbufferOffset is unique for a character, so this can group character parts
		int tbufferOffset = pResData[16 * 4 + 2];

		int partIndex = (int)(it - m_CurFrameEnemyDatas.begin());
		if (tbufferOffset >= 0 && (tbufferOffset * 12) < (int)skinTBSize)
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
	for (auto itFirst = enemyParts.begin(); itFirst != enemyParts.end();)
	{
		auto range = enemyParts.equal_range(itFirst->first);

		uint32_t totalIndexCount = 0;
		std::vector<SEnemyDrawData> drawcalls;
		for (auto it = range.first; it != range.second; ++it)
		{
			totalIndexCount += m_CurFrameEnemyDatas[it->second].indexCount;
			drawcalls.push_back(m_CurFrameEnemyDatas[it->second]);
		}

		if (totalIndexCount >= 3000)
		{ // reject enemy equipment
			char refVertRaw[OBJECT_VB_STRIDE];
			Vec3 aabb;
			if (GetReferenceVert(drawcalls, refVertRaw, &aabb))
			{
				SVertData vert(refVertRaw);
				Vec3 skinedVert = SkinVert(vert, pSkinTexBuffer, itFirst->first);

				ID3D11Buffer* pObjectCB = m_CurFrameEnemyDatas[itFirst->second].pObjectCB;

				SAimResult res;
				TransformVertToScreenSpace(skinedVert, pObjectCB, pFrameCB, &res);
				res.id = ((uint32_t)round(aabb.x * 100)) * 1000 + (uint32_t)round(aabb.z * 100);
				m_TargetPos.push_back(res);
			}
		}

		itFirst = range.second;
	}

	UnmapBuffer(m_pCurFrameTexBuffer);
	UnmapBuffer(m_pCurFrameCB);
}

void AutoAimAnalyzer::OnFrameEnd()
{
	++m_CurrFrame;
	m_TargetPos.clear();

	AnalyseEnemyData();

	{
		for (auto it = m_CurFrameAllyDatas.begin(); it != m_CurFrameAllyDatas.end(); ++it)
		{
			uint8_t* pVBBuffer;
			uint32_t VBSize;
			MapBuffer(it->pCachedVB, (void**)&pVBBuffer, &VBSize);

			float* pTexBuffer;
			uint32_t TBSize;
			MapBuffer(it->pCachedTB, (void**)&pTexBuffer, &TBSize);

			uint32_t tex1Offset = it->vbOffset + it->vertexOffset * ALLY_VB_STRIDE + ALLY_TEX1_VB_OFFSET;
			if (tex1Offset + sizeof(uint32_t) <= VBSize)
			{
				uint32_t tex1 = *(uint32_t*) &pVBBuffer[tex1Offset];

				if ((tex1 + 2) * 4 * 4 <= TBSize)
				{
					float xcoord = pTexBuffer[(tex1 + 0) * 4 + 3];
					float ycoord = pTexBuffer[(tex1 + 1) * 4 + 3];

					SAimResult res;
					res.id = -1;
					res.onScreenPos.x = xcoord + 10;
					res.onScreenPos.y = ycoord + 10;
				}
				else
				{
					g_Logger->error("AutoAimAnalyzer::OnFrameEnd ally TB out of range {} {}",
									tex1Offset, TBSize);

				}
			}
			else
			{
				g_Logger->error("AutoAimAnalyzer::OnFrameEnd ally VB out of range {} {} {}", 
								it->vbOffset, it->vertexOffset, VBSize);
			}

			UnmapBuffer(it->pCachedVB);
			UnmapBuffer(it->pCachedTB);
		}
	}

	ClearFrameData();
}

void AutoAimAnalyzer::ClearFrameData()
{
	SAFE_RELEASE(m_pCurFrameTexBuffer);
	SAFE_RELEASE(m_pCurFrameCB);
	for (auto it = m_CurFrameEnemyDatas.begin(); it != m_CurFrameEnemyDatas.end(); ++it)
	{
		SAFE_RELEASE(it->pObjectCB);
	}
	m_CurFrameEnemyDatas.clear();

	for (auto it = m_FrameCachedVBData.begin(); it != m_FrameCachedVBData.end(); ++it)
	{
		it->first->Release();
		SAFE_RELEASE(it->second);
	}
	m_FrameCachedVBData.clear();

	m_CurFrameAllyDatas.clear();
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

		if (m_CachedVBData.size() > 128)
		{
			for (auto it = m_CachedVBData.begin(); it != m_CachedVBData.end(); )
			{
				if (it->second.lastAccessFrame + 60 * 60 * 10 < m_CurrFrame)
				{
					it->first->Release();
					SAFE_RELEASE(it->second.pStageBuffer);
					it = m_CachedVBData.erase(it);
				}
				else
				{
					++it;
				}
			}
		}
	}

	m_CachedVBData[pVB].lastAccessFrame = m_CurrFrame;
	return &m_CachedVBData[pVB];
}

ID3D11Buffer* AutoAimAnalyzer::GetFrameCachedBufferData(ID3D11Buffer* pVB)
{
	if (m_FrameCachedVBData.find(pVB) == m_FrameCachedVBData.end())
	{
		m_FrameCachedVBData[pVB] = CopyBufferToCpu(pVB);
		pVB->AddRef();
	}

	return m_FrameCachedVBData[pVB];
}

void AutoAimAnalyzer::MapBuffer(ID3D11Buffer* pStageBuffer, void** ppData, uint32_t* pByteWidth)
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
