#include "DeviceContextState.h"
#include "CommonUtils.h"
#include <stddef.h>

namespace rdcboost
{
	SDeviceContextState::SDeviceContextState()
	{
		static_assert(offsetof(SDeviceContextState, m_VertexShaderState) == 0, 
					  "this class can't have virtual functions, or memset will cause error");

		memset(this, 0, sizeof(SDeviceContextState));
	}

	SDeviceContextState::~SDeviceContextState()
	{
		for (int i = 0; i < eCBCount; ++i)
		{
			SAFE_RELEASE(m_VertexShaderState.m_pConstantBuffers[i]);
			SAFE_RELEASE(m_HullShaderState.m_pConstantBuffers[i]);
			SAFE_RELEASE(m_DomainShaderState.m_pConstantBuffers[i]);
			SAFE_RELEASE(m_GeometryShaderState.m_pConstantBuffers[i]);
			SAFE_RELEASE(m_PixelShaderState.m_pConstantBuffers[i]);
			SAFE_RELEASE(m_ComputeShaderState.m_pConstantBuffers[i]);
		}

		for (int i = 0; i < eSamplerCount; ++i)
		{
			SAFE_RELEASE(m_VertexShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_HullShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_DomainShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_GeometryShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_PixelShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_ComputeShaderState.m_pSamplers[i]);
		}

		for (int i = 0; i < eSRVCount; ++i)
		{
			SAFE_RELEASE(m_VertexShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_HullShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_DomainShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_GeometryShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_PixelShaderState.m_pSamplers[i]);
			SAFE_RELEASE(m_ComputeShaderState.m_pSamplers[i]);
		}

		SAFE_RELEASE(m_VertexShaderState.m_pShader);
		SAFE_RELEASE(m_HullShaderState.m_pShader);
		SAFE_RELEASE(m_DomainShaderState.m_pShader);
		SAFE_RELEASE(m_GeometryShaderState.m_pShader);
		SAFE_RELEASE(m_PixelShaderState.m_pShader);
		SAFE_RELEASE(m_ComputeShaderState.m_pShader);

		for (int i = 0; i < eVBCount; ++i)
			SAFE_RELEASE(m_pVertexBuffers[i]);

		SAFE_RELEASE(m_pInputLayout);
		SAFE_RELEASE(m_pIndexBuffer);

		for (int i = 0; i < eSOTargetCount; ++i)
			SAFE_RELEASE(m_pSOTargets[i]);

		SAFE_RELEASE(m_pRasterizerState);
		SAFE_RELEASE(m_pBlendState);
		SAFE_RELEASE(m_pDepthStencilState);
		SAFE_RELEASE(m_pDepthStencilView);
		for (int i = 0; i < eRTVCount; ++i)
			SAFE_RELEASE(m_pRenderTargetViews[i]);

		for (int i = 0; i < eUAVCount; ++i)
		{
			SAFE_RELEASE(m_pUnorderedAccessViews[i]);
			SAFE_RELEASE(m_pCSUnorderedAccessViews[i]);
		}
	}

	void SDeviceContextState::GetFromContext(ID3D11DeviceContext* ctx, UINT* SOOffsets)
	{
		ctx->VSGetConstantBuffers(0, eCBCount, m_VertexShaderState.m_pConstantBuffers);
		ctx->VSGetSamplers(0, eSamplerCount, m_VertexShaderState.m_pSamplers);
		ctx->VSGetShaderResources(0, eSRVCount, m_VertexShaderState.m_pSRViews);
		ctx->VSGetShader(&m_VertexShaderState.m_pShader, NULL, NULL);

		ctx->HSGetConstantBuffers(0, eCBCount, m_HullShaderState.m_pConstantBuffers);
		ctx->HSGetSamplers(0, eSamplerCount, m_HullShaderState.m_pSamplers);
		ctx->HSGetShaderResources(0, eSRVCount, m_HullShaderState.m_pSRViews);
		ctx->HSGetShader(&m_HullShaderState.m_pShader, NULL, NULL);

		ctx->DSGetConstantBuffers(0, eCBCount, m_DomainShaderState.m_pConstantBuffers);
		ctx->DSGetSamplers(0, eSamplerCount, m_DomainShaderState.m_pSamplers);
		ctx->DSGetShaderResources(0, eSRVCount, m_DomainShaderState.m_pSRViews);
		ctx->DSGetShader(&m_DomainShaderState.m_pShader, NULL, NULL);

		ctx->GSGetConstantBuffers(0, eCBCount, m_GeometryShaderState.m_pConstantBuffers);
		ctx->GSGetSamplers(0, eSamplerCount, m_GeometryShaderState.m_pSamplers);
		ctx->GSGetShaderResources(0, eSRVCount, m_GeometryShaderState.m_pSRViews);
		ctx->GSGetShader(&m_GeometryShaderState.m_pShader, NULL, NULL);

		ctx->PSGetConstantBuffers(0, eCBCount, m_PixelShaderState.m_pConstantBuffers);
		ctx->PSGetSamplers(0, eSamplerCount, m_PixelShaderState.m_pSamplers);
		ctx->PSGetShaderResources(0, eSRVCount, m_PixelShaderState.m_pSRViews);
		ctx->PSGetShader(&m_PixelShaderState.m_pShader, NULL, NULL);

		ctx->CSGetConstantBuffers(0, eCBCount, m_ComputeShaderState.m_pConstantBuffers);
		ctx->CSGetSamplers(0, eSamplerCount, m_ComputeShaderState.m_pSamplers);
		ctx->CSGetShaderResources(0, eSRVCount, m_ComputeShaderState.m_pSRViews);
		ctx->CSGetShader(&m_ComputeShaderState.m_pShader, NULL, NULL);

		ctx->IAGetPrimitiveTopology(&m_PrimitiveTopology);
		ctx->IAGetVertexBuffers(0, eVBCount, m_pVertexBuffers,
								m_VertexBufferStrides, m_VertexBufferOffsets);
		ctx->IAGetInputLayout(&m_pInputLayout);
		ctx->IAGetIndexBuffer(&m_pIndexBuffer, &m_IndexFormat, &m_IndexOffset);

		ctx->SOGetTargets(eSOTargetCount, m_pSOTargets);
		if (SOOffsets)
			memcpy(m_SOOffsets, SOOffsets, sizeof(m_SOOffsets));
		else
			memset(m_SOOffsets, 0, sizeof(m_SOOffsets));

		ctx->RSGetState(&m_pRasterizerState);
		ctx->RSGetScissorRects(&m_ScissorCount, m_ScissorRects);
		ctx->RSGetViewports(&m_ViewportCount, m_Viewports);

		ctx->OMGetBlendState(&m_pBlendState, m_BlendFactor, &m_SampleMask);
		ctx->OMGetDepthStencilState(&m_pDepthStencilState, &m_StencilRef);
		ctx->OMGetRenderTargetsAndUnorderedAccessViews(
			eRTVCount, m_pRenderTargetViews, &m_pDepthStencilView,
			0, eUAVCount, m_pUnorderedAccessViews);

		ctx->CSGetUnorderedAccessViews(0, eUAVCount, m_pCSUnorderedAccessViews);
	}

	void SDeviceContextState::SetToContext(ID3D11DeviceContext* ctx) const
	{
		ctx->VSSetConstantBuffers(0, eCBCount, m_VertexShaderState.m_pConstantBuffers);
		ctx->VSSetSamplers(0, eSamplerCount, m_VertexShaderState.m_pSamplers);
		ctx->VSSetShaderResources(0, eSRVCount, m_VertexShaderState.m_pSRViews);
		ctx->VSSetShader(m_VertexShaderState.m_pShader, NULL, 0);

		ctx->HSSetConstantBuffers(0, eCBCount, m_HullShaderState.m_pConstantBuffers);
		ctx->HSSetSamplers(0, eSamplerCount, m_HullShaderState.m_pSamplers);
		ctx->HSSetShaderResources(0, eSRVCount, m_HullShaderState.m_pSRViews);
		ctx->HSSetShader(m_HullShaderState.m_pShader, NULL, 0);

		ctx->DSSetConstantBuffers(0, eCBCount, m_DomainShaderState.m_pConstantBuffers);
		ctx->DSSetSamplers(0, eSamplerCount, m_DomainShaderState.m_pSamplers);
		ctx->DSSetShaderResources(0, eSRVCount, m_DomainShaderState.m_pSRViews);
		ctx->DSSetShader(m_DomainShaderState.m_pShader, NULL, 0);

		ctx->GSSetConstantBuffers(0, eCBCount, m_GeometryShaderState.m_pConstantBuffers);
		ctx->GSSetSamplers(0, eSamplerCount, m_GeometryShaderState.m_pSamplers);
		ctx->GSSetShaderResources(0, eSRVCount, m_GeometryShaderState.m_pSRViews);
		ctx->GSSetShader(m_GeometryShaderState.m_pShader, NULL, 0);

		ctx->PSSetConstantBuffers(0, eCBCount, m_PixelShaderState.m_pConstantBuffers);
		ctx->PSSetSamplers(0, eSamplerCount, m_PixelShaderState.m_pSamplers);
		ctx->PSSetShaderResources(0, eSRVCount, m_PixelShaderState.m_pSRViews);
		ctx->PSSetShader(m_PixelShaderState.m_pShader, NULL, 0);

		ctx->CSSetConstantBuffers(0, eCBCount, m_ComputeShaderState.m_pConstantBuffers);
		ctx->CSSetSamplers(0, eSamplerCount, m_ComputeShaderState.m_pSamplers);
		ctx->CSSetShaderResources(0, eSRVCount, m_ComputeShaderState.m_pSRViews);
		ctx->CSSetShader(m_ComputeShaderState.m_pShader, NULL, 0);

		ctx->IASetPrimitiveTopology(m_PrimitiveTopology);
		ctx->IASetVertexBuffers(0, eVBCount, m_pVertexBuffers,
								m_VertexBufferStrides, m_VertexBufferOffsets);
		ctx->IASetInputLayout(m_pInputLayout);
		ctx->IASetIndexBuffer(m_pIndexBuffer, m_IndexFormat, m_IndexOffset);

		ctx->SOSetTargets(eSOTargetCount, m_pSOTargets, m_SOOffsets);

		ctx->RSSetState(m_pRasterizerState);
		ctx->RSSetScissorRects(m_ScissorCount, m_ScissorRects);
		ctx->RSSetViewports(m_ViewportCount, m_Viewports);

		ctx->OMSetBlendState(m_pBlendState, m_BlendFactor, m_SampleMask);
		ctx->OMSetDepthStencilState(m_pDepthStencilState, m_StencilRef);

		// -1 indicates to keep the current offset.
		UINT UAVInitialCounts[eUAVCount];
		memset(UAVInitialCounts, -1, sizeof(UAVInitialCounts));

		ctx->OMSetRenderTargets(eRTVCount, m_pRenderTargetViews, m_pDepthStencilView);
		// TODO_wzq 这个函数不能乱调
// 		ctx->OMSetRenderTargetsAndUnorderedAccessViews(
// 			eRTVCount, m_pRenderTargetViews, m_pDepthStencilView,
// 			0, eUAVCount, m_pUnorderedAccessViews, UAVInitialCounts);
		ctx->CSSetUnorderedAccessViews(0, eUAVCount, m_pCSUnorderedAccessViews, UAVInitialCounts);
	}
}

