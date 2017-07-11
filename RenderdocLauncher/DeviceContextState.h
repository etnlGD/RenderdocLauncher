#pragma once
#include <d3d11.h>

namespace rdcboost
{
	struct SDeviceContextState
	{
		enum {
			eCBCount = D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT,
			eSamplerCount = D3D11_COMMONSHADER_SAMPLER_SLOT_COUNT,
			eSRVCount = D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT,
			eVBCount = D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT,
			eSOTargetCount = D3D11_SO_BUFFER_SLOT_COUNT,
			eViewportCount = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE,
			eRTVCount = D3D11_SIMULTANEOUS_RENDER_TARGET_COUNT,
			eUAVCount = D3D11_1_UAV_SLOT_COUNT,
		};

		template <typename TShader>
		struct SShaderStageState
		{
			ID3D11Buffer* m_pConstantBuffers[eCBCount];
			ID3D11SamplerState* m_pSamplers[eSamplerCount];
			ID3D11ShaderResourceView* m_pSRViews[eSRVCount];
			TShader* m_pShader;
		};

		SShaderStageState<ID3D11VertexShader> m_VertexShaderState;
		SShaderStageState<ID3D11HullShader> m_HullShaderState;
		SShaderStageState<ID3D11DomainShader> m_DomainShaderState;
		SShaderStageState<ID3D11GeometryShader> m_GeometryShaderState;
		SShaderStageState<ID3D11PixelShader> m_PixelShaderState;
		SShaderStageState<ID3D11ComputeShader> m_ComputeShaderState;
		D3D11_PRIMITIVE_TOPOLOGY m_PrimitiveTopology;
		ID3D11Buffer* m_pVertexBuffers[eVBCount];
		UINT m_VertexBufferStrides[eVBCount];
		UINT m_VertexBufferOffsets[eVBCount];
		ID3D11InputLayout* m_pInputLayout;
		ID3D11Buffer* m_pIndexBuffer;
		DXGI_FORMAT m_IndexFormat;
		UINT m_IndexOffset;

		UINT m_SOOffsets[eSOTargetCount];
		ID3D11Buffer* m_pSOTargets[eSOTargetCount];

		ID3D11RasterizerState* m_pRasterizerState;
		D3D11_RECT m_ScissorRects[eViewportCount];
		UINT m_ScissorCount;
		D3D11_VIEWPORT m_Viewports[eViewportCount];
		UINT m_ViewportCount;

		ID3D11BlendState* m_pBlendState;
		FLOAT m_BlendFactor[4];
		UINT m_SampleMask;
		ID3D11DepthStencilState* m_pDepthStencilState;
		UINT m_StencilRef;
		ID3D11DepthStencilView* m_pDepthStencilView;
		ID3D11RenderTargetView* m_pRenderTargetViews[eRTVCount];
		ID3D11UnorderedAccessView* m_pUnorderedAccessViews[eUAVCount];

		ID3D11UnorderedAccessView* m_pCSUnorderedAccessViews[eUAVCount];

		SDeviceContextState();

		~SDeviceContextState();

		void GetFromContext(ID3D11DeviceContext* ctx, UINT* SOOffsets);

		void SetToContext(ID3D11DeviceContext* ctx) const;

	private:
		SDeviceContextState(const SDeviceContextState&);
		SDeviceContextState& operator=(const SDeviceContextState&);
	};
}

