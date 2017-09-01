cbuffer Constant : register(b0)
{
	float4 TargetPos[64]: packoffset(c0.x);
	float  triangleSize : packoffset(c64.x);
	float2 screenSize   : packoffset(c64.y);
	uint   selectId     : packoffset(c64.w);
};

struct VS_OUTPUT
{
	float4 Pos : SV_Position;
	uint   id  : TEXCOORD0;
};

VS_OUTPUT VS(uint vertId : SV_VertexID)
{
	float2 offset;
	if (vertId % 3 == 0)
		offset = 0;
	else if (vertId % 3 == 1)
		offset = float2(-triangleSize / screenSize.x, +triangleSize / screenSize.y);
	else if (vertId % 3 == 2)
		offset = float2(+triangleSize / screenSize.x, +triangleSize / screenSize.y);
		
	float2 Tex = TargetPos[vertId / 3].xy + offset;
	
	VS_OUTPUT o;
	o.Pos = float4(Tex.x * 2.0 - 1.0, 1.0 -  Tex.y * 2.0, 0, 1);
	o.id  = vertId / 3;
	
	return o;
}

float4 PS(VS_OUTPUT i) : SV_Target0
{
	if (i.id == selectId)
		return float4(1, 0, 0, 1);
	else
		return float4(0, 1, 0, 1);
}
