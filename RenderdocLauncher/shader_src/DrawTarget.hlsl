cbuffer Constant : register(b0)
{
	float4 TargetPos[64];
};

float4 VS(uint vertId : SV_VertexID) : SV_Position
{
	float2 offset;
	if (vertId % 3 == 0)
		offset = 0;
	else if (vertId % 3 == 1)
		offset = float2(16.0 / 1920.0, 16.0 / 1080.0);
	else if (vertId % 3 == 2)
		offset = float2(-16.0 / 1920.0, -16.0 / 1080.0);
		
	float2 Tex = TargetPos[vertId / 3] + offset;
	float4 Pos = float4(Tex.x * 2.0 - 1.0, 1.0 -  Tex.y * 2.0, 0, 1);
	
	return Pos;
}

float4 PS() : SV_Target0
{
	return float4(0, 1, 0, 1);
}
