#if 0
//
// Generated by Microsoft (R) HLSL Shader Compiler 9.29.952.3111
//
//
//   fxc /Tvs_5_0 shader_src\DrawTarget.hlsl /EVS /Fh shader_obj\DrawTargetVS.h
//    /Vn g_VSDrawTarget
//
//
// Buffer Definitions: 
//
// cbuffer Constant
// {
//
//   float4 TargetPos[64];              // Offset:    0 Size:  1024
//   float triangleSize;                // Offset: 1024 Size:     4
//   float2 screenSize;                 // Offset: 1028 Size:     8
//   uint selectId;                     // Offset: 1036 Size:     4 [unused]
//
// }
//
//
// Resource Bindings:
//
// Name                                 Type  Format         Dim Slot Elements
// ------------------------------ ---------- ------- ----------- ---- --------
// Constant                          cbuffer      NA          NA    0        1
//
//
//
// Input signature:
//
// Name                 Index   Mask Register SysValue Format   Used
// -------------------- ----- ------ -------- -------- ------ ------
// SV_VertexID              0   x           0   VERTID   uint   x   
//
//
// Output signature:
//
// Name                 Index   Mask Register SysValue Format   Used
// -------------------- ----- ------ -------- -------- ------ ------
// SV_Position              0   xyzw        0      POS  float   xyzw
// TEXCOORD                 0   x           1     NONE   uint   x   
//
vs_5_0
dcl_globalFlags refactoringAllowed
dcl_constantbuffer cb0[65], dynamicIndexed
dcl_input_sgv v0.x, vertex_id
dcl_output_siv o0.xyzw, position
dcl_output o1.x
dcl_temps 3
div r0.x, -cb0[64].x, cb0[64].y
div r0.yz, cb0[64].xxxx, cb0[64].zzyz
udiv r1.x, r2.x, v0.x, l(3)
ieq r0.w, r2.x, l(1)
movc r0.xy, r0.wwww, r0.xyxx, r0.zyzz
movc r0.xy, r2.xxxx, r0.xyxx, l(0,0,0,0)
add r0.xy, r0.xyxx, cb0[r1.x + 0].xyxx
mov o1.x, r1.x
mad o0.x, r0.x, l(2.000000), l(-1.000000)
mad o0.y, -r0.y, l(2.000000), l(1.000000)
mov o0.zw, l(0,0,0,1.000000)
ret 
// Approximately 12 instruction slots used
#endif

const BYTE g_VSDrawTarget[] =
{
     68,  88,  66,  67,  80, 145, 
     62, 148, 157, 174, 125, 213, 
    247, 120, 120, 221, 107,  91, 
    231,  14,   1,   0,   0,   0, 
    116,   5,   0,   0,   5,   0, 
      0,   0,  52,   0,   0,   0, 
    108,   2,   0,   0, 160,   2, 
      0,   0, 248,   2,   0,   0, 
    216,   4,   0,   0,  82,  68, 
     69,  70,  48,   2,   0,   0, 
      1,   0,   0,   0, 104,   0, 
      0,   0,   1,   0,   0,   0, 
     60,   0,   0,   0,   0,   5, 
    254, 255,   0,   1,   0,   0, 
    252,   1,   0,   0,  82,  68, 
     49,  49,  60,   0,   0,   0, 
     24,   0,   0,   0,  32,   0, 
      0,   0,  40,   0,   0,   0, 
     36,   0,   0,   0,  12,   0, 
      0,   0,   0,   0,   0,   0, 
     92,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,   1,   0, 
      0,   0,  67, 111, 110, 115, 
    116,  97, 110, 116,   0, 171, 
    171, 171,  92,   0,   0,   0, 
      4,   0,   0,   0, 128,   0, 
      0,   0,  16,   4,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,  32,   1,   0,   0, 
      0,   0,   0,   0,   0,   4, 
      0,   0,   2,   0,   0,   0, 
     52,   1,   0,   0,   0,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0, 255, 255, 
    255, 255,   0,   0,   0,   0, 
     88,   1,   0,   0,   0,   4, 
      0,   0,   4,   0,   0,   0, 
      2,   0,   0,   0, 108,   1, 
      0,   0,   0,   0,   0,   0, 
    255, 255, 255, 255,   0,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0, 144,   1, 
      0,   0,   4,   4,   0,   0, 
      8,   0,   0,   0,   2,   0, 
      0,   0, 164,   1,   0,   0, 
      0,   0,   0,   0, 255, 255, 
    255, 255,   0,   0,   0,   0, 
    255, 255, 255, 255,   0,   0, 
      0,   0, 200,   1,   0,   0, 
     12,   4,   0,   0,   4,   0, 
      0,   0,   0,   0,   0,   0, 
    216,   1,   0,   0,   0,   0, 
      0,   0, 255, 255, 255, 255, 
      0,   0,   0,   0, 255, 255, 
    255, 255,   0,   0,   0,   0, 
     84,  97, 114, 103, 101, 116, 
     80, 111, 115,   0, 102, 108, 
    111,  97, 116,  52,   0, 171, 
    171, 171,   1,   0,   3,   0, 
      1,   0,   4,   0,  64,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,  42,   1, 
      0,   0, 116, 114, 105,  97, 
    110, 103, 108, 101,  83, 105, 
    122, 101,   0, 102, 108, 111, 
     97, 116,   0, 171,   0,   0, 
      3,   0,   1,   0,   1,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
    101,   1,   0,   0, 115,  99, 
    114, 101, 101, 110,  83, 105, 
    122, 101,   0, 102, 108, 111, 
     97, 116,  50,   0, 171, 171, 
      1,   0,   3,   0,   1,   0, 
      2,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0, 155,   1,   0,   0, 
    115, 101, 108, 101,  99, 116, 
     73, 100,   0, 100, 119, 111, 
    114, 100,   0, 171,   0,   0, 
     19,   0,   1,   0,   1,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
    209,   1,   0,   0,  77, 105, 
     99, 114, 111, 115, 111, 102, 
    116,  32,  40,  82,  41,  32, 
     72,  76,  83,  76,  32,  83, 
    104,  97, 100, 101, 114,  32, 
     67, 111, 109, 112, 105, 108, 
    101, 114,  32,  57,  46,  50, 
     57,  46,  57,  53,  50,  46, 
     51,  49,  49,  49,   0, 171, 
    171, 171,  73,  83,  71,  78, 
     44,   0,   0,   0,   1,   0, 
      0,   0,   8,   0,   0,   0, 
     32,   0,   0,   0,   0,   0, 
      0,   0,   6,   0,   0,   0, 
      1,   0,   0,   0,   0,   0, 
      0,   0,   1,   1,   0,   0, 
     83,  86,  95,  86, 101, 114, 
    116, 101, 120,  73,  68,   0, 
     79,  83,  71,  78,  80,   0, 
      0,   0,   2,   0,   0,   0, 
      8,   0,   0,   0,  56,   0, 
      0,   0,   0,   0,   0,   0, 
      1,   0,   0,   0,   3,   0, 
      0,   0,   0,   0,   0,   0, 
     15,   0,   0,   0,  68,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   1,   0, 
      0,   0,   1,   0,   0,   0, 
      1,  14,   0,   0,  83,  86, 
     95,  80, 111, 115, 105, 116, 
    105, 111, 110,   0,  84,  69, 
     88,  67,  79,  79,  82,  68, 
      0, 171, 171, 171,  83,  72, 
     69,  88, 216,   1,   0,   0, 
     80,   0,   1,   0, 118,   0, 
      0,   0, 106,   8,   0,   1, 
     89,   8,   0,   4,  70, 142, 
     32,   0,   0,   0,   0,   0, 
     65,   0,   0,   0,  96,   0, 
      0,   4,  18,  16,  16,   0, 
      0,   0,   0,   0,   6,   0, 
      0,   0, 103,   0,   0,   4, 
    242,  32,  16,   0,   0,   0, 
      0,   0,   1,   0,   0,   0, 
    101,   0,   0,   3,  18,  32, 
     16,   0,   1,   0,   0,   0, 
    104,   0,   0,   2,   3,   0, 
      0,   0,  14,   0,   0,  10, 
     18,   0,  16,   0,   0,   0, 
      0,   0,  10, 128,  32, 128, 
     65,   0,   0,   0,   0,   0, 
      0,   0,  64,   0,   0,   0, 
     26, 128,  32,   0,   0,   0, 
      0,   0,  64,   0,   0,   0, 
     14,   0,   0,   9,  98,   0, 
     16,   0,   0,   0,   0,   0, 
      6, 128,  32,   0,   0,   0, 
      0,   0,  64,   0,   0,   0, 
    166, 137,  32,   0,   0,   0, 
      0,   0,  64,   0,   0,   0, 
     78,   0,   0,   9,  18,   0, 
     16,   0,   1,   0,   0,   0, 
     18,   0,  16,   0,   2,   0, 
      0,   0,  10,  16,  16,   0, 
      0,   0,   0,   0,   1,  64, 
      0,   0,   3,   0,   0,   0, 
     32,   0,   0,   7, 130,   0, 
     16,   0,   0,   0,   0,   0, 
     10,   0,  16,   0,   2,   0, 
      0,   0,   1,  64,   0,   0, 
      1,   0,   0,   0,  55,   0, 
      0,   9,  50,   0,  16,   0, 
      0,   0,   0,   0, 246,  15, 
     16,   0,   0,   0,   0,   0, 
     70,   0,  16,   0,   0,   0, 
      0,   0, 102,  10,  16,   0, 
      0,   0,   0,   0,  55,   0, 
      0,  12,  50,   0,  16,   0, 
      0,   0,   0,   0,   6,   0, 
     16,   0,   2,   0,   0,   0, 
     70,   0,  16,   0,   0,   0, 
      0,   0,   2,  64,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   9,  50,   0,  16,   0, 
      0,   0,   0,   0,  70,   0, 
     16,   0,   0,   0,   0,   0, 
     70, 128,  32,   4,   0,   0, 
      0,   0,  10,   0,  16,   0, 
      1,   0,   0,   0,  54,   0, 
      0,   5,  18,  32,  16,   0, 
      1,   0,   0,   0,  10,   0, 
     16,   0,   1,   0,   0,   0, 
     50,   0,   0,   9,  18,  32, 
     16,   0,   0,   0,   0,   0, 
     10,   0,  16,   0,   0,   0, 
      0,   0,   1,  64,   0,   0, 
      0,   0,   0,  64,   1,  64, 
      0,   0,   0,   0, 128, 191, 
     50,   0,   0,  10,  34,  32, 
     16,   0,   0,   0,   0,   0, 
     26,   0,  16, 128,  65,   0, 
      0,   0,   0,   0,   0,   0, 
      1,  64,   0,   0,   0,   0, 
      0,  64,   1,  64,   0,   0, 
      0,   0, 128,  63,  54,   0, 
      0,   8, 194,  32,  16,   0, 
      0,   0,   0,   0,   2,  64, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0, 128,  63, 
     62,   0,   0,   1,  83,  84, 
     65,  84, 148,   0,   0,   0, 
     12,   0,   0,   0,   3,   0, 
      0,   0,   0,   0,   0,   0, 
      3,   0,   0,   0,   3,   0, 
      0,   0,   1,   0,   0,   0, 
      0,   0,   0,   0,   1,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   2,   0, 
      0,   0,   2,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0,   0,   0, 
      0,   0,   0,   0
};
