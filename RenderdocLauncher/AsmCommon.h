#pragma once
#include <capstone.h>

#ifdef min
#undef min
#endif

#include <asmjit/asmjit.h>

extern asmjit::JitRuntime* g_JIT;         // Runtime specialized for JIT code execution.

x86_reg UnifyReg(x86_reg input);

int GetRegSize(x86_reg input);

const asmjit::X86Gp& ToJitReg(x86_reg input);

x86_reg GetUnifiedReg(cs_x86* x86, int regId);

bool GenerateRestoreCode(uint8_t* pFuncAddr, int codeSize,
						 uint8_t** ppRestoreCode, uint32_t* pRestoreCodeSize);
