#pragma once
#include <capstone.h>
#include "CommonUtils.h"

#ifdef min
#undef min
#endif

#include <asmjit/asmjit.h>

extern asmjit::JitRuntime* g_JIT;         // Runtime specialized for JIT code execution.

x86_reg UnifyReg(x86_reg input);

int GetRegSize(x86_reg input);

const asmjit::X86Gp& ToJitReg(x86_reg input);

x86_reg GetUnifiedReg(cs_x86* x86, int regId);

void LogInstructionDetail(spdlog::level::level_enum level, cs_insn* pInsn);


struct PrologueJmpPatch
{
	uint64_t* jmpTargetAddr;
	uint64_t  oldJmpTarget;
	uint64_t  newJmpTarget;

	PrologueJmpPatch() : oldJmpTarget(0), newJmpTarget(0), jmpTargetAddr(NULL) {}
};

bool GenerateRestoreCode(uint8_t* pFuncAddr, int codeSize, uint8_t* jmpAddrAfterRestore,
						 uint8_t** ppRestoreCode, uint32_t* pRestoreCodeSize, 
						 PrologueJmpPatch* jmpPatch);
