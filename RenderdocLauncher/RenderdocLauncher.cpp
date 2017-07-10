#include "RenderdocLauncher.h"
#include "CommonUtils.h"

#include <cstdio>
#include <d3d11.h>

#include "PolyHook/PolyHook.hpp"
#include <vector>
#include <string>
#include <stdint.h>
#include <map>
#include <ShlObj.h>
#include <stack>

#undef min
#include <asmjit/asmjit.h>
#include "AutoAimAnalyzer.h"

static bool g_RenderdocMode = true;
static bool g_DebugMode = false;

static asmjit::JitRuntime* g_JIT;         // Runtime specialized for JIT code execution.


int WINAPI CreateDirect3D11DeviceFromDXGIDevice() { printf("CreateDirect3D11DeviceFromDXGIDevice"); return 0; }
int WINAPI CreateDirect3D11SurfaceFromDXGISurface() { printf("CreateDirect3D11SurfaceFromDXGISurface"); return 0; }
int WINAPI D3D11CoreCreateDevice() { printf("D3D11CoreCreateDevice"); return 0; }
int WINAPI D3D11CoreCreateLayeredDevice() { printf("D3D11CoreCreateLayeredDevice"); return 0; }
int WINAPI D3D11CoreGetLayeredDeviceSize() { printf("D3D11CoreGetLayeredDeviceSize"); return 0; }
int WINAPI D3D11CoreRegisterLayers() { printf("D3D11CoreRegisterLayers"); return 0; }
int WINAPI D3D11CreateDevice() { printf("D3D11CreateDevice"); return 0; }
int WINAPI D3D11CreateDeviceAndSwapChain() { printf("D3D11CreateDeviceAndSwapChain"); return 0; }
int WINAPI D3D11CreateDeviceForD3D12() { printf("D3D11CreateDeviceForD3D12"); return 0; }
int WINAPI D3D11On12CreateDevice() { printf("D3D11On12CreateDevice"); return 0; }
int WINAPI D3DKMTCloseAdapter() { printf("D3DKMTCloseAdapter"); return 0; }
int WINAPI D3DKMTCreateAllocation() { printf("D3DKMTCreateAllocation"); return 0; }
int WINAPI D3DKMTCreateContext() { printf("D3DKMTCreateContext"); return 0; }
int WINAPI D3DKMTCreateDevice() { printf("D3DKMTCreateDevice"); return 0; }
int WINAPI D3DKMTCreateSynchronizationObject() { printf("D3DKMTCreateSynchronizationObject"); return 0; }
int WINAPI D3DKMTDestroyAllocation() { printf("D3DKMTDestroyAllocation"); return 0; }
int WINAPI D3DKMTDestroyContext() { printf("D3DKMTDestroyContext"); return 0; }
int WINAPI D3DKMTDestroyDevice() { printf("D3DKMTDestroyDevice"); return 0; }
int WINAPI D3DKMTDestroySynchronizationObject() { printf("D3DKMTDestroySynchronizationObject"); return 0; }
int WINAPI D3DKMTEscape() { printf("D3DKMTEscape"); return 0; }
int WINAPI D3DKMTGetContextSchedulingPriority() { printf("D3DKMTGetContextSchedulingPriority"); return 0; }
int WINAPI D3DKMTGetDeviceState() { printf("D3DKMTGetDeviceState"); return 0; }
int WINAPI D3DKMTGetDisplayModeList() { printf("D3DKMTGetDisplayModeList"); return 0; }
int WINAPI D3DKMTGetMultisampleMethodList() { printf("D3DKMTGetMultisampleMethodList"); return 0; }
int WINAPI D3DKMTGetRuntimeData() { printf("D3DKMTGetRuntimeData"); return 0; }
int WINAPI D3DKMTGetSharedPrimaryHandle() { printf("D3DKMTGetSharedPrimaryHandle"); return 0; }
int WINAPI D3DKMTLock() { printf("D3DKMTLock"); return 0; }
int WINAPI D3DKMTOpenAdapterFromHdc() { printf("D3DKMTOpenAdapterFromHdc"); return 0; }
int WINAPI D3DKMTOpenResource() { printf("D3DKMTOpenResource"); return 0; }
int WINAPI D3DKMTPresent() { printf("D3DKMTPresent"); return 0; }
int WINAPI D3DKMTQueryAdapterInfo() { printf("D3DKMTQueryAdapterInfo"); return 0; }
int WINAPI D3DKMTQueryAllocationResidency() { printf("D3DKMTQueryAllocationResidency"); return 0; }
int WINAPI D3DKMTQueryResourceInfo() { printf("D3DKMTQueryResourceInfo"); return 0; }
int WINAPI D3DKMTRender() { printf("D3DKMTRender"); return 0; }
int WINAPI D3DKMTSetAllocationPriority() { printf("D3DKMTSetAllocationPriority"); return 0; }
int WINAPI D3DKMTSetContextSchedulingPriority() { printf("D3DKMTSetContextSchedulingPriority"); return 0; }
int WINAPI D3DKMTSetDisplayMode() { printf("D3DKMTSetDisplayMode"); return 0; }
int WINAPI D3DKMTSetDisplayPrivateDriverFormat() { printf("D3DKMTSetDisplayPrivateDriverFormat"); return 0; }
int WINAPI D3DKMTSetGammaRamp() { printf("D3DKMTSetGammaRamp"); return 0; }
int WINAPI D3DKMTSetVidPnSourceOwner() { printf("D3DKMTSetVidPnSourceOwner"); return 0; }
int WINAPI D3DKMTSignalSynchronizationObject() { printf("D3DKMTSignalSynchronizationObject"); return 0; }
int WINAPI D3DKMTUnlock() { printf("D3DKMTUnlock"); return 0; }
int WINAPI D3DKMTWaitForSynchronizationObject() { printf("D3DKMTWaitForSynchronizationObject"); return 0; }
int WINAPI D3DKMTWaitForVerticalBlankEvent() { printf("D3DKMTWaitForVerticalBlankEvent"); return 0; }
int WINAPI D3DPerformance_BeginEvent() { printf("D3DPerformance_BeginEvent"); return 0; }
int WINAPI D3DPerformance_EndEvent() { printf("D3DPerformance_EndEvent"); return 0; }
int WINAPI D3DPerformance_GetStatus() { printf("D3DPerformance_GetStatus"); return 0; }
int WINAPI D3DPerformance_SetMarker() { printf("D3DPerformance_SetMarker"); return 0; }
int WINAPI EnableFeatureLevelUpgrade() { printf("EnableFeatureLevelUpgrade"); return 0; }
int WINAPI OpenAdapter10() { printf("OpenAdapter10"); return 0; }
int WINAPI OpenAdapter10_2() { printf("OpenAdapter10_2"); return 0; }

x86_reg UnifyReg(x86_reg input)
{
	switch (input)
	{
	case X86_REG_AL:
	case X86_REG_AH:
	case X86_REG_AX:
	case X86_REG_EAX:
	case X86_REG_RAX:
		return X86_REG_RAX;
	case X86_REG_BL:
	case X86_REG_BH:
	case X86_REG_BX:
	case X86_REG_EBX:
	case X86_REG_RBX:
		return X86_REG_RBX;
	case X86_REG_CL:
	case X86_REG_CH:
	case X86_REG_CX:
	case X86_REG_ECX:
	case X86_REG_RCX:
		return X86_REG_RCX;
	case X86_REG_DL:
	case X86_REG_DH:
	case X86_REG_DX:
	case X86_REG_EDX:
	case X86_REG_RDX:
		return X86_REG_RDX;
	case X86_REG_SIL:
	case X86_REG_SI:
	case X86_REG_ESI:
	case X86_REG_RSI:
		return X86_REG_RSI;
	case X86_REG_DIL:
	case X86_REG_DI:
	case X86_REG_EDI:
	case X86_REG_RDI:
		return X86_REG_RDI;
	case X86_REG_BPL:
	case X86_REG_BP:
	case X86_REG_EBP:
	case X86_REG_RBP:
		return X86_REG_RBP;
	case X86_REG_SPL:
	case X86_REG_SP:
	case X86_REG_ESP:
	case X86_REG_RSP:
		return X86_REG_RSP;
// 	case X86_REG_IP:
// 	case X86_REG_EIP:
// 	case X86_REG_RIP:
// 		return X86_REG_RIP;
	case X86_REG_R8B:
	case X86_REG_R8W:
	case X86_REG_R8D:
	case X86_REG_R8:
		return X86_REG_R8;
	case X86_REG_R9B:
	case X86_REG_R9W:
	case X86_REG_R9D:
	case X86_REG_R9:
		return X86_REG_R9;
	case X86_REG_R10B:
	case X86_REG_R10W:
	case X86_REG_R10D:
	case X86_REG_R10:
		return X86_REG_R10;
	case X86_REG_R11B:
	case X86_REG_R11W:
	case X86_REG_R11D:
	case X86_REG_R11:
		return X86_REG_R11;
	case X86_REG_R12B:
	case X86_REG_R12W:
	case X86_REG_R12D:
	case X86_REG_R12:
		return X86_REG_R12;
	case X86_REG_R13B:
	case X86_REG_R13W:
	case X86_REG_R13D:
	case X86_REG_R13:
		return X86_REG_R13;
	case X86_REG_R14B:
	case X86_REG_R14W:
	case X86_REG_R14D:
	case X86_REG_R14:
		return X86_REG_R14;
	case X86_REG_R15B:
	case X86_REG_R15W:
	case X86_REG_R15D:
	case X86_REG_R15:
		return X86_REG_R15;
	default:
		return X86_REG_INVALID;
	}
}


int GetRegSize(x86_reg input)
{
	switch (input)
	{
	case X86_REG_AL:
	case X86_REG_AH:
	case X86_REG_BL:
	case X86_REG_BH:
	case X86_REG_CL:
	case X86_REG_CH:
	case X86_REG_DL:
	case X86_REG_DH:
	case X86_REG_SIL:
	case X86_REG_DIL:
	case X86_REG_BPL:
	case X86_REG_SPL:
	case X86_REG_R8B:
	case X86_REG_R9B:
	case X86_REG_R10B:
	case X86_REG_R11B:
	case X86_REG_R12B:
	case X86_REG_R13B:
	case X86_REG_R14B:
	case X86_REG_R15B:
		return 1;
	case X86_REG_AX:
	case X86_REG_BX:
	case X86_REG_CX:
	case X86_REG_DX:
	case X86_REG_SI:
	case X86_REG_DI:
	case X86_REG_BP:
	case X86_REG_SP:
	case X86_REG_R8W:
	case X86_REG_R9W:
	case X86_REG_R10W:
	case X86_REG_R11W:
	case X86_REG_R12W:
	case X86_REG_R13W:
	case X86_REG_R14W:
	case X86_REG_R15W:
		return 2;
	case X86_REG_EAX:
	case X86_REG_EBX:
	case X86_REG_ECX:
	case X86_REG_EDX:
	case X86_REG_ESI:
	case X86_REG_EDI:
	case X86_REG_EBP:
	case X86_REG_ESP:
	case X86_REG_R8D:
	case X86_REG_R9D:
	case X86_REG_R10D:
	case X86_REG_R11D:
	case X86_REG_R12D:
	case X86_REG_R13D:
	case X86_REG_R14D:
	case X86_REG_R15D:
		return 4;
	case X86_REG_RAX:
	case X86_REG_RBX:
	case X86_REG_RCX:
	case X86_REG_RDX:
	case X86_REG_RSI:
	case X86_REG_RDI:
	case X86_REG_RBP:
	case X86_REG_RSP:
	case X86_REG_R8:
	case X86_REG_R9:
	case X86_REG_R10:
	case X86_REG_R11:
	case X86_REG_R12:
	case X86_REG_R13:
	case X86_REG_R14:
	case X86_REG_R15:
		return 8;
	}

	return 0;
}

const asmjit::X86Gp& ToJitReg(x86_reg input)
{
	using namespace asmjit;
	static X86Gp sInvalid;
	switch (input)
	{
	case X86_REG_AL:
		return x86::al;
	case X86_REG_AH:
		return x86::ah;
	case X86_REG_AX:
		return x86::ax;
	case X86_REG_EAX:
		return x86::eax;
	case X86_REG_RAX:
		return x86::rax;
	case X86_REG_BL:
		return x86::bl;
	case X86_REG_BH:
		return x86::bh;
	case X86_REG_BX:
		return x86::bx;
	case X86_REG_EBX:
		return x86::ebx;
	case X86_REG_RBX:
		return x86::rbx;
	case X86_REG_CL:
		return x86::cl;
	case X86_REG_CH:
		return x86::ch;
	case X86_REG_CX:
		return x86::cx;
	case X86_REG_ECX:
		return x86::ecx;
	case X86_REG_RCX:
		return x86::rcx;
	case X86_REG_DL:
		return x86::dl;
	case X86_REG_DH:
		return x86::dh;
	case X86_REG_DX:
		return x86::dx;
	case X86_REG_EDX:
		return x86::edx;
	case X86_REG_RDX:
		return x86::rdx;
	case X86_REG_SIL:
		return x86::sil;
	case X86_REG_SI:
		return x86::si;
	case X86_REG_ESI:
		return x86::esi;
	case X86_REG_RSI:
		return x86::rsi;
	case X86_REG_DIL:
		return x86::dil;
	case X86_REG_DI:
		return x86::di;
	case X86_REG_EDI:
		return x86::edi;
	case X86_REG_RDI:
		return x86::rdi;
	case X86_REG_BPL:
		return x86::bpl;
	case X86_REG_BP:
		return x86::bp;
	case X86_REG_EBP:
		return x86::ebp;
	case X86_REG_RBP:
		return x86::rbp;
	case X86_REG_SPL:
		return x86::spl;
	case X86_REG_SP:
		return x86::sp;
	case X86_REG_ESP:
		return x86::esp;
	case X86_REG_RSP:
		return x86::rsp;
	case X86_REG_R8B:
		return x86::r8b;
	case X86_REG_R8W:
		return x86::r8w;
	case X86_REG_R8D:
		return x86::r8d;
	case X86_REG_R8:
		return x86::r8;
	case X86_REG_R9B:
		return x86::r9b;
	case X86_REG_R9W:
		return x86::r9w;
	case X86_REG_R9D:
		return x86::r9d;
	case X86_REG_R9:
		return x86::r9;
	case X86_REG_R10B:
		return x86::r10b;
	case X86_REG_R10W:
		return x86::r10w;
	case X86_REG_R10D:
		return x86::r10d;
	case X86_REG_R10:
		return x86::r10;
	case X86_REG_R11B:
		return x86::r11b;
	case X86_REG_R11W:
		return x86::r11w;
	case X86_REG_R11D:
		return x86::r11d;
	case X86_REG_R11:
		return x86::r11;
	case X86_REG_R12B:
		return x86::r12b;
	case X86_REG_R12W:
		return x86::r12w;
	case X86_REG_R12D:
		return x86::r12d;
	case X86_REG_R12:
		return x86::r12;
	case X86_REG_R13B:
		return x86::r13b;
	case X86_REG_R13W:
		return x86::r13w;
	case X86_REG_R13D:
		return x86::r13d;
	case X86_REG_R13:
		return x86::r13;
	case X86_REG_R14B:
		return x86::r14b;
	case X86_REG_R14W:
		return x86::r14w;
	case X86_REG_R14D:
		return x86::r14d;
	case X86_REG_R14:
		return x86::r14;
	case X86_REG_R15B:
		return x86::r15b;
	case X86_REG_R15W:
		return x86::r15w;
	case X86_REG_R15D:
		return x86::r15d;
	case X86_REG_R15:
		return x86::r15;
	default:
		return sInvalid;
	}
}

x86_reg GetUnifiedReg(cs_x86* x86, int regId)
{
	if (x86->op_count > regId && x86->operands[regId].type == X86_OP_REG)
		return UnifyReg(x86->operands[regId].reg);
	return X86_REG_INVALID;
}

static void LogInstructionDetail(spdlog::level::level_enum level, cs_insn* pInsn)
{
	char bytes[64];
	for (int i = 0; i < pInsn->size; ++i)
	{
		sprintf_s(&bytes[i * 3], 4, "%02X ", (uint32_t)pInsn->bytes[i]);
	}
	bytes[pInsn->size * 3] = '\0';

	g_Logger->debug("\t{:<16p} {:<48} {:<8} {}",
				    (void*) pInsn->address, bytes, pInsn->mnemonic, pInsn->op_str);
}

static bool GenerateRestoreCode(uint8_t* pFuncAddr, int codeSize, 
								uint8_t** ppRestoreCode, uint32_t* pRestoreCodeSize)
{
	csh handle;
	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	if (err != CS_ERR_OK)
	{
		g_Logger->error("Capstone initialize failed {}", err);
		return false;
	}

	g_Logger->debug("{:*^128}", "Generating Restore Code");
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	size_t size = codeSize + 16 - 1;
	const uint8_t* pCode = pFuncAddr;
	uint64_t pAddr = (uint64_t)pFuncAddr;

	g_Logger->debug("Original function prologue: ");
	cs_insn* pInstructions;
	size_t count = cs_disasm(handle, pCode, size, pAddr, 0, &pInstructions);
	size_t effectiveInsnCount;
	for (effectiveInsnCount = 0; effectiveInsnCount < count; ++effectiveInsnCount)
	{
		if (codeSize <= 0)
			break;
		codeSize -= pInstructions[effectiveInsnCount].size;
		LogInstructionDetail(spdlog::level::debug, &pInstructions[effectiveInsnCount]);
	}

	// 1. 对栈上数据的修改都不用撤销（除了第四个函数参数之后的参数，得确定下是否有可能直接修改栈上参数）
	// 2. 对非栈上的内存的修改需要还原
	// 3. 对 non-volatile 寄存器的修改需要还原，这个是肯定能够还原的，不然函数调用也会出错 
	// 4. 对 volatile 寄存器的修改不需要还原，包括 RAX, RCX, RDX, R8, R9, R10, XMM0L, XMM1L, XMM2L, XMM3L, XMM4L and XMM5L
// 	struct RegState
// 	{
// 		bool isVolatile;
// 		RegState(bool bIsVolatile) : isVolatile(bIsVolatile) {}
// 	};
// 
// 	std::map<x86_reg, RegState> regs;
// 	regs[X86_REG_RAX] = RegState(true);
// 	regs[X86_REG_RCX] = RegState(false);
// 	regs[X86_REG_RDX] = RegState(false);
// 	regs[X86_REG_R8] = RegState(false);
// 	regs[X86_REG_R9] = RegState(false);
// 	regs[X86_REG_R10] = RegState(true);
// 	regs[X86_REG_R11] = RegState(true);
// 
// 	regs[X86_REG_RBX] = RegState(false);
// 	regs[X86_REG_RSI] = RegState(false);
// 	regs[X86_REG_RDI] = RegState(false);
// 	regs[X86_REG_RBP] = RegState(false);
// 	regs[X86_REG_RSP] = RegState(false);
// 	regs[X86_REG_R12] = RegState(false);
// 	regs[X86_REG_R13] = RegState(false);
// 	regs[X86_REG_R14] = RegState(false);
// 	regs[X86_REG_R15] = RegState(false);

	using namespace asmjit;
	CodeHolder code;                        // Holds code and relocation information.
	code.init(g_JIT->getCodeInfo());        // Initialize to the same arch as JIT runtime.
	X86Assembler assembler(&code);          // Create and attach X86Assembler to `code`.

	int64_t curRSP = 0;
	int64_t curRBP = 0;
	std::stack<std::string> restoreCode;
	for (size_t i = 0; i < effectiveInsnCount; ++i)
	{
		cs_x86* x86 = &pInstructions[i].detail->x86;
		cs_x86_op* ops = x86->operands;

		bool handled = false;
		x86_reg reg0 = GetUnifiedReg(x86, 0);
		x86_reg reg1 = GetUnifiedReg(x86, 1);
		if (strcmp(pInstructions[i].mnemonic, "push") == 0)
		{
			if (x86->op_count == 1 && ops[0].reg == reg0)
			{
				curRSP -= GetRegSize(ops[0].reg);
				assembler.pop(ToJitReg(ops[0].reg));
				handled = true;
			}
		}
		else if (strcmp(pInstructions[i].mnemonic, "mov") == 0)
		{
			if (reg0 != X86_REG_INVALID && reg1 != X86_REG_INVALID)
			{ // move between regs
				// mov ops[1].reg, ops[0].reg
				handled = true;

				if (reg0 == X86_REG_RBP)
				{
					if (reg1 == X86_REG_RSP)
						curRBP = curRSP;
					else
						handled = false;
				}
				
				if (handled)
					assembler.mov(ToJitReg(ops[1].reg), ToJitReg(ops[0].reg));
			}
			else if (x86->op_count > 0 && ops[0].type == X86_OP_MEM)
			{ // save reg into stack
				uint32_t memBase = ops[0].mem.base;
				if ((memBase == X86_REG_RSP || memBase == X86_REG_RBP) && reg1 != X86_REG_INVALID)
				{
					if (ops[0].mem.segment == X86_REG_INVALID && ops[0].mem.index == X86_REG_INVALID)
					{
						int64_t stackPos;
						if (memBase == X86_REG_RSP)
							stackPos = curRSP + ops[0].mem.disp;
						else
							stackPos = curRBP + ops[0].mem.disp - curRSP;

						// mov ops[1].reg, [rsp + stackPos]

						X86Mem mem(x86::rsp, (int32_t)stackPos);
						assembler.mov(ToJitReg(ops[1].reg), mem);
						handled = true;
					}
				}
			}
		}
		else if (strcmp(pInstructions[i].mnemonic, "sub") == 0)
		{ // sub rsp/rbp
			if (x86->op_count > 1 && ops[1].type == X86_OP_IMM)
			{
				// add rsp, imm or add rbp, imm
				if (reg0 == X86_REG_RSP)
				{
					curRSP -= ops[1].imm;
					assembler.add(x86::rsp, ops[1].imm);
					handled = true;
				}
				else if (reg0 == X86_REG_RBP)
				{
					curRBP -= ops[1].imm;
					assembler.add(x86::rbp, ops[1].imm);
					handled = true;
				}
			}
		}
		else if (strcmp(pInstructions[i].mnemonic, "add") == 0)
		{ // add rsp/rbp
			if (x86->op_count > 1 && ops[1].type == X86_OP_IMM)
			{
				// sub rsp, imm or sub rbp, imm
				if (reg0 == X86_REG_RSP)
				{
					curRSP += ops[1].imm;
					assembler.sub(x86::rsp, ops[1].imm);
					handled = true;
				}
				else if (reg0 == X86_REG_RBP)
				{
					curRBP += ops[1].imm;
					assembler.sub(x86::rbp, ops[1].imm);
					handled = true;
				}
			}
		}
		else if (strcmp(pInstructions[i].mnemonic, "lea") == 0)
		{
			if (reg0 != X86_REG_INVALID && reg0 != X86_REG_RBP && reg0 != X86_REG_RSP)
				handled = true;
		}

		if (!handled)
		{
			// log
		}
	}
	cs_free(pInstructions, count);

	void (* pfnVoidFunc)();
	g_JIT->add(&pfnVoidFunc, &code);

	*pRestoreCodeSize = (uint32_t) code.getCodeSize();
	count = cs_disasm(handle, (uint8_t*)pfnVoidFunc, *pRestoreCodeSize, 
					  (uint64_t)pfnVoidFunc, 0, &pInstructions);

	g_Logger->debug("Generated function epilogue: ");
	*ppRestoreCode = new uint8_t[*pRestoreCodeSize];
	for (size_t i = 0, codeOff = 0; i < count; ++i)
	{
		size_t idx = count - i - 1;

		// no rip related instructions, so we can do the copy safely.
		memcpy((*ppRestoreCode) + codeOff, pInstructions[idx].bytes, pInstructions[idx].size);
		codeOff += pInstructions[idx].size;

		LogInstructionDetail(spdlog::level::debug, &pInstructions[idx]);
	}
	cs_free(pInstructions, count);
	g_JIT->release(pfnVoidFunc);

	g_Logger->debug("{:*^128}", "");

	return true;
}

static HMODULE hD3D11 = 0;
static HMODULE hCurrentModule = 0;
static HMODULE hRenderdoc = 0;
static HMODULE hDXGI = 0;
static std::wstring g_HookedProcessName;

struct DetourHookInfo
{
public:
	HMODULE hTargetModule;
	LPCSTR  sTargetFunc;
	FARPROC m_pSourceFunc;
	PLH::Detour* m_pDetour;
	bool m_bInstalledHook;

public:
	DetourHookInfo(HMODULE targetModule, LPCSTR targetFunc, 
				   HMODULE sourceModule, LPCSTR sourceFunc = NULL) :
		hTargetModule(targetModule), sTargetFunc(targetFunc),
		m_pDetour(new PLH::Detour), m_bInstalledHook(false)
	{
		if (sourceFunc == NULL)
			sourceFunc = targetFunc;

		m_pSourceFunc = (FARPROC)GetProcAddress(sourceModule, sourceFunc);
	}

	DetourHookInfo(HMODULE targetModule, LPCSTR targetFunc,
				   FARPROC pSourceFunc) :
				   hTargetModule(targetModule), sTargetFunc(targetFunc),
				   m_pSourceFunc(pSourceFunc),
				   m_pDetour(new PLH::Detour), m_bInstalledHook(false)
	{
	}

	void HackOverwatch(uint8_t* pTargetFunc)
	{
		if (hTargetModule == hD3D11 || hTargetModule == hDXGI)
		{
			uint8_t* restoreCode;
			uint32_t restoreCodeSize;
			GenerateRestoreCode(pTargetFunc, 32, &restoreCode, &restoreCodeSize);
			m_pDetour->m_PreserveSize = 32;
			m_pDetour->m_RestoreCode = restoreCode;
			m_pDetour->m_RestoreCodeSize = restoreCodeSize;
		}
	}

	bool InstallHook()
	{
		uint8_t* pTargetFunc = (uint8_t*)GetProcAddress(hTargetModule, sTargetFunc);

		WCHAR targetModulePath[MAX_PATH];
		GetModuleFileName(hTargetModule, targetModulePath, MAX_PATH);
		if (pTargetFunc == NULL)
		{
			g_Logger->warn("can't find proc address of {}!{}", w2s(targetModulePath), sTargetFunc);
			return false;
		}

		if (m_pSourceFunc == NULL)
		{
			return false;
		}

		// Overwatch checks top 32 bytes of these functions, so do some hack.
		if (g_DebugMode || g_HookedProcessName.find(L"overwatch.exe") != std::wstring::npos)
			HackOverwatch(pTargetFunc);
		
		m_pDetour->SetupHook(pTargetFunc, (uint8_t*) m_pSourceFunc);
		m_bInstalledHook = m_pDetour->Hook();
		if (!m_bInstalledHook)
		{
			g_Logger->warn("Detour function {}!{} from {:p} to {:p} failed",
						   w2s(targetModulePath), sTargetFunc, 
						   (void*) pTargetFunc, (void*) m_pSourceFunc);
		}
		else
		{
			g_Logger->debug("Detour function {}!{} from {:p} to {:p} succeed",
						    w2s(targetModulePath), sTargetFunc,
						    (void*)pTargetFunc, (void*)m_pSourceFunc);
		}

		return m_bInstalledHook;
	}

	FARPROC GetOriginal()
	{
		return m_bInstalledHook ? 
			m_pDetour->GetOriginal<FARPROC>() : GetProcAddress(hTargetModule, sTargetFunc);
	}
};
std::vector<DetourHookInfo> sDetourHooks;

// // 保证 Renderdoc 始终调用真正的 d3d11 API
static PLH::IATHook* pGetProcAddressHook;
static FARPROC WINAPI Hooked_GetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName)
{
	if (hModule == hCurrentModule)
	{
		hModule = hD3D11;
	}

	for (auto it = sDetourHooks.begin(); it != sDetourHooks.end(); ++it)
	{
		if (hModule == it->hTargetModule && strcmp(it->sTargetFunc, lpProcName) == 0)
			return it->GetOriginal();
	}

	return GetProcAddress(hModule, lpProcName);
}

static bool InstallRenderdocIATHook()
{
	// 保证 Renderdoc 始终调用真正的 d3d11 API
	pGetProcAddressHook = new PLH::IATHook;
	pGetProcAddressHook->SetupHook("kernel32.dll", "GetProcAddress",
								   (uint8_t*)&Hooked_GetProcAddress, "renderdoc.dll");
	if (!pGetProcAddressHook->Hook())
	{
		g_Logger->error("Hook renderdoc.dll GetProcAddress failed");
		return false;
	}

	typedef void (__cdecl *tRENDERDOC_CreateHooks) (UINT Flags);

	tRENDERDOC_CreateHooks pfnCreateHooks = 
		(tRENDERDOC_CreateHooks) GetProcAddress(hRenderdoc, "RENDERDOC_CreateHooks");

	if (pfnCreateHooks == NULL)
	{
		g_Logger->error("GetProcAddress: RENDERDOC_CreateHooks failed, are you using official renderdoc ?");
		return false;
	}
	else
	{
		pfnCreateHooks(1);
	}

	return true;
}

std::map<ID3D11DeviceContext*, PLH::Detour*> ContextUsingDetours;
std::vector<PLH::Detour*> AllDrawIndexedDetours;
typedef void (STDMETHODCALLTYPE *tDrawIndexed) (ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);
typedef void (STDMETHODCALLTYPE *tOMSetDepthStencilState) (ID3D11DeviceContext* pContext, ID3D11DepthStencilState *pDepthStencilState, UINT StencilRef);
typedef void (STDMETHODCALLTYPE *tSetPredication) (ID3D11DeviceContext* pContext, ID3D11Predicate *pPredicate, BOOL PredicateValue);

static void HookD3D11DeviceContext(ID3D11DeviceContext* pContext);

static void STDMETHODCALLTYPE Hooked_DrawIndexed(ID3D11DeviceContext* pContext, 
		UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation)
{
	bool isOutlinePass = false;
	UINT stencilRef = 0;
	ID3D11DepthStencilState* pDepthStencilState = NULL;

	if (g_DebugMode || g_HookedProcessName.find(L"overwatch.exe") != std::wstring::npos)
	{
		pContext->OMGetDepthStencilState(&pDepthStencilState, &stencilRef);
		if (pDepthStencilState != NULL && stencilRef == 0x10)
		{
			D3D11_DEPTH_STENCIL_DESC Desc;
			pDepthStencilState->GetDesc(&Desc);
			if (Desc.DepthEnable == TRUE && Desc.DepthFunc == D3D11_COMPARISON_LESS_EQUAL &&
				Desc.StencilEnable == TRUE && Desc.StencilWriteMask == 0x10 &&
				Desc.StencilReadMask == 0x00 &&
				Desc.FrontFace.StencilFunc == D3D11_COMPARISON_ALWAYS &&
				Desc.BackFace.StencilFunc == D3D11_COMPARISON_ALWAYS)
			{
				isOutlinePass = true;

				Desc.DepthFunc = D3D11_COMPARISON_ALWAYS;

				ID3D11Device* pDevice;
				ID3D11DepthStencilState* pHackedDepthStencilState;
				pContext->GetDevice(&pDevice);
				pDevice->CreateDepthStencilState(&Desc, &pHackedDepthStencilState);

				pContext->OMSetDepthStencilState(pHackedDepthStencilState, stencilRef);

				pHackedDepthStencilState->Release();
				pDevice->Release();
			}
		}
	}
	
	auto itContext = ContextUsingDetours.find(pContext);
	if (itContext == ContextUsingDetours.end())
	{
		HookD3D11DeviceContext(pContext);
		itContext = ContextUsingDetours.find(pContext);
	}

	tDrawIndexed pfnOriginalDrawIndexed = itContext->second->GetOriginal<tDrawIndexed>();
	pfnOriginalDrawIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation);

	// restore depth stencil state.
	if (isOutlinePass)
		pContext->OMSetDepthStencilState(pDepthStencilState, stencilRef);

	if (pDepthStencilState != NULL)
		pDepthStencilState->Release();
}

static void HookD3D11DeviceContext(ID3D11DeviceContext* pContext)
{
	if (ContextUsingDetours.find(pContext) == ContextUsingDetours.end())
	{
		const int DrawIndexed_VTABLE_INDEX = 12;
		uint8_t** vtable = *((uint8_t***)pContext);
		uint8_t* pSourceFunc = vtable[DrawIndexed_VTABLE_INDEX];
		for (auto it = AllDrawIndexedDetours.begin(); it != AllDrawIndexedDetours.end(); ++it)
		{
			if ((*it)->GetSourcePtr() == pSourceFunc)
			{
				// already hooked for other instance.
				ContextUsingDetours[pContext] = *it;
				pContext->AddRef();
				return;
			}
		}

		PLH::Detour* DrawIndexedDetour = new PLH::Detour;
		DrawIndexedDetour->m_PreserveSize = 32;
		GenerateRestoreCode(pSourceFunc, 32, 
							&DrawIndexedDetour->m_RestoreCode, 
							&DrawIndexedDetour->m_RestoreCodeSize);
		DrawIndexedDetour->SetupHook(pSourceFunc, (uint8_t*) &Hooked_DrawIndexed);
		if (!DrawIndexedDetour->Hook())
		{
			g_Logger->warn("Detour virtual function {} at {:p} for object {:p} failed",
						   "ID3D11DeviceContext::DrawIndex", pSourceFunc, (void*) pContext);
		}
		else
		{
			g_Logger->debug("Detour virtual function {} at {:p} for object {:p} succeed",
						    "ID3D11DeviceContext::DrawIndex", pSourceFunc, (void*)pContext);
		}

		ContextUsingDetours[pContext] = DrawIndexedDetour;
		pContext->AddRef();

		AllDrawIndexedDetours.push_back(DrawIndexedDetour);
	}
}

static void HookD3D11Device(ID3D11Device** ppDevice)
{
	if (ppDevice == NULL || *ppDevice == NULL)
		return;

	ID3D11DeviceContext* pContext;
	(*ppDevice)->GetImmediateContext(&pContext);
	if (pContext == NULL)
	{
		g_Logger->warn("GetImmediateContext from device {} returns null", (void*) ppDevice);
		return;
	}

	HookD3D11DeviceContext(pContext);
	pContext->Release();
}

HRESULT WINAPI CreateDerivedD3D11DeviceAndSwapChain(
	_In_opt_ IDXGIAdapter* pAdapter,
	D3D_DRIVER_TYPE DriverType,
	HMODULE Software,
	UINT Flags,
	_In_reads_opt_(FeatureLevels) CONST D3D_FEATURE_LEVEL* pFeatureLevels,
	UINT FeatureLevels,
	UINT SDKVersion,
	_In_opt_ CONST DXGI_SWAP_CHAIN_DESC* pSwapChainDesc,
	_Out_opt_ IDXGISwapChain** ppSwapChain,
	_Out_opt_ ID3D11Device** ppDevice,
	_Out_opt_ D3D_FEATURE_LEVEL* pFeatureLevel,
	_Out_opt_ ID3D11DeviceContext** ppImmediateContext)
{
	g_Logger->info("{:*^50}", "D3D11CreateDeviceAndSwapChain");
	g_Logger->info("pAdater: {}", (void*) pAdapter);
	g_Logger->info("DriverType: {}", (UINT)DriverType);
	g_Logger->info("Software: {}", (void*) Software);
	g_Logger->info("Flags: {}", Flags);
	g_Logger->info("pFeatureLevels: {}", pFeatureLevels && FeatureLevels > 0 ? (UINT) pFeatureLevels[0] : 0);
	g_Logger->info("FeatureLevels: {}", FeatureLevels);
	g_Logger->info("SDKVersion: {}", SDKVersion);
	g_Logger->info("pSwapChainDesc: {}", (void*) pSwapChainDesc);
	if (pSwapChainDesc)
	{
		DXGI_MODE_DESC b = pSwapChainDesc->BufferDesc;
		g_Logger->info("\t\tWidth: {}, Height: {}, RefreshDenomiator: {}, RefreshNumerator: {}, "
					   "Format: {}, ScanlineOrdering: {}, Scaling: {}",
					   b.Width, b.Height, b.RefreshRate.Denominator, b.RefreshRate.Numerator,
					   (UINT) b.Format, (UINT) b.ScanlineOrdering, (UINT) b.Scaling);

		g_Logger->info("\t\tSampleQuality: {}, SampleCount: {}, BufferUsage: {}, BufferCount: {}, "
					   "OutputWindow: {}, Windowed: {}, SwapEffect: {}, Flags: {}",
					   pSwapChainDesc->SampleDesc.Quality, pSwapChainDesc->SampleDesc.Count,
					   (UINT) pSwapChainDesc->BufferUsage, pSwapChainDesc->BufferCount, 
					   (void*) pSwapChainDesc->OutputWindow, pSwapChainDesc->Windowed, 
					   (UINT) pSwapChainDesc->SwapEffect, pSwapChainDesc->Flags);
	}
	g_Logger->info("ppSwapChain: {}", (void*) ppSwapChain);
	g_Logger->info("ppDevice: {}", (void*) ppDevice);
	g_Logger->info("pFeatureLevel: {}", (void*) pFeatureLevel);
	g_Logger->info("ppImmediateContext: {}", (void*) ppImmediateContext);
	g_Logger->info("{:*^50}", "");

	PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN pfn = (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN) Hooked_GetProcAddress(hD3D11, "D3D11CreateDeviceAndSwapChain");
	D3D_FEATURE_LEVEL selected;
	HRESULT res = pfn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, pSwapChainDesc, 
					  ppSwapChain, ppDevice, &selected, ppImmediateContext);

	if (SUCCEEDED(res))
	{
		g_Logger->debug("D3D11CreateDeviceAndSwapChain succeed with feature level {}", selected);
	}
	else
	{
		g_Logger->warn("D3D11CreateDeviceAndSwapChain failed with retcode {}", res);
	}


	if (pFeatureLevel)
		*pFeatureLevel = selected;

	HookD3D11Device(ppDevice);
	return res;
}

HRESULT WINAPI CreateDerivedD3D11Device(
	_In_opt_ IDXGIAdapter* pAdapter,
	D3D_DRIVER_TYPE DriverType,
	HMODULE Software,
	UINT Flags,
	_In_reads_opt_(FeatureLevels) CONST D3D_FEATURE_LEVEL* pFeatureLevels,
	UINT FeatureLevels,
	UINT SDKVersion,
	_Out_opt_ ID3D11Device** ppDevice,
	_Out_opt_ D3D_FEATURE_LEVEL* pFeatureLevel,
	_Out_opt_ ID3D11DeviceContext** ppImmediateContext)
{
	return CreateDerivedD3D11DeviceAndSwapChain(pAdapter, DriverType, Software, Flags,
												pFeatureLevels, FeatureLevels, SDKVersion,
												NULL, NULL, ppDevice, pFeatureLevel, 
												ppImmediateContext);
}

void initGlobalLog()
{
	char filename[128];
	{
		time_t timer;
		time(&timer);

		struct tm tm_info;
		localtime_s(&tm_info, &timer);

		strftime(filename, 128, "RDL_log_%Y.%m.%d_%H.%M.%S.log", &tm_info);
	}

	WCHAR DocumentPath[MAX_PATH];
	SHGetFolderPath(NULL, CSIDL_MYDOCUMENTS, NULL, SHGFP_TYPE_CURRENT, DocumentPath);

	std::wstring logDir = std::wstring(DocumentPath) + L"\\RenderdocLauncher\\";
	if (!CreateDirectory(logDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
		logDir = DocumentPath;

	g_Logger = spdlog::basic_logger_mt("logger", logDir + s2w(filename));
	spdlog::set_level(spdlog::level::debug);
	g_Logger->flush_on(spdlog::level::debug);
}

bool InitD3D11AndRenderdoc(HMODULE currentModule)
{
	initGlobalLog();

	g_JIT = new asmjit::JitRuntime;

	hCurrentModule = currentModule;

	{
		WCHAR curFile[MAX_PATH];
		GetModuleFileName(NULL, curFile, MAX_PATH);
		std::wstring f(curFile);
		g_Logger->info("Hooked into process {}", w2s(f));

		transform(f.begin(), f.end(), f.begin(), towlower);
		g_HookedProcessName = f;
	}
	
	WCHAR fullPath[MAX_PATH];
	UINT ret = GetSystemDirectoryW(fullPath, MAX_PATH);
	if (ret != 0 && ret < MAX_PATH)
	{
		wcscat_s(fullPath, MAX_PATH, L"\\d3d11.dll");
		hD3D11 = LoadLibraryEx(fullPath, NULL, 0);
	}

	hDXGI = LoadLibrary(L"dxgi.dll");
	if (hD3D11 == NULL || hDXGI == NULL)
	{
		g_Logger->error("load librarys {} and dxgi.dll failed.\n", w2s(fullPath));
		return false;
	}

	if (g_RenderdocMode)
	{
		hRenderdoc = LoadLibrary(L"renderdoc.dll");
		if (hRenderdoc == NULL)
		{
			g_Logger->error("load renderdoc.dll failed.\n");
			return false;
		}
	}

	if (hRenderdoc != NULL)
	{
		sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDeviceAndSwapChain", hRenderdoc, "RENDERDOC_CreateWrappedD3D11DeviceAndSwapChain"));
		sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDevice", hRenderdoc, "RENDERDOC_CreateWrappedD3D11Device"));
		sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDeviceAndSwapChain", hRenderdoc, "RENDERDOC_CreateWrappedD3D11DeviceAndSwapChain"));
		sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDevice", hRenderdoc, "RENDERDOC_CreateWrappedD3D11Device"));
		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory"));
		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory1", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory1"));
		sDetourHooks.push_back(DetourHookInfo(hDXGI, "CreateDXGIFactory2", hRenderdoc, "RENDERDOC_CreateWrappedDXGIFactory2"));
	}
	else
	{
		sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDeviceAndSwapChain", (FARPROC)&CreateDerivedD3D11DeviceAndSwapChain));
		sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDevice", (FARPROC)&CreateDerivedD3D11Device));
		sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDeviceAndSwapChain", (FARPROC)&CreateDerivedD3D11DeviceAndSwapChain));
		sDetourHooks.push_back(DetourHookInfo(hD3D11, "D3D11CreateDevice", (FARPROC)&CreateDerivedD3D11Device));
	}

	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "CreateDirect3D11DeviceFromDXGIDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "CreateDirect3D11SurfaceFromDXGISurface", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CoreCreateDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CoreCreateLayeredDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CoreGetLayeredDeviceSize", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CoreRegisterLayers", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11CreateDeviceForD3D12", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3D11On12CreateDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCloseAdapter", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCreateAllocation", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCreateContext", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCreateDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTCreateSynchronizationObject", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTDestroyAllocation", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTDestroyContext", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTDestroyDevice", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTDestroySynchronizationObject", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTEscape", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetContextSchedulingPriority", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetDeviceState", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetDisplayModeList", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetMultisampleMethodList", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetRuntimeData", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTGetSharedPrimaryHandle", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTLock", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTOpenAdapterFromHdc", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTOpenResource", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTPresent", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTQueryAdapterInfo", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTQueryAllocationResidency", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTQueryResourceInfo", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTRender", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetAllocationPriority", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetContextSchedulingPriority", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetDisplayMode", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetDisplayPrivateDriverFormat", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetGammaRamp", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSetVidPnSourceOwner", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTSignalSynchronizationObject", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTUnlock", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTWaitForSynchronizationObject", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DKMTWaitForVerticalBlankEvent", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DPerformance_BeginEvent", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DPerformance_EndEvent", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DPerformance_GetStatus", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "D3DPerformance_SetMarker", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "EnableFeatureLevelUpgrade", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "OpenAdapter10", hD3D11));
	sDetourHooks.push_back(DetourHookInfo(hCurrentModule, "OpenAdapter10_2", hD3D11));
	
	for (auto it = sDetourHooks.begin(); it != sDetourHooks.end(); ++it)
	{
		it->InstallHook();
	}

	if (g_RenderdocMode && !InstallRenderdocIATHook())
	{
		return false;
	}

	return true;
}
