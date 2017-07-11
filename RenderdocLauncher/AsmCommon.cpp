#include "AsmCommon.h"
#include "CommonUtils.h"

extern asmjit::JitRuntime* g_JIT = NULL;

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
					(void*)pInsn->address, bytes, pInsn->mnemonic, pInsn->op_str);
}

bool GenerateRestoreCode(uint8_t* pFuncAddr, int codeSize,
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

	void(*pfnVoidFunc)();
	g_JIT->add(&pfnVoidFunc, &code);

	*pRestoreCodeSize = (uint32_t)code.getCodeSize();
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
