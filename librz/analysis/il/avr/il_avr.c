// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "il_avr.h"

#define AVR_REG_SIZE  8
#define AVR_SREG_SIZE 8
#define AVR_RAMP_SIZE 8
#define AVR_SP_SIZE   16

// SREG = I|T|H|S|V|N|Z|C
// bits   0|1|2|3|4|5|6|7
#define AVR_SREG_I 0
#define AVR_SREG_T 1
#define AVR_SREG_H 2
#define AVR_SREG_S 3
#define AVR_SREG_V 4
#define AVR_SREG_N 5
#define AVR_SREG_Z 6
#define AVR_SREG_C 7

#define AVR_SPL_ADDR  0x3d
#define AVR_SPH_ADDR  0x3e
#define AVR_SREG_ADDR 0x3f

#define avr_return_val_if_invalid_gpr(x, v) \
	if (x >= 32) { \
		RZ_LOG_ERROR("RzIL: AVR: invalid register R%u\n", x); \
		return v; \
	}

#define avr_il_cast_reg(name, dst, len, sh, src) \
	do { \
		RzILOp *var = rz_il_new_op(RZIL_OP_VAR); \
		var->op.var->v = (src); \
		RzILOp *cast = rz_il_new_op(RZIL_OP_CAST); \
		cast->op.cast->val = var; \
		cast->op.cast->length = (len); \
		cast->op.cast->shift = (sh); \
		RzILOp *set = rz_il_new_op(RZIL_OP_SET); \
		set->op.set->x = cast; \
		set->op.set->v = (dst); \
		(name) = rz_il_new_op(RZIL_OP_PERFORM); \
		(name)->op.perform->eff = set; \
	} while (0)

#define avr_il_assign_reg(name, dst, src) \
	do { \
		RzILOp *var = rz_il_new_op(RZIL_OP_VAR); \
		var->op.var->v = (src); \
		RzILOp *set = rz_il_new_op(RZIL_OP_SET); \
		set->op.set->x = var; \
		set->op.set->v = (dst); \
		(name) = rz_il_new_op(RZIL_OP_PERFORM); \
		(name)->op.perform->eff = set; \
	} while (0)

#define avr_il_assign_imm(name, reg, imm) \
	do { \
		RzILOp *n = rz_il_new_op(RZIL_OP_INT); \
		n->op.int_->value = (imm); \
		n->op.int_->length = AVR_REG_SIZE; \
		RzILOp *set = rz_il_new_op(RZIL_OP_SET); \
		set->op.set->x = n; \
		set->op.set->v = (reg); \
		(name) = rz_il_new_op(RZIL_OP_PERFORM); \
		(name)->op.perform->eff = set; \
	} while (0)

#define avr_il_store_reg(name, address, reg) \
	do { \
		RzILOp *var = rz_il_new_op(RZIL_OP_VAR); \
		var->op.var->v = (reg); \
		RzILOp *addr = rz_il_new_op(RZIL_OP_INT); \
		addr->op.int_->value = (address); \
		addr->op.int_->length = 32; \
		(name) = rz_il_new_op(RZIL_OP_STORE); \
		(name)->op.store->key = addr; \
		(name)->op.store->value = var; \
	} while (0)

#define avr_il_set_bits(name, reg, and_bits, or_bits) \
	do { \
		RzILOp *tmp = NULL; \
		RzILOp *sreg = rz_il_new_op(RZIL_OP_VAR); \
		sreg->op.var->v = (reg); \
		tmp = rz_il_new_op(RZIL_OP_INT); \
		tmp->op.int_->value = (and_bits); \
		tmp->op.int_->length = AVR_REG_SIZE; \
		RzILOp *opand = rz_il_new_op(RZIL_OP_LOGAND); \
		opand->op.logand->x = sreg; \
		opand->op.logand->y = tmp; \
		if (or_bits) { \
			RzILOp *mask1 = rz_il_new_op(RZIL_OP_INT); \
			mask1->op.int_->value = (or_bits); \
			mask1->op.int_->length = AVR_REG_SIZE; \
			tmp = rz_il_new_op(RZIL_OP_LOGOR); \
			tmp->op.logand->x = opand; \
			tmp->op.logand->y = mask1; \
		} else { \
			tmp = opand; \
		} \
		RzILOp *set = rz_il_new_op(RZIL_OP_SET); \
		set->op.set->x = tmp; \
		set->op.set->v = (reg); \
		(name) = rz_il_new_op(RZIL_OP_PERFORM); \
		(name)->op.perform->eff = set; \
	} while (0)

#define avr_il_set16_from_reg(name, dst, and_mask, sh, src) \
	do { \
		RzILOp *var0 = rz_il_new_op(RZIL_OP_VAR); \
		var0->op.var->v = (dst); \
		RzILOp *mask = rz_il_new_op(RZIL_OP_INT); \
		mask->op.int_->value = (and_mask); \
		mask->op.int_->length = 16; \
		RzILOp *opand = rz_il_new_op(RZIL_OP_LOGAND); \
		opand->op.logand->x = var0; \
		opand->op.logand->y = mask; \
		RzILOp *var1 = rz_il_new_op(RZIL_OP_VAR); \
		var1->op.var->v = (src); \
		RzILOp *cast = rz_il_new_op(RZIL_OP_CAST); \
		cast->op.cast->val = var1; \
		cast->op.cast->length = 16; \
		cast->op.cast->shift = (sh); \
		RzILOp *opor = rz_il_new_op(RZIL_OP_LOGOR); \
		opor->op.logand->x = cast; \
		opor->op.logand->y = opand; \
		RzILOp *set = rz_il_new_op(RZIL_OP_SET); \
		set->op.set->x = opor; \
		set->op.set->v = (dst); \
		(name) = rz_il_new_op(RZIL_OP_PERFORM); \
		(name)->op.perform->eff = set; \
	} while (0)

typedef RzPVector *(*avr_rzil_op)(AVROp *aop, RzAnalysis *analysis);

const char *avr_registers[32] = {
	"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9",
	"R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18",
	"R19", "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27",
	"R28", "R29", "R30", "R31"
};

static RzPVector *avr_il_nop(AVROp *aop, RzAnalysis *analysis) {
	return NULL;
}

static RzPVector *avr_il_clr(AVROp *aop, RzAnalysis *analysis) {
	// Rd = Rd ^ Rd -> S=0, V=0, N=0, Z=1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *clr = NULL;
	RzILOp *perform = NULL;
	avr_il_assign_imm(clr, avr_registers[Rd], 0);

	ut8 bit_0 = ~((1 << AVR_SREG_S) | (1 << AVR_SREG_V) | (1 << AVR_SREG_N));
	ut8 bit_1 = (1 << AVR_SREG_Z);
	avr_il_set_bits(perform, "SREG", bit_0, bit_1);

	return rz_il_make_oplist(2, clr, perform);
}

static RzPVector *avr_il_cpi(AVROp *aop, RzAnalysis *analysis) {
	// SREG = compare(Rd, K)
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *cpi = NULL, *zsreg = NULL;

	// SREG = I|T|H|S|V|N|Z|C
	// bits = x|x|0|0|0|0|0|0
	ut8 bit_0 = ~((1 << AVR_SREG_H) | (1 << AVR_SREG_S) | (1 << AVR_SREG_V) |
		(1 << AVR_SREG_N) | (1 << AVR_SREG_Z) | (1 << AVR_SREG_C));
	avr_il_set_bits(zsreg, "SREG", bit_0, 0);

	return rz_il_make_oplist(2, zsreg, cpi);
}

static RzPVector *avr_il_ldi(AVROp *aop, RzAnalysis *analysis) {
	// Rd = K
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *ldi = NULL;
	avr_il_assign_imm(ldi, avr_registers[Rd], K);
	return rz_il_make_oplist(1, ldi);
}

static RzPVector *avr_il_out(AVROp *aop, RzAnalysis *analysis) {
	// I/O(A) = Rr -> None
	ut16 A = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// R0-31 registers from 0 to 0x1F
	// I/O registers 0x20 to 0x5F
	// Ext I/O registers 0x60 to 0xFF

	RzILOp *out = NULL;
	if (A < 32) {
		avr_il_assign_reg(out, avr_registers[A], avr_registers[Rr]);
	} else if (A == AVR_SPL_ADDR) {
		// zeros low 8 bits and OR new value
		avr_il_set16_from_reg(out, "SP", 0xFF00, 0, avr_registers[Rr]);
	} else if (A == AVR_SPH_ADDR) {
		// zeros high 8 bits and OR new value
		avr_il_set16_from_reg(out, "SP", 0x00FF, 8, avr_registers[Rr]);
	} else if (A == AVR_SREG_ADDR) {
		// zeros low 8 bits and OR new value
		avr_il_assign_reg(out, "SREG", avr_registers[Rr]);
	} else {
		avr_il_store_reg(out, A, avr_registers[Rr]);
	}
	return rz_il_make_oplist(1, out);
}

static RzPVector *avr_il_rjmp(AVROp *aop, RzAnalysis *analysis) {
	// PC = PC + k + 1
	ut16 k = aop->param[0];

	RzILOp *bitv = rz_il_new_op(RZIL_OP_BV);
	bitv->op.bitv->value = rz_il_bv_new_from_ut64(analysis->rzil->vm->pc->len, k - aop->size);
	RzILOp *rjmp = rz_il_new_op(RZIL_OP_JMP);
	rjmp->op.jmp->dst = bitv;

	RzILOp *perform = rz_il_new_op(RZIL_OP_PERFORM);
	perform->op.perform->eff = rjmp;

	return rz_il_make_oplist(1, perform);
}

static RzPVector *avr_il_ser(AVROp *aop, RzAnalysis *analysis) {
	// Rd = $FF
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *ser = NULL;
	avr_il_assign_imm(ser, avr_registers[Rd], 0xFF);
	return rz_il_make_oplist(1, ser);
}

static avr_rzil_op avr_ops[AVR_OP_SIZE] = {
	avr_il_nop, /* AVR_OP_INVALID */
	avr_il_nop, /* AVR_OP_ADC */
	avr_il_nop, /* AVR_OP_ADD */
	avr_il_nop, /* AVR_OP_ADIW */
	avr_il_nop, /* AVR_OP_AND */
	avr_il_nop, /* AVR_OP_ANDI */
	avr_il_nop, /* AVR_OP_ASR */
	avr_il_nop, /* AVR_OP_BLD */
	avr_il_nop, /* AVR_OP_BRCC */
	avr_il_nop, /* AVR_OP_BRCS */
	avr_il_nop, /* AVR_OP_BREAK */
	avr_il_nop, /* AVR_OP_BREQ */
	avr_il_nop, /* AVR_OP_BRGE */
	avr_il_nop, /* AVR_OP_BRHC */
	avr_il_nop, /* AVR_OP_BRHS */
	avr_il_nop, /* AVR_OP_BRID */
	avr_il_nop, /* AVR_OP_BRIE */
	avr_il_nop, /* AVR_OP_BRLO */
	avr_il_nop, /* AVR_OP_BRLT */
	avr_il_nop, /* AVR_OP_BRMI */
	avr_il_nop, /* AVR_OP_BRNE */
	avr_il_nop, /* AVR_OP_BRPL */
	avr_il_nop, /* AVR_OP_BRSH */
	avr_il_nop, /* AVR_OP_BRTC */
	avr_il_nop, /* AVR_OP_BRTS */
	avr_il_nop, /* AVR_OP_BRVC */
	avr_il_nop, /* AVR_OP_BRVS */
	avr_il_nop, /* AVR_OP_BST */
	avr_il_nop, /* AVR_OP_CALL */
	avr_il_nop, /* AVR_OP_CBI */
	avr_il_nop, /* AVR_OP_CLC */
	avr_il_nop, /* AVR_OP_CLH */
	avr_il_nop, /* AVR_OP_CLI */
	avr_il_nop, /* AVR_OP_CLN */
	avr_il_clr,
	avr_il_nop, /* AVR_OP_CLS */
	avr_il_nop, /* AVR_OP_CLT */
	avr_il_nop, /* AVR_OP_CLV */
	avr_il_nop, /* AVR_OP_CLZ */
	avr_il_nop, /* AVR_OP_COM */
	avr_il_nop, /* AVR_OP_CP */
	avr_il_nop, /* AVR_OP_CPC */
	avr_il_cpi,
	avr_il_nop, /* AVR_OP_CPSE */
	avr_il_nop, /* AVR_OP_DEC */
	avr_il_nop, /* AVR_OP_DES */
	avr_il_nop, /* AVR_OP_EICALL */
	avr_il_nop, /* AVR_OP_EIJMP */
	avr_il_nop, /* AVR_OP_ELPM */
	avr_il_nop, /* AVR_OP_EOR */
	avr_il_nop, /* AVR_OP_FMUL */
	avr_il_nop, /* AVR_OP_FMULS */
	avr_il_nop, /* AVR_OP_FMULSU */
	avr_il_nop, /* AVR_OP_ICALL */
	avr_il_nop, /* AVR_OP_IJMP */
	avr_il_nop, /* AVR_OP_IN */
	avr_il_nop, /* AVR_OP_INC */
	avr_il_nop, /* AVR_OP_JMP */
	avr_il_nop, /* AVR_OP_LAC */
	avr_il_nop, /* AVR_OP_LAS */
	avr_il_nop, /* AVR_OP_LAT */
	avr_il_nop, /* AVR_OP_LD */
	avr_il_nop, /* AVR_OP_LDD */
	avr_il_ldi,
	avr_il_nop, /* AVR_OP_LDS */
	avr_il_nop, /* AVR_OP_LPM */
	avr_il_nop, /* AVR_OP_LSL */
	avr_il_nop, /* AVR_OP_LSR */
	avr_il_nop, /* AVR_OP_MOV */
	avr_il_nop, /* AVR_OP_MOVW */
	avr_il_nop, /* AVR_OP_MUL */
	avr_il_nop, /* AVR_OP_MULS */
	avr_il_nop, /* AVR_OP_MULSU */
	avr_il_nop, /* AVR_OP_NEG */
	avr_il_nop, /* AVR_OP_NOP */
	avr_il_nop, /* AVR_OP_OR */
	avr_il_nop, /* AVR_OP_ORI */
	avr_il_out,
	avr_il_nop, /* AVR_OP_POP */
	avr_il_nop, /* AVR_OP_PUSH */
	avr_il_nop, /* AVR_OP_RCALL */
	avr_il_nop, /* AVR_OP_RET */
	avr_il_nop, /* AVR_OP_RETI */
	avr_il_rjmp,
	avr_il_nop, /* AVR_OP_ROL */
	avr_il_nop, /* AVR_OP_ROR */
	avr_il_nop, /* AVR_OP_SBC */
	avr_il_nop, /* AVR_OP_SBCI */
	avr_il_nop, /* AVR_OP_SBI */
	avr_il_nop, /* AVR_OP_SBIC */
	avr_il_nop, /* AVR_OP_SBIS */
	avr_il_nop, /* AVR_OP_SBIW */
	avr_il_nop, /* AVR_OP_SBRC */
	avr_il_nop, /* AVR_OP_SBRS */
	avr_il_nop, /* AVR_OP_SEC */
	avr_il_nop, /* AVR_OP_SEH */
	avr_il_nop, /* AVR_OP_SEI */
	avr_il_nop, /* AVR_OP_SEN */
	avr_il_ser,
	avr_il_nop, /* AVR_OP_SES */
	avr_il_nop, /* AVR_OP_SET */
	avr_il_nop, /* AVR_OP_SEV */
	avr_il_nop, /* AVR_OP_SEZ */
	avr_il_nop, /* AVR_OP_SLEEP */
	avr_il_nop, /* AVR_OP_SPM */
	avr_il_nop, /* AVR_OP_ST */
	avr_il_nop, /* AVR_OP_STD */
	avr_il_nop, /* AVR_OP_STS */
	avr_il_nop, /* AVR_OP_SUB */
	avr_il_nop, /* AVR_OP_SUBI */
	avr_il_nop, /* AVR_OP_SWAP */
	avr_il_nop, /* AVR_OP_TST */
	avr_il_nop, /* AVR_OP_WDR */
	avr_il_nop, /* AVR_OP_XCH */
};

/*
static const char *avr_ops_name[AVR_OP_SIZE] = {
	"INVALID", "ADC", "ADD", "ADIW", "AND", "ANDI", "ASR",
	"BLD", "BRCC", "BRCS", "BREAK", "BREQ", "BRGE", "BRHC",
	"BRHS", "BRID", "BRIE", "BRLO", "BRLT", "BRMI", "BRNE",
	"BRPL", "BRSH", "BRTC", "BRTS", "BRVC", "BRVS", "BST",
	"CALL", "CBI", "CLC", "CLH", "CLI", "CLN", "CLR",
	"CLS", "CLT", "CLV", "CLZ", "COM", "CP", "CPC",
	"CPI", "CPSE", "DEC", "DES", "EICALL", "EIJMP", "ELPM",
	"EOR", "FMUL", "FMULS", "FMULSU", "ICALL", "IJMP", "IN",
	"INC", "JMP", "LAC", "LAS", "LAT", "LD", "LDD",
	"LDI", "LDS", "LPM", "LSL", "LSR", "MOV", "MOVW",
	"MUL", "MULS", "MULSU", "NEG", "NOP", "OR", "ORI",
	"OUT", "POP", "PUSH", "RCALL", "RET", "RETI", "RJMP",
	"ROL", "ROR", "SBC", "SBCI", "SBI", "SBIC", "SBIS",
	"SBIW", "SBRC", "SBRS", "SEC", "SEH", "SEI", "SEN",
	"SER", "SES", "SET", "SEV", "SEZ", "SLEEP", "SPM",
	"ST", "STD", "STS", "SUB", "SUBI", "SWAP", "TST",
	"WDR", "XCH"
};
*/

RZ_IPI bool avr_rzil_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, AVROp *aop) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);
	op->rzil_op = RZ_NEW0(RzAnalysisRzilOp);
	if (!op->rzil_op) {
		RZ_LOG_ERROR("RzIL: AVR: cannot allocate RzAnalysisRzilOp\n");
		return false;
	}

	if (aop->mnemonic >= AVR_OP_SIZE) {
		RZ_LOG_ERROR("RzIL: AVR: out of bounds op\n");
		return false;
	}

	avr_rzil_op create_op = avr_ops[aop->mnemonic];
	op->rzil_op->ops = create_op(aop, analysis);

	//if (create_op != avr_il_nop) {
	//	eprintf("0x%08llx -> op %s %d\n", pc, avr_ops_name[aop->mnemonic], create_op == avr_il_nop);
	//}
	return true;
}

RZ_IPI bool avr_rzil_fini(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);

	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->vm) {
		rz_il_vm_fini(rzil->vm);
		rzil->vm = NULL;
	}

	rzil->inited = false;
	return true;
}

RZ_IPI bool avr_rzil_init(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);
	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->inited) {
		RZ_LOG_ERROR("RzIL: AVR: VM is already configured\n");
		return true;
	}

	RzArchProfile *profile = analysis->arch_target ? analysis->arch_target->profile : NULL;

	ut32 addr_space = 22; // 22 bits address space
	ut64 pc_address = 0;

	if (profile && profile->rom_size < 0x10000) {
		addr_space = 16;
	}

	if (!rz_il_vm_init(rzil->vm, pc_address, addr_space, addr_space)) {
		RZ_LOG_ERROR("RzIL: AVR: failed to initialize VM\n");
		return false;
	}

	char reg[8] = { 0 };

	for (ut32 i = 0; i < 32; ++i) {
		rz_strf(reg, "R%d", i);
		rz_il_vm_add_reg(rzil->vm, reg, AVR_REG_SIZE);
	}

	rz_il_vm_add_reg(rzil->vm, "SP", AVR_SP_SIZE);
	// SREG = I|T|H|S|V|N|Z|C
	// bits   0|1|2|3|4|5|6|7
	rz_il_vm_add_reg(rzil->vm, "SREG", AVR_SREG_SIZE);

	if (addr_space > 16) {
		rz_il_vm_add_reg(rzil->vm, "RAMPX", AVR_RAMP_SIZE);
		rz_il_vm_add_reg(rzil->vm, "RAMPY", AVR_RAMP_SIZE);
		rz_il_vm_add_reg(rzil->vm, "RAMPZ", AVR_RAMP_SIZE);
		rz_il_vm_add_reg(rzil->vm, "RAMPD", AVR_RAMP_SIZE);
		rz_il_vm_add_reg(rzil->vm, "EIND", AVR_RAMP_SIZE);
	}

	rz_il_vm_add_mem(rzil->vm, 8);

	return true;
}
