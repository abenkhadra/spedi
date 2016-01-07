//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#include "MCInstAnalyzer.h"

namespace disasm {

MCInstAnalyzer::MCInstAnalyzer(ISAType isa) : m_isa{isa} {
    m_inst_width = getMinxInstWidth(isa);
}

bool MCInstAnalyzer::isBranch(const cs_insn *inst) const {
    if (inst->detail == NULL) return false;

    cs_detail *detail = inst->detail;
    // assuming that each instruction should belong to at least one group
    if (detail->groups[detail->groups_count - 1] == ARM_GRP_JUMP)
        return true;
    if (inst->id == ARM_INS_POP) {
        // pop accepts a register list. If pc was among them then this a branch
        for (int i = 0; i < detail->arm.op_count; ++i) {
            if (detail->arm.operands[i].reg == ARM_REG_PC) return true;
        }
    }

    if ((detail->arm.operands[0].type == ARM_OP_REG)
        && (detail->arm.operands[0].reg == ARM_REG_PC)) {
        if (inst->id == ARM_INS_STR) {
            return false;
        }
        return true;
    }
    return false;
}

bool MCInstAnalyzer::isValid(const cs_insn *inst) const {

    for (int i = 0; i < inst->detail->arm.op_count; ++i) {
        if (inst->detail->arm.operands[i].type == ARM_OP_REG) {
            if (inst->detail->arm.operands[i].reg == ARM_REG_PC) {
                // We do no apply PC, SP restrictions to load instructions
                if (ARM_INS_LDA <= inst->id && inst->id <= ARM_INS_LDR) {
                    continue;
                }
                // PC usage restrictions based on manual A2-46
                // and Table D9.5 details.
                switch (inst->id) {
                    case ARM_INS_ADD:
                    case ARM_INS_ADR:
                    case ARM_INS_BX:
                    case ARM_INS_BLX:
                    case ARM_INS_MOV:
                    case ARM_INS_SUB:
                        // allowed as destination register only
                        if (i != 0) return false;
                    case ARM_INS_SUBS:
                    case ARM_INS_MOVS:
                        // XXX more restrictions can be applied here
                        break;
                    default:
                        // TODO: make logging consistent and configurable
                        // Pop are allowed to use PC
                        if (inst->id != ARM_INS_POP) {
                            printf("Found invalid pc at 0x%lx, %s, %s\n",
                                   inst->address,
                                   inst->mnemonic,
                                   inst->op_str);
                            return false;
                        }
                }
            } else if (inst->detail->arm.operands[i].reg == ARM_REG_SP) {
                // We do no apply PC, SP restrictions to load instructions
                if (ARM_INS_LDA <= inst->id && inst->id <= ARM_INS_LDR) {
                    continue;
                }
                // restrictions on SP usage
                switch (inst->id) {
                    case ARM_INS_MOV:
                    case ARM_INS_ADD:
                    case ARM_INS_ADDW:
                    case ARM_INS_SUB:
                    case ARM_INS_CMN:
                    case ARM_INS_CMP:
                        break;
                    default:
                        // we allow stores to use SP
                        if (!(ARM_INS_STMDA <= inst->id
                            && inst->id <= ARM_INS_STR)) {
                            printf("Found invalid sp at 0x%lx, %s, %s\n",
                                   inst->address,
                                   inst->mnemonic,
                                   inst->op_str);
                            return false;
                        }
                        break;
                }
            } else if (!(
                ((ARM_REG_R0 <= inst->detail->arm.operands[i].reg) &&
                    (inst->detail->arm.operands[i].reg <= ARM_REG_R12))
                    || inst->detail->arm.operands[i].reg == ARM_REG_LR)) {
                // XXX: using unusual registers such as co-processor registers
                // is currently not allowed. For example, we do not allow access
                // to registers of system control co-processor (CP15). Note that
                // only some instructions like MRC, MCREQ & MCR can use
                // co-processor registers
                printf("Found invalid register at 0x%lx, %s, %s\n",
                       inst->address,
                       inst->mnemonic,
                       inst->op_str);
                return false;
            }
        } else if (inst->detail->arm.operands[i].type == ARM_OP_CIMM
            || inst->detail->arm.operands[i].type == ARM_OP_PIMM) {
            printf("Found invalid co-register at 0x%lx, %s, %s\n",
                   inst->address,
                   inst->mnemonic,
                   inst->op_str);
            return false;
        }
    }
    return true;
}

bool MCInstAnalyzer::isConditional(const cs_insn *inst) const {
    if (inst->id == ARM_INS_CBNZ || inst->id == ARM_INS_CBZ) {
        return true;
    }
    return inst->detail->arm.cc != ARM_CC_AL;
}
ISAInstWidth MCInstAnalyzer::getMinxInstWidth(ISAType isa) const {
    switch (isa) {
        case ISAType::kx86:
        case ISAType::kx86_64:
            return ISAInstWidth::kByte;
        case ISAType::kThumb:
        case ISAType::kTriCore:
            return ISAInstWidth::kHWord;
        default:
            return ISAInstWidth::kWord;
    }
}
}
