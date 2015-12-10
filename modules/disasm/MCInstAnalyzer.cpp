//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "MCInstAnalyzer.h"
#include <capstone/capstone.h>

namespace disasm {

MCInstAnalyzer::MCInstAnalyzer(ISAType isa) : m_isa{isa} { }

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

int MCInstAnalyzer::branchTarget(const cs_insn *inst) const {
    cs_detail *detail = inst->detail;
    for (int i = 0; i < detail->arm.op_count; ++i) {
        if (detail->arm.operands[i].type == ARM_OP_IMM) {
            return detail->arm.operands[i].imm;
        } else if (detail->arm.operands[i].type == ARM_OP_MEM) {
            return 0;
        }
    }
    return 0;
}

//TODO: a function to get the absolute branch target based on current PC
bool MCInstAnalyzer::isValid(const cs_insn *inst) const {
    // restrictions on PC usage
    if (inst->detail->arm.operands[0].type == ARM_OP_REG
        && inst->detail->arm.operands[0].reg == ARM_REG_PC) {
        // based on manual A2-46
        switch (inst->id) {
            case ARM_INS_ADD:
            case ARM_INS_MOV:
            // in arm state only
            case ARM_INS_ADC:
            case ARM_INS_ADR:
            case ARM_INS_AND:
            case ARM_INS_ASR:
            case ARM_INS_BIC:
            case ARM_INS_EOR:
            case ARM_INS_MVN:
            case ARM_INS_ORR:
            case ARM_INS_ROR:
            case ARM_INS_SUB:
            case ARM_INS_RRX:
            case ARM_INS_RSB:
            case ARM_INS_STR:
            case ARM_INS_BX:
            case ARM_INS_BLX:
            case ARM_INS_POP:
                return true;
            default:
                // we allow loads to use PC
                if (ARM_INS_LDA <= inst->id && inst->id <= ARM_INS_LDR) {
                    return true;
                }
                printf("Found invalid pc at 0x%lx, %s, %s\n", inst->address,
                       inst->mnemonic,
                       inst->op_str);
                return false;
        }
    }

    // restrictions on SP usage
    for (int i = 0; i < inst->detail->arm.op_count; ++i) {
        if (inst->detail->arm.operands[i].type == ARM_OP_REG
            && inst->detail->arm.operands[i].reg == ARM_REG_SP) {
            switch (inst->id) {
                case ARM_INS_MOV:
                case ARM_INS_ADD:
                case ARM_INS_ADDW:
                case ARM_INS_SUB:
                case ARM_INS_CMN:
                case ARM_INS_CMP:
                    return true;
                default:
                    // we allow loads to use SP
                    if (ARM_INS_LDA <= inst->id && inst->id <= ARM_INS_LDR) {
                        return true;
                    }
                    // we allow stores to use SP
                    if (ARM_INS_STMDA <= inst->id && inst->id <= ARM_INS_STR) {
                        return true;
                    }
                    printf("Found invalid sp at 0x%lx, %s, %s\n", inst->address,
                           inst->mnemonic,
                           inst->op_str);
                    return false;
            }
        }
    }
    return true;
}
}