//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "MCInstAnalyzer.h"
#include <capstone/capstone.h>

namespace disasm{

MCInstAnalyzer::MCInstAnalyzer(ISAType isa): m_isa{isa}
{}

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

    if (ARM_INS_STRBT <= inst->id
        && inst->id <= ARM_INS_STRT
        && inst->detail->arm.operands[0].type == ARM_OP_REG
        && inst->detail->arm.operands[0].reg == ARM_REG_PC) {
        // If the instruction is a modified store then it can't store pc!
        return false;
    }
    return true;
}
}