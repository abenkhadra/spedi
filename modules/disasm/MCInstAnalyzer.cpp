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
    if(inst->detail == NULL) return false;

    cs_detail* detail = inst-> detail;
    for (int i = 0; i < detail->groups_count; ++i) {
        if (detail->groups[i] == ARM_GRP_JUMP ) {
            return true;
        }
    }

    if ((detail->arm.operands[0].type == ARM_OP_REG)
        && (detail->arm.operands[0].reg == ARM_REG_PC)) return true;

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
}