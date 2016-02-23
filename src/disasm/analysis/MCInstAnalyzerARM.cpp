//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "MCInstAnalyzerARM.h"
#include "CFGNode.h"

namespace disasm {

MCInstAnalyzerARM::MCInstAnalyzerARM() :
    m_isa{ISAType::kThumb} {
}

MCInstAnalyzerARM::MCInstAnalyzerARM(ISAType isa) :
    m_isa{isa} {
}

std::vector<const MCInst *> MCInstAnalyzerARM::getPCRelativeLoadsInstructions
    (const CFGNode *cfg_node) const noexcept {
    // XXX: assuming pc-relative loads can happen only in LDR, VLDR, and LDRD
    auto predicate = [](const MCInst *inst) -> bool {
        if ((inst->id() == ARM_INS_LDR ||
            inst->id() == ARM_INS_VLDR) &&
            inst->detail().arm.operands[1].mem.base == ARM_REG_PC) {
            return true;
        }
        return false;
    };
    return cfg_node->getCandidateInstructionsSatisfying(predicate);
}
}
