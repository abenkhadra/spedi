//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "MaximalBlockAnalyzer.h"
#include "BlockCFGNode.h"

namespace disasm {

MaximalBlockAnalyzer::MaximalBlockAnalyzer() :
    m_isa{ISAType::kThumb} {
}

MaximalBlockAnalyzer::MaximalBlockAnalyzer(ISAType isa) :
    m_isa{isa} {
}

bool MaximalBlockAnalyzer::isCall(const MCInst *inst) const noexcept {
    return inst->id() == ARM_INS_BLX || inst->id() == ARM_INS_BL;
}

std::vector<const MCInst *> MaximalBlockAnalyzer::getPCRelativeLoadsInstructions
    (const BlockCFGNode *cfg_node) const noexcept {
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