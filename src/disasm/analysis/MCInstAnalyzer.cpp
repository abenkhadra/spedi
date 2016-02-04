//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "MCInstAnalyzer.h"
#include "../MCInst.h"
#include <capstone/capstone.h>

namespace disasm {

MCInstAnalyzer::MCInstAnalyzer() :
    m_isa{ISAType::kThumb} {
}

MCInstAnalyzer::MCInstAnalyzer(ISAType isa) :
    m_isa{isa} {
}

bool MCInstAnalyzer::isCall(const MCInst *inst) const {
    return inst->id() == ARM_INS_BLX || inst->id() == ARM_INS_BL;
}
}