//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "../common.h"

namespace disasm {
class MCInst;

/**
 * MCInstAnalyzer
 */
class MCInstAnalyzer {
public:
    MCInstAnalyzer();
    MCInstAnalyzer(ISAType isa);
    virtual ~MCInstAnalyzer() = default;
    MCInstAnalyzer(const MCInstAnalyzer &src) = default;
    MCInstAnalyzer &operator=(const MCInstAnalyzer &src) = default;
    MCInstAnalyzer(MCInstAnalyzer &&src) = default;

    bool isCall(const MCInst *inst) const;
private:
    ISAType m_isa;
};
}



