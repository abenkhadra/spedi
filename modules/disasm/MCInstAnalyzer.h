//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#pragma once
#include "common.h"

struct cs_insn;

namespace disasm {
/**
 * MCInstAnalyzer
 */
class MCInstAnalyzer {
public:
    /**
     * Construct a MCInstAnalyzer
     */
    explicit MCInstAnalyzer(ISAType isa);
    virtual ~MCInstAnalyzer() = default;
    MCInstAnalyzer(const MCInstAnalyzer &src) = default;
    MCInstAnalyzer &operator=(const MCInstAnalyzer &src) = default;
    MCInstAnalyzer(MCInstAnalyzer &&src) = default;

    bool isBranch(const cs_insn *inst) const;
    /*
     * precondition: instruction is known to be a branch.
     * if direct branch return immediate value, otherwise return 0.
     */
    int branchTarget(const cs_insn *inst) const;

    bool isValid(const cs_insn *inst) const;

private:
    ISAType m_isa;
};
}



