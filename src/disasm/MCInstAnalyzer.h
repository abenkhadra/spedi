//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#pragma once
#include <capstone/capstone.h>
#include "common.h"
#include "BranchData.h"

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
    MCInstAnalyzer() = default;
    explicit MCInstAnalyzer(ISAType isa);
    virtual ~MCInstAnalyzer() = default;
    MCInstAnalyzer(const MCInstAnalyzer &src) = default;
    MCInstAnalyzer &operator=(const MCInstAnalyzer &src) = default;
    MCInstAnalyzer(MCInstAnalyzer &&src) = default;

    /**
     * return true if instruction is a branch
     */
    bool isBranch(const cs_insn *inst) const;

    /**
     * return true if instruction is conditional, note that conditional
     * instructions inside IT block context info that is not available here.
     */
    bool isConditional(const cs_insn *inst) const;

    bool isDirectBranch(const cs_insn *inst) const;

    bool isValid(const cs_insn *inst) const;

    ISAInstWidth getMinxInstWidth(ISAType isa) const;

    const ISAType &getISA() const {
        return m_isa;
    }
    void setISA(const ISAType &isa) {
        m_isa = isa;
        m_inst_width = getMinxInstWidth(isa);
    }
    const ISAInstWidth &getInstWidth() const {
        return m_inst_width;
    }

    const std::string conditionCodeToString(const cs_insn *inst) const;
private:
    ISAType m_isa;
    ISAInstWidth m_inst_width;
};
}

