//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#pragma once
#include <capstone/capstone.h>
#include "BranchData.h"

struct cs_insn;

namespace disasm {
/**
 * RawInstAnalyzer
 */
class RawInstAnalyzer {
public:
    /**
     * Construct a RawInstAnalyzer
     */
    RawInstAnalyzer() = default;
    explicit RawInstAnalyzer(ISAType isa);
    virtual ~RawInstAnalyzer() = default;
    RawInstAnalyzer(const RawInstAnalyzer &src) = default;
    RawInstAnalyzer &operator=(const RawInstAnalyzer &src) = default;
    RawInstAnalyzer(RawInstAnalyzer &&src) = default;

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

    ISAType getISA() const {
        return m_isa;
    }

    void setISA(const ISAType isa);

    // valid only for ARM architecture which has two modes Thumb & ARM
    void changeModeTo(const ISAType &isa);
    const ISAInstWidth &getInstWidth() const {
        return m_inst_width;
    }

    const std::string conditionCodeToString(const arm_cc &condition) const;
private:
    ISAType m_isa;
    ISAInstWidth m_inst_width;
};
}

