//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "disasm/common.h"
#include <vector>

namespace disasm {
class MCInst;
class CFGNode;

/**
 * MaximalBlockAnalyzer
 */
class MaximalBlockAnalyzer {
public:
    MaximalBlockAnalyzer();
    MaximalBlockAnalyzer(ISAType isa);
    virtual ~MaximalBlockAnalyzer() = default;
    MaximalBlockAnalyzer(const MaximalBlockAnalyzer &src) = default;
    MaximalBlockAnalyzer &operator=(const MaximalBlockAnalyzer &src) = default;
    MaximalBlockAnalyzer(MaximalBlockAnalyzer &&src) = default;

    bool isCall(const MCInst *inst) const noexcept;

    bool modifySP(const MCInst *inst) const;

    std::vector<const MCInst *> getPCRelativeLoadsInstructions
        (const CFGNode *cfg_node) const noexcept;

private:
    ISAType m_isa;
};
}



