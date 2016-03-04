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
 * MCInstAnalyzerARM
 */
class MCInstAnalyzerARM {
public:
    MCInstAnalyzerARM();
    MCInstAnalyzerARM(ISAType isa);
    virtual ~MCInstAnalyzerARM() = default;
    MCInstAnalyzerARM(const MCInstAnalyzerARM &src) = default;
    MCInstAnalyzerARM &operator=(const MCInstAnalyzerARM &src) = default;
    MCInstAnalyzerARM(MCInstAnalyzerARM &&src) = default;
    bool modifySP(const MCInst *inst) const;
    std::vector<const MCInst *> getPCRelativeLoadsInstructions
        (const CFGNode *cfg_node) const noexcept;
    addr_t recoverLDRSwitchBaseAddr(const CFGNode &node) const;
private:
    ISAType m_isa;
};
}
