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
 * DisassemblyAnalyzerHelperARM
 */
class DisassemblyAnalyzerHelperARM {
public:
    DisassemblyAnalyzerHelperARM();
    DisassemblyAnalyzerHelperARM(ISAType isa);
    virtual ~DisassemblyAnalyzerHelperARM() = default;
    DisassemblyAnalyzerHelperARM(const DisassemblyAnalyzerHelperARM &src) =
    default;
    DisassemblyAnalyzerHelperARM
        &operator=(const DisassemblyAnalyzerHelperARM &src) = default;
    DisassemblyAnalyzerHelperARM(DisassemblyAnalyzerHelperARM &&src) = default;
    bool modifySP(const MCInst *inst) const;
    std::vector<const MCInst *> getPCRelativeLoadsInstructions
        (const CFGNode *cfg_node) const noexcept;
    // returns 0 if valid instructions do not store LR, otherwise returns the
    // index of LR on the stack.
    unsigned getLRStackStoreIndex(const CFGNode *cfg_node) const noexcept;
    addr_t recoverLDRSwitchBaseAddr(const CFGNode &node) const;
    bool isReturn(const MCInst *inst) const noexcept;
    bool isCall(const MCInst *inst) const noexcept;
private:
    ISAType m_isa;
};
}
