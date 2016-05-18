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
#include <disasm/MCInst.h>

namespace disasm {
class MCInst;
class CFGNode;

/**
 * DisassemblyAnalysisHelperARM
 */
class DisassemblyAnalysisHelperARM {
public:
    DisassemblyAnalysisHelperARM();
    DisassemblyAnalysisHelperARM(ISAType isa);
    virtual ~DisassemblyAnalysisHelperARM() = default;
    DisassemblyAnalysisHelperARM(const DisassemblyAnalysisHelperARM &src) =
    default;
    DisassemblyAnalysisHelperARM
        &operator=(const DisassemblyAnalysisHelperARM &src) = default;
    DisassemblyAnalysisHelperARM(DisassemblyAnalysisHelperARM &&src) = default;
    bool modifySP(const MCInst *inst) const;
    std::vector<const MCInst *> getPCRelativeLoadsInstructions
        (const CFGNode *cfg_node) const noexcept;
    // returns 0 if valid instructions do not store LR, otherwise returns the
    // index of LR on the stack.
    unsigned getLRStackStoreIndex(const CFGNode *cfg_node) const noexcept;
    addr_t recoverLDRSwitchBaseAddr(const CFGNode &node) const;
    bool isReturnToCaller(const MCInst *inst) const noexcept;
    bool isIndirectTailCall(const MCInst *inst) const noexcept;
private:
    ISAType m_isa;
};
}
