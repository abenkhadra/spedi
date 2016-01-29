//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "MaximalBlockCFGNode.h"

namespace disasm {
/**
 * DisassemblyCFG
 */
class DisassemblyCFG {
public:
    /**
     * Construct a DisassemblyCFG that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    DisassemblyCFG() = default;
    virtual ~DisassemblyCFG() = default;
    DisassemblyCFG(const DisassemblyCFG &src) = default;
    DisassemblyCFG
        &operator=(const DisassemblyCFG &src) = default;
    DisassemblyCFG(DisassemblyCFG &&src) = default;

    const MaximalBlockCFGNode &getNodeAt(size_t index) const;
    const std::vector<MaximalBlockCFGNode> &getCFG() const;
    /*
     * Valid only after building CFG.
     */
    bool isValid() const { return m_valid; }
    size_t calculateNodeWeight(const MaximalBlockCFGNode *node) const noexcept;

    friend class SectionDisassemblyAnalyzer;
private:
    MaximalBlockCFGNode *getCFGNodeOf(const MaximalBlock *max_block);
    MaximalBlockCFGNode *ptrToNodeAt(size_t index);

private:
    bool m_valid;
    std::vector<MaximalBlockCFGNode> m_cfg;
};
}



