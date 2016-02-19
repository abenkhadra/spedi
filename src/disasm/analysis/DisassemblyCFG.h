//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "CFGNode.h"

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

    const CFGNode &getNodeAt(size_t index) const;
    const std::vector<CFGNode> &getCFG() const;
    /*
     * Valid only after building CFG.
     */
    bool isValid() const { return m_valid; }
    bool isLast(const CFGNode *node) const noexcept;
    std::vector<CFGNode>::const_iterator cbegin() const noexcept;
    std::vector<CFGNode>::const_iterator cend() const noexcept;
    const CFGNode &previous(const CFGNode &node) const;
    const CFGNode &next(const CFGNode &node) const;
    friend class SectionDisassemblyAnalyzer;
private:
    CFGNode *getCFGNodeOf(const MaximalBlock *max_block);
    CFGNode *ptrToNodeAt(size_t index);

private:
    bool m_valid;
    std::vector<CFGNode> m_cfg;
};
}
