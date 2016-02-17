//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "BlockCFGNode.h"

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

    const BlockCFGNode &getNodeAt(size_t index) const;
    const std::vector<BlockCFGNode> &getCFG() const;
    /*
     * Valid only after building CFG.
     */
    bool isValid() const { return m_valid; }
    bool isLast(const BlockCFGNode *node) const noexcept;
    std::vector<BlockCFGNode>::const_iterator cbegin() const noexcept;
    std::vector<BlockCFGNode>::const_iterator cend() const noexcept;
    const BlockCFGNode &previous(const BlockCFGNode &node) const;
    const BlockCFGNode &next(const BlockCFGNode &node) const;
    friend class SectionDisassemblyAnalyzer;
private:
    BlockCFGNode *getCFGNodeOf(const MaximalBlock *max_block);
    BlockCFGNode *ptrToNodeAt(size_t index);

private:
    bool m_valid;
    std::vector<BlockCFGNode> m_cfg;
};
}



