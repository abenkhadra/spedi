//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "DisassemblyCFG.h"

namespace disasm {

BlockCFGNode *DisassemblyCFG::getCFGNodeOf
    (const MaximalBlock *max_block) {
    return &(*(m_cfg.begin() + max_block->id()));
}

const BlockCFGNode &DisassemblyCFG::getNodeAt(size_t index) const {
    return m_cfg[index];
}

const std::vector<BlockCFGNode> &DisassemblyCFG::getCFG() const {
    return m_cfg;
}

BlockCFGNode *DisassemblyCFG::ptrToNodeAt(size_t index) {
    return &(*(m_cfg.begin() + index));
}

bool DisassemblyCFG::isLast(const BlockCFGNode *node) const noexcept {
    return m_cfg.back().id() == node->id();
}

std::vector<BlockCFGNode>::const_iterator DisassemblyCFG::cbegin() const noexcept {
    return m_cfg.cbegin();
}

std::vector<BlockCFGNode>::const_iterator DisassemblyCFG::cend() const noexcept {
    return m_cfg.cend();
}

const BlockCFGNode &DisassemblyCFG::previous(const BlockCFGNode &node) const {
    return *(m_cfg.begin() + node.id() - 1);
}

const BlockCFGNode &DisassemblyCFG::next(const BlockCFGNode &node) const {
    return *(m_cfg.begin() + node.id() + 1);
}
}
