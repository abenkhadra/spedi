//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "DisassemblyCFG.h"

namespace disasm {

CFGNode *DisassemblyCFG::getCFGNodeOf
    (const MaximalBlock *max_block) {
    return &(*(m_cfg.begin() + max_block->id()));
}

const CFGNode &DisassemblyCFG::getNodeAt(size_t index) const {
    return m_cfg[index];
}

const std::vector<CFGNode> &DisassemblyCFG::getCFG() const {
    return m_cfg;
}

CFGNode *DisassemblyCFG::ptrToNodeAt(size_t index) {
    return &(*(m_cfg.begin() + index));
}

bool DisassemblyCFG::isLast(const CFGNode *node) const noexcept {
    return m_cfg.back().id() == node->id();
}

std::vector<CFGNode>::const_iterator DisassemblyCFG::cbegin() const noexcept {
    return m_cfg.cbegin();
}

std::vector<CFGNode>::const_iterator DisassemblyCFG::cend() const noexcept {
    return m_cfg.cend();
}

const CFGNode &DisassemblyCFG::previous(const CFGNode &node) const {
    return *(m_cfg.begin() + node.id() - 1);
}

const CFGNode &DisassemblyCFG::next(const CFGNode &node) const {
    return *(m_cfg.begin() + node.id() + 1);
}
}
