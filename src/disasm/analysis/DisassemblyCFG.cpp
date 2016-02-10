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

size_t DisassemblyCFG::calculateNodeWeight
    (const BlockCFGNode *node) const noexcept {
    if (node->isData()) {
        return 0;
    }
    unsigned pred_weight = 0;
    for (auto pred_iter = node->getPredecessors().begin();
         pred_iter < node->getPredecessors().end(); ++pred_iter) {
        pred_weight +=
            (*pred_iter).first->getMaximalBlock()->instructionsCount();
    }
    return node->getMaximalBlock()->instructionsCount() + pred_weight;
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
}
