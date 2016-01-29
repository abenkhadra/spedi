//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "DisassemblyCFG.h"

namespace disasm {

MaximalBlockCFGNode *DisassemblyCFG::getCFGNodeOf
    (const MaximalBlock *max_block) {
    return &(*(m_cfg.begin() + max_block->id()));
}

const MaximalBlockCFGNode &DisassemblyCFG::getNodeAt(size_t index) const {
    return m_cfg[index];
}
const std::vector<MaximalBlockCFGNode> &DisassemblyCFG::getCFG() const {
    return m_cfg;
}
MaximalBlockCFGNode *DisassemblyCFG::ptrToNodeAt(size_t index) {
    return &(*(m_cfg.begin() + index));
}

size_t DisassemblyCFG::calculateNodeWeight
    (const MaximalBlockCFGNode *node) const noexcept {
    unsigned pred_weight = 0;
    for (auto pred_iter = node->getPredecessors().begin();
         pred_iter < node->getPredecessors().end(); ++pred_iter) {
        pred_weight +=
            (*pred_iter).first->getMaximalBlock()->instructionsCount();
    }
    return node->getMaximalBlock()->instructionsCount() + pred_weight;
}
}
