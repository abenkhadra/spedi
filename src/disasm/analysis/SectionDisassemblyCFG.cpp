//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "SectionDisassemblyCFG.h"

namespace disasm {

MaximalBlockCFGNode *SectionDisassemblyCFG::getCFGNodeOf
    (const MaximalBlock *max_block) {
    return &(*(m_cfg.begin() + max_block->getId()));
}

const MaximalBlockCFGNode &SectionDisassemblyCFG::nodeAt(size_t index) const {
    return m_cfg[index];
}
const std::vector<MaximalBlockCFGNode> &SectionDisassemblyCFG::getCFG() const {
    return m_cfg;
}
}