//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "MaximalBlockCFGNode.h"
#include <cassert>
namespace disasm {
MaximalBlockCFGNode::MaximalBlockCFGNode(MaximalBlock *current_block) :
    m_overlap_mblock{nullptr},
    m_direct_successor{nullptr},
    m_remote_successor{nullptr},
    m_current{current_block} {
}
void MaximalBlockCFGNode::addPredecessor(MaximalBlock *predecessor,
                                         addr_t target_addr) {
    assert(m_current->isWithinAddressSpace(target_addr)
               && "Invalid target address");
    m_predecessors.emplace_back(std::pair<MaximalBlock *, addr_t>(predecessor,
                                                                  target_addr));
}
void MaximalBlockCFGNode::setDirectSuccessor(MaximalBlock *successor) {
    m_direct_successor = successor;
}
void MaximalBlockCFGNode::setRemoteSuccessor(MaximalBlock *successor) {
    m_remote_successor = successor;
}

void MaximalBlockCFGNode::setOverlapMaximalBlock(MaximalBlock *overlap_block) {
    m_overlap_mblock = overlap_block;
}
const MaximalBlock *MaximalBlockCFGNode::getMaximalBlock() const {
    return m_current;
}

MaximalBlock * MaximalBlockCFGNode::getOverlapMaximalBlock() const {
    return m_overlap_mblock;
}
}