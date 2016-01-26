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
    m_type{MaximalBlockType::kMaybe},
    m_known_start_addr{0},
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

MaximalBlock *MaximalBlockCFGNode::getOverlapMaximalBlock() const {
    return m_overlap_mblock;
}
bool MaximalBlockCFGNode::isData() const {
    return m_type == MaximalBlockType::kData;
}
bool MaximalBlockCFGNode::isCode() const {
    return m_type == MaximalBlockType::kCode;
}
void MaximalBlockCFGNode::setType(const MaximalBlockType type) {
    m_type = type;
}
MaximalBlockType MaximalBlockCFGNode::getType() const {
    return m_type;
}
std::vector<MCInstSmall> MaximalBlockCFGNode::getKnownInstructions() const {
    std::vector<MCInstSmall> result;
    if (m_known_start_addr == 0) {
        return result;
    }
    addr_t current = m_known_start_addr;
    for (auto &inst : m_current->getAllInstructions()) {
        if (inst.addr() == current) {
            result.push_back(inst);
            current += inst.size();
        }
    }
    return result;
}
addr_t MaximalBlockCFGNode::getKnownStartAddr() const {
    return m_known_start_addr;
}
}