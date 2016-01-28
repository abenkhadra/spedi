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
MaximalBlockCFGNode::MaximalBlockCFGNode() :
    m_type{MaximalBlockType::kMaybe},
    m_known_start_addr{0},
    m_valid_basic_block_id{0},
    m_overlap_node{nullptr},
    m_direct_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{nullptr} {
}

MaximalBlockCFGNode::MaximalBlockCFGNode(MaximalBlock *current_block) :
    m_type{MaximalBlockType::kMaybe},
    m_known_start_addr{0},
    m_valid_basic_block_id{0},
    m_overlap_node{nullptr},
    m_direct_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{current_block} {
}

void MaximalBlockCFGNode::addPredecessor(MaximalBlockCFGNode *predecessor,
                                         addr_t target_addr) {
    assert(m_max_block->isWithinAddressSpace(target_addr)
               && "Invalid target address");
    m_predecessors.emplace_back(std::pair<MaximalBlockCFGNode *, addr_t>(
        predecessor,
        target_addr));
}

void MaximalBlockCFGNode::setDirectSuccessor(MaximalBlockCFGNode *successor) {
    m_direct_successor = successor;
}

void MaximalBlockCFGNode::setRemoteSuccessor(MaximalBlockCFGNode *successor) {
    m_remote_successor = successor;
}

const MaximalBlock *MaximalBlockCFGNode::getMaximalBlock() const {
    return m_max_block;
}

const MaximalBlockCFGNode *MaximalBlockCFGNode::getOverlapCFGNode() const {
    return m_overlap_node;
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
    for (auto &inst : m_max_block->getAllInstructions()) {
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

const MaximalBlockCFGNode *MaximalBlockCFGNode::getDirectSuccessor() const {
    return m_direct_successor;
}

const MaximalBlockCFGNode *MaximalBlockCFGNode::getRemoteSuccessor() const {
    return m_remote_successor;
}

const std::vector<std::pair<MaximalBlockCFGNode *, addr_t>> &
MaximalBlockCFGNode::getPredecessors() const {
    return m_predecessors;
}

void MaximalBlockCFGNode::setMaximalBlock(MaximalBlock *maximal_block) noexcept {
    m_max_block = maximal_block;
}

unsigned int MaximalBlockCFGNode::getId() const noexcept {
    return m_max_block->getId();
}

MaximalBlockCFGNode *MaximalBlockCFGNode::ptrToOverlapNode() const {
    return m_overlap_node;
}
}