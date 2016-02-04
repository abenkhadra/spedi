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
    m_valid_basic_block_ptr{nullptr},
    m_overlap_node{nullptr},
    m_direct_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{nullptr} {
}

MaximalBlockCFGNode::MaximalBlockCFGNode(MaximalBlock *current_block) :
    m_type{MaximalBlockType::kMaybe},
    m_known_start_addr{0},
    m_valid_basic_block_ptr{nullptr},
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

const MaximalBlockCFGNode *MaximalBlockCFGNode::getOverlapNode() const {
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

std::vector<const MCInst *> MaximalBlockCFGNode::getValidInstructions() const {
    std::vector<const MCInst *> result;
    addr_t current = getValidBasicBlock()->startAddr();
    if (current < getKnownStartAddr()) {
        current = getValidBasicBlock()->addressAt(1);
    }
    for (auto &inst : getMaximalBlock()->getAllInstructions()) {
        if (inst.addr() == current) {
            result.push_back(&inst);
            current += inst.size();
        }
    }
    return result;
}

addr_t MaximalBlockCFGNode::getKnownStartAddr() const noexcept {
    return m_known_start_addr;
}

void MaximalBlockCFGNode::setKnownStartAddr(addr_t known_start) noexcept {
    m_known_start_addr = known_start;
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

unsigned int MaximalBlockCFGNode::id() const noexcept {
    return m_max_block->id();
}

MaximalBlockCFGNode *MaximalBlockCFGNode::getOverlapNodePtr() const {
    return m_overlap_node;
}

bool MaximalBlockCFGNode::isValidBasicBlockSet() const noexcept {
    return m_valid_basic_block_ptr != nullptr;
}

bool MaximalBlockCFGNode::hasOverlapWithOtherNode() const noexcept {
    return m_overlap_node != nullptr;
}

const BasicBlock *MaximalBlockCFGNode::getValidBasicBlock() const noexcept {
    return m_valid_basic_block_ptr;
}
}