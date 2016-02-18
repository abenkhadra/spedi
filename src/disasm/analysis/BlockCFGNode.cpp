//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "BlockCFGNode.h"
#include <cassert>

namespace disasm {
BlockCFGNode::BlockCFGNode() :
    m_type{BlockCFGNodeType::kMaybe},
    m_candidate_start_addr{0},
    m_overlap_node{nullptr},
    m_direct_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{nullptr} {
}

BlockCFGNode::BlockCFGNode(MaximalBlock *current_block) :
    m_type{BlockCFGNodeType::kMaybe},
    m_candidate_start_addr{0},
    m_overlap_node{nullptr},
    m_direct_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{current_block} {
}

void BlockCFGNode::addPredecessor(BlockCFGNode *predecessor,
                                  addr_t target_addr) {
    assert(m_max_block->isWithinAddressSpace(target_addr)
               && "Invalid target address");
    m_predecessors.emplace_back(std::pair<BlockCFGNode *, addr_t>(
        predecessor,
        target_addr));
}

void BlockCFGNode::setDirectSuccessor(BlockCFGNode *successor) {
    m_direct_successor = successor;
}

void BlockCFGNode::setRemoteSuccessor(BlockCFGNode *successor) {
    m_remote_successor = successor;
}

const MaximalBlock *BlockCFGNode::getMaximalBlock() const {
    return m_max_block;
}

const BlockCFGNode *BlockCFGNode::getOverlapNode() const {
    return m_overlap_node;
}

bool BlockCFGNode::isData() const {
    return m_type == BlockCFGNodeType::kData;
}

bool BlockCFGNode::isCode() const {
    return m_type == BlockCFGNodeType::kCode;
}

void BlockCFGNode::setType(const BlockCFGNodeType type) {
    m_type = type;
}

BlockCFGNodeType BlockCFGNode::getType() const {
    return m_type;
}

std::vector<const MCInst *> BlockCFGNode::getCandidateInstructions() const {
    std::vector<const MCInst *> result;
    addr_t current = m_candidate_start_addr;
    for (auto &inst : m_max_block->getAllInstructions()) {
        if (inst.addr() == current) {
            result.push_back(&inst);
            current += inst.size();
        }
    }
    return result;
}

std::vector<const MCInst *> BlockCFGNode::getCandidateInstructionsSatisfying
    (std::function<bool(const MCInst *)> predicate) const {
    std::vector<const MCInst *> result;
    addr_t current = m_candidate_start_addr;
    for (auto &inst : m_max_block->getAllInstructions()) {
        if (inst.addr() == current) {
            if (predicate(&inst)) {
                result.push_back(&inst);
            }
            current += inst.size();
        }
    }
    return result;
}

addr_t BlockCFGNode::getCandidateStartAddr() const noexcept {
    return m_candidate_start_addr;
}

void BlockCFGNode::setCandidateStartAddr(addr_t candidate_start) noexcept {
    // a candidate start address should be set to the first instruction that can
    // match it.
    for (auto &inst : m_max_block->getAllInstructions()) {
        if (candidate_start <= inst.addr()) {
            m_candidate_start_addr = candidate_start;
            break;
        }
    }
}

const BlockCFGNode *BlockCFGNode::getDirectSuccessor() const {
    return m_direct_successor;
}

const BlockCFGNode *BlockCFGNode::getRemoteSuccessor() const {
    return m_remote_successor;
}

const std::vector<std::pair<BlockCFGNode *, addr_t>> &
BlockCFGNode::getPredecessors() const {
    return m_predecessors;
}

void BlockCFGNode::setMaximalBlock(MaximalBlock *maximal_block) noexcept {
    m_max_block = maximal_block;
}

unsigned int BlockCFGNode::id() const noexcept {
    return m_max_block->id();
}

BlockCFGNode *BlockCFGNode::getOverlapNodePtr() const {
    return m_overlap_node;
}

bool BlockCFGNode::hasOverlapWithOtherNode() const noexcept {
    return m_overlap_node != nullptr;
}

bool BlockCFGNode::isCandidateStartAddressSet() const noexcept {
    return m_candidate_start_addr != 0;
}

bool BlockCFGNode::isCandidateStartAddressValid
    (addr_t candidate_addr) const noexcept {
    return candidate_addr <= m_max_block->addrOfLastInst();
}

void BlockCFGNode::setToDataAndInvalidatePredecessors() {
    if (m_type == BlockCFGNodeType::kData) {
        return;
    }
    m_type = BlockCFGNodeType::kData;
    for (auto pred_iter = m_predecessors.begin();
         pred_iter < m_predecessors.end(); ++pred_iter) {
        printf("CONFLICT: Invalidating %u predecessor of %u\n",
               (*pred_iter).first->id(),
               id());
        (*pred_iter).first->setToDataAndInvalidatePredecessors();
    }
}

void BlockCFGNode::resetCandidateStartAddress() {
    m_candidate_start_addr = 0;
}
}
