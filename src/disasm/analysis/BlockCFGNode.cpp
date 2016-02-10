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
    m_type{MaximalBlockType::kMaybe},
    m_candidate_start_addr{0},
    m_valid_basic_block_ptr{nullptr},
    m_overlap_node{nullptr},
    m_direct_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{nullptr} {
}

BlockCFGNode::BlockCFGNode(MaximalBlock *current_block) :
    m_type{MaximalBlockType::kMaybe},
    m_candidate_start_addr{0},
    m_valid_basic_block_ptr{nullptr},
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
    return m_type == MaximalBlockType::kData;
}

bool BlockCFGNode::isCode() const {
    return m_type == MaximalBlockType::kCode;
}

void BlockCFGNode::setType(const MaximalBlockType type) {
    m_type = type;
}

MaximalBlockType BlockCFGNode::getType() const {
    return m_type;
}

std::vector<const MCInst *> BlockCFGNode::getCandidateInstructions() const {
    std::vector<const MCInst *> result;
    addr_t current = m_candidate_start_addr;
    for (auto &inst : getMaximalBlock()->getAllInstructions()) {
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
    for (auto &inst : getMaximalBlock()->getAllInstructions()) {
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
    m_candidate_start_addr = candidate_start;
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

bool BlockCFGNode::isValidBasicBlockSet() const noexcept {
    return m_valid_basic_block_ptr != nullptr;
}

bool BlockCFGNode::hasOverlapWithOtherNode() const noexcept {
    return m_overlap_node != nullptr;
}

const BasicBlock *BlockCFGNode::getValidBasicBlock() const noexcept {
    return m_valid_basic_block_ptr;
}

bool BlockCFGNode::givenCandidateStartAddressIsValid() const noexcept {
    return m_candidate_start_addr < m_max_block->addrOfLastInst();
}

void BlockCFGNode::adjustCandidateStartAddress() noexcept {
    for (auto addr : m_valid_basic_block_ptr->getInstructionAddresses()) {
        if (m_candidate_start_addr <= addr) {
            m_candidate_start_addr = addr;
            break;
        }
    }
}
}
