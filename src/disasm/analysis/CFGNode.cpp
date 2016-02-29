//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "CFGNode.h"
#include <cassert>

namespace disasm {
CFGNode::CFGNode() :
    m_type{CFGNodeKind::kMaybe},
    m_candidate_start_addr{0},
    m_overlap_node{nullptr},
    m_procedure{nullptr},
    m_traversal_status{TraversalStatus::kUnvisited},
    m_immediate_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{nullptr} {
    m_indirect_preds = std::make_pair(nullptr, IndirectBranchType::kOther);
}

CFGNode::CFGNode(MaximalBlock *current_block) :
    m_type{CFGNodeKind::kMaybe},
    m_candidate_start_addr{0},
    m_overlap_node{nullptr},
    m_procedure{nullptr},
    m_traversal_status{TraversalStatus::kUnvisited},
    m_immediate_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{current_block} {
    m_indirect_preds = std::make_pair(nullptr, IndirectBranchType::kOther);
}

void CFGNode::addDirectPredecessor(CFGNode *predecessor, addr_t target_addr) {
    assert(m_max_block->isWithinAddressSpace(target_addr)
               && "Invalid target address");
    m_direct_predecessors.emplace_back(std::pair<CFGNode *, addr_t>(
        predecessor,
        target_addr));
}

void CFGNode::setImmediateSuccessor(CFGNode *successor) {
    m_immediate_successor = successor;
}

void CFGNode::setRemoteSuccessor(CFGNode *successor) {
    m_remote_successor = successor;
}

const MaximalBlock *CFGNode::getMaximalBlock() const {
    return m_max_block;
}

const CFGNode *CFGNode::getOverlapNode() const {
    return m_overlap_node;
}

bool CFGNode::isData() const {
    return m_type == CFGNodeKind::kData;
}

bool CFGNode::isCode() const {
    return m_type == CFGNodeKind::kCode;
}

void CFGNode::setType(const CFGNodeKind type) {
    m_type = type;
}

CFGNodeKind CFGNode::getType() const {
    return m_type;
}

std::vector<const MCInst *> CFGNode::getCandidateInstructions() const {
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

std::vector<const MCInst *> CFGNode::getCandidateInstructionsSatisfying
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

addr_t CFGNode::getCandidateStartAddr() const noexcept {
    return m_candidate_start_addr;
}

void CFGNode::setCandidateStartAddr(addr_t candidate_start) noexcept {
    // a candidate start address should be set to the first instruction that can
    // match it.
    for (auto &inst : m_max_block->getAllInstructions()) {
        if (candidate_start <= inst.addr()) {
            m_candidate_start_addr = inst.addr();
            break;
        }
    }
}

const CFGNode *CFGNode::getImmediateSuccessor() const {
    return m_immediate_successor;
}

const CFGNode *CFGNode::getRemoteSuccessor() const {
    return m_remote_successor;
}

const std::vector<std::pair<CFGNode *, addr_t>> &
CFGNode::getDirectPredecessors() const noexcept {
    return m_direct_predecessors;
}

void CFGNode::setMaximalBlock(MaximalBlock *maximal_block) noexcept {
    m_max_block = maximal_block;
}

size_t CFGNode::id() const noexcept {
    return m_max_block->id();
}

CFGNode *CFGNode::getOverlapNodePtr() const noexcept {
    return m_overlap_node;
}

bool CFGNode::hasOverlapWithOtherNode() const noexcept {
    return m_overlap_node != nullptr;
}

bool CFGNode::isCandidateStartAddressSet() const noexcept {
    return m_candidate_start_addr != 0;
}

bool CFGNode::isCandidateStartAddressValid
    (addr_t candidate_addr) const noexcept {
    return candidate_addr <= m_max_block->addrOfLastInst();
}

void CFGNode::setToDataAndInvalidatePredecessors() {
    if (m_type == CFGNodeKind::kData) {
        return;
    }
    m_type = CFGNodeKind::kData;
    for (auto pred_iter = m_direct_predecessors.begin();
         pred_iter < m_direct_predecessors.end(); ++pred_iter) {
        printf("CONFLICT: Invalidating %lu predecessor of %lu\n",
               (*pred_iter).first->id(),
               id());
        (*pred_iter).first->setToDataAndInvalidatePredecessors();
    }
}

void CFGNode::resetCandidateStartAddress() {
    m_candidate_start_addr = 0;
}

bool CFGNode::operator==(const CFGNode &src) const noexcept {
    return this->id() == src.id();
}

bool CFGNode::isAssignedToProcedure() const noexcept {
    return m_procedure != nullptr;
}

bool CFGNode::isPossibleCall() const noexcept {
    return m_max_block->getBranchInstruction()->id() == ARM_INS_BLX
        || m_max_block->getBranchInstruction()->id() == ARM_INS_BL;
}

bool CFGNode::isPossibleReturn() const noexcept {
    return m_indirect_preds.first != nullptr
        && m_indirect_preds.second == IndirectBranchType::kCall;
}

size_t CFGNode::getCountOfCandidateInstructions() const noexcept {
    size_t result = 0;
    addr_t current = m_candidate_start_addr;
    for (auto &inst : m_max_block->getAllInstructions()) {
        if (inst.addr() == current) {
            current += inst.size();
            result++;
        }
    }
    return result;
}

void CFGNode::setAsReturnNodeFrom(CFGNode *cfg_node) {
    m_indirect_preds.first = cfg_node;
    m_indirect_preds.second = IndirectBranchType::kCall;
    cfg_node->m_indirect_succs.push_back(
        std::make_pair(this, IndirectBranchType::kCall));
}

bool CFGNode::isSwitchStatement() const noexcept {
    return m_indirect_succs.size() > 1;
}

bool CFGNode::isSwitchCaseStatement() const noexcept {
    return m_indirect_preds.second == IndirectBranchType::kSwitchStatement;
}

void CFGNode::setAsSwitchCaseFor(CFGNode *cfg_node) {
    m_indirect_preds.first = cfg_node;
    m_indirect_preds.second = IndirectBranchType::kSwitchStatement;
    cfg_node->m_indirect_succs.push_back(
        std::make_pair(this, IndirectBranchType::kSwitchStatement));
}
}
