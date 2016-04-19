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
    m_type{CFGNodeType::kUnknown},
    m_is_call{false},
    m_traversal_status{TraversalStatus::kUnvisited},
    m_role_in_procedure{CFGNodeRoleInProcedure::kUnknown},
    m_candidate_start_addr{0},
    m_overlap_node{nullptr},
    m_node_appendable_by_this{nullptr},
    m_procedure_id{0},
    m_immediate_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{nullptr} {
}

CFGNode::CFGNode(MaximalBlock *current_block) :
    m_type{CFGNodeType::kUnknown},
    m_is_call{false},
    m_traversal_status{TraversalStatus::kUnvisited},
    m_role_in_procedure{CFGNodeRoleInProcedure::kUnknown},
    m_candidate_start_addr{0},
    m_overlap_node{nullptr},
    m_node_appendable_by_this{nullptr},
    m_procedure_id{0},
    m_immediate_successor{nullptr},
    m_remote_successor{nullptr},
    m_max_block{current_block} {
}

void CFGNode::addRemotePredecessor(CFGNode *predecessor, addr_t target_addr) {
    m_direct_preds.emplace_back
        (CFGEdge(CFGEdgeType::kDirect, predecessor, target_addr));
}

void CFGNode::addImmediatePredecessor
    (CFGNode *predecessor, addr_t target_addr) {
    m_direct_preds.emplace_back
        (CFGEdge(CFGEdgeType::kConditional, predecessor, target_addr));
}

void CFGNode::setImmediateSuccessor(CFGNode *successor) {
    m_immediate_successor = successor;
}

void CFGNode::setRemoteSuccessor(CFGNode *successor) {
    m_remote_successor = successor;
}

const MaximalBlock *CFGNode::maximalBlock() const {
    return m_max_block;
}

const CFGNode *CFGNode::getOverlapNode() const {
    return m_overlap_node;
}

bool CFGNode::isData() const {
    return m_type == CFGNodeType::kData;
}

bool CFGNode::isCode() const {
    return m_type == CFGNodeType::kCode;
}

void CFGNode::setType(const CFGNodeType type) {
    m_type = type;
}

CFGNodeType CFGNode::getType() const {
    return m_type;
}

std::vector<const MCInst *> CFGNode::getCandidateInstructions() const {
    std::vector<const MCInst *> result;
    addr_t current = m_candidate_start_addr;
    for (const auto &inst : m_max_block->getAllInstructions()) {
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
    for (const auto &inst : m_max_block->getAllInstructions()) {
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
    for (const auto &inst : m_max_block->getAllInstructions()) {
        if (candidate_start <= inst.addr()) {
            m_candidate_start_addr = inst.addr();
            break;
        }
    }
}

const CFGNode *CFGNode::immediateSuccessor() const {
    return m_immediate_successor;
}

const CFGNode *CFGNode::remoteSuccessor() const {
    return m_remote_successor;
}

const std::vector<CFGEdge> &
CFGNode::getDirectPredecessors() const noexcept {
    return m_direct_preds;
}

const std::vector<CFGEdge> &
CFGNode::getIndirectPredecessors() const noexcept {
    return m_indirect_preds;
}

const std::vector<CFGEdge> &CFGNode::getIndirectSuccessors() const noexcept {
    return m_indirect_succs;
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

bool CFGNode::isProcedureEntry() const noexcept {
    return m_role_in_procedure == CFGNodeRoleInProcedure::kEntry
        || m_role_in_procedure == CFGNodeRoleInProcedure::kEntryCandidate;
}

bool CFGNode::isProcedureEntryCandidate() const noexcept {
    return m_role_in_procedure == CFGNodeRoleInProcedure::kEntryCandidate;
}

bool CFGNode::isCandidateStartAddressValid
    (addr_t candidate_addr) const noexcept {
    return candidate_addr <= m_max_block->addrOfLastInst();
}

void CFGNode::setToDataAndInvalidatePredecessors() {
    m_type = CFGNodeType::kData;
    for (auto pred_iter = m_direct_preds.begin();
         pred_iter < m_direct_preds.end(); ++pred_iter) {
        if (!(*pred_iter).node()->isData()
            && (*pred_iter).type() == CFGEdgeType::kDirect
            || (*pred_iter).type() == CFGEdgeType::kConditional) {
//            printf("Invalidating predecessors of %lu at %lx: pred %lu\n",
//                   this->id(),
//                   this->maximalBlock()->addrOfLastInst(),
//                   (*pred_iter).node()->id());
            (*pred_iter).node()->setToDataAndInvalidatePredecessors();
        }
    }
}

void CFGNode::resetCandidateStartAddress() {
    m_candidate_start_addr = 0;
}

bool CFGNode::operator==(const CFGNode &src) const noexcept {
    return this->id() == src.id();
}

bool CFGNode::isAssignedToProcedure() const noexcept {
    return m_procedure_id != 0;
}

bool CFGNode::isCall() const noexcept {
    return m_is_call;
}

bool CFGNode::isPossibleReturn() const noexcept {
    return m_node_appendable_by_this != nullptr;
}

const CFGNode *CFGNode::getPreceedingCallNode() const noexcept {
    return m_node_appendable_by_this;
}

size_t CFGNode::getCountOfCandidateInstructions() const noexcept {
    size_t result = 0;
    addr_t current = m_candidate_start_addr;
    for (const auto &inst : m_max_block->getAllInstructions()) {
        if (inst.addr() == current) {
            current += inst.size();
            result++;
        }
    }
    return result;
}

void CFGNode::setAsReturnNodeFrom(CFGNode &cfg_node) {
    m_node_appendable_by_this = &cfg_node;
    cfg_node.m_indirect_succs.emplace_back
        (CFGEdge(CFGEdgeType::kReturn,
                 this,
                 cfg_node.maximalBlock()->endAddr()));
    cfg_node.m_is_call = true;
}

void CFGNode::setAsSwitchCaseFor(CFGNode *cfg_node, const addr_t target_addr) {
//    printf("Node: %lu at %lx Target: %lx\n", cfg_node->id(),
//           cfg_node->maximalBlock()->endAddr(), target_addr);
    m_indirect_preds.emplace_back
        (CFGEdge(CFGEdgeType::kSwitchTable, cfg_node, target_addr));
    cfg_node->m_indirect_succs.emplace_back
        (CFGEdge(CFGEdgeType::kSwitchTable, this, target_addr));
}

bool CFGNode::hasPredecessors() const noexcept {
    return !(m_node_appendable_by_this == nullptr
        && m_indirect_preds.size() == 0
        && m_direct_preds.size() == 0);
}

bool CFGNode::isSwitchStatement() const noexcept {
    return m_indirect_succs.size() > 1;
}

bool CFGNode::isSwitchBranchTarget() const noexcept {
    for (const auto &cfg_edge : m_indirect_preds) {
        if (cfg_edge.type() == CFGEdgeType::kSwitchTable)
            return true;
    }
    return false;
}

addr_t CFGNode::getMinTargetAddrOfValidPredecessor() const noexcept {
    addr_t minimum_addr = UINT64_MAX;
    for (const auto &pred : m_indirect_preds) {
        if (pred.targetAddr() < minimum_addr) {
            minimum_addr = pred.targetAddr();
        }
    }
    if (minimum_addr != UINT64_MAX) {
        return minimum_addr;
    }
    for (const auto &pred : m_direct_preds) {
        if (pred.targetAddr() < minimum_addr
            && pred.node()->getType() != CFGNodeType::kData
            && pred.type() != CFGEdgeType::kConditional
            && pred.node()->id() != this->id()) {
            minimum_addr = pred.targetAddr();
        }
    }
    if (minimum_addr == UINT64_MAX) {
        return 0;
    }
    return minimum_addr;
}

bool CFGNode::isImmediateSuccessorSet() const noexcept {
    return m_immediate_successor != nullptr;
}

bool CFGNode::isProcedureEntryNode() const noexcept {
    return m_role_in_procedure == CFGNodeRoleInProcedure::kEntry;
}

bool CFGNode::isAppendableBy(const CFGNode *cfg_node) const {
    return m_max_block->endAddr() ==
        cfg_node->maximalBlock()->addrOfFirstInst();
}

CFGNode *CFGNode::getReturnSuccessorNode() const noexcept {
    if (m_indirect_succs.size() == 1
        && m_indirect_succs[0].type() == CFGEdgeType::kReturn) {
        return m_indirect_succs[0].node();
    }
    return nullptr;
}

bool CFGNode::isRoleInProcedureSet() const noexcept {
    return m_role_in_procedure != CFGNodeRoleInProcedure::kUnknown;
}

addr_t CFGNode::procedure_id() const noexcept {
    return m_procedure_id;
}
}
