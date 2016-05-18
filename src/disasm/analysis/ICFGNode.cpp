//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "ICFGNode.h"
#include <sstream>

namespace disasm {

ICFGNode::ICFGNode(): m_entry_node{nullptr} {
}

ICFGNode::ICFGNode(addr_t entry_addr,
                   CFGNode *entry_node,
                   ICFGProcedureType type) :
    m_proc_type{type},
    m_valid{false},
    m_non_return_proc{false},
    m_returns_to_caller{false},
    m_entry_node{entry_node},
    m_end_node{nullptr},
    m_entry_addr{entry_addr},
    m_end_addr{0},
    m_estimated_end_addr{0},
    m_lr_store_idx{0},
    m_has_overlap{false} {

    if (m_entry_node == nullptr) {
        m_proc_type = ICFGProcedureType::kExternal;
    } else {
        entry_node->m_role_in_procedure = CFGNodeRoleInProcedure::kEntry;
        entry_node->m_procedure_id = entry_addr;
        // XXX this should typically be the case.
        entry_node->m_candidate_start_addr = entry_addr;
        m_end_node = m_entry_node;
        m_end_addr = m_entry_node->maximalBlock()->endAddr();
    }
    std::ostringstream out;
    out << "proc_" << std::hex << m_entry_addr;
    m_name = out.str();
}

ICFGNode::ICFGNode(CFGNode *entry_node, ICFGProcedureType type) :
    m_proc_type{type},
    m_valid{false},
    m_non_return_proc{false},
    m_returns_to_caller{false},
    m_entry_node{entry_node},
    m_end_node{nullptr},
    m_entry_addr{entry_node->getCandidateStartAddr()},
    m_end_addr{0},
    m_estimated_end_addr{0},
    m_lr_store_idx{0},
    m_has_overlap{false} {

    entry_node->m_role_in_procedure = CFGNodeRoleInProcedure::kEntry;
    entry_node->m_procedure_id = entry_node->getCandidateStartAddr();
    m_end_node = m_entry_node;
    m_end_addr = m_entry_node->maximalBlock()->endAddr();
    std::ostringstream out;
    out << "proc_" << std::hex << m_entry_addr;
    m_name = out.str();
}

size_t ICFGNode::id() const noexcept {
    return m_entry_addr;
}

bool ICFGNode::isWithinEstimatedAddressSpace(const addr_t addr) const noexcept {
    return addr < m_estimated_end_addr
        && addr >= m_entry_addr;
}

void ICFGNode::addCaller(const CFGNode *caller) noexcept {
    m_callers.push_back(caller);
}

bool ICFGNode::operator==(const ICFGNode &src) const noexcept {
    return this->m_entry_addr == src.m_entry_addr;
}

bool ICFGNode::operator<(const ICFGNode &src) const noexcept {
    return this->m_entry_addr < src.m_entry_addr;
}

CFGNode *ICFGNode::entryNode() const noexcept {
    return m_entry_node;
}

CFGNode *ICFGNode::endNode() const noexcept {
    return m_end_node;
}

bool ICFGNode::isBuilt() const noexcept {
    return m_valid;
}

bool ICFGNode::isValid() const noexcept {
    return m_entry_node != nullptr;
}

addr_t ICFGNode::entryAddr() const noexcept {
    return m_entry_addr;
}

addr_t ICFGNode::endAddr() const noexcept {
    return m_end_addr;
}

addr_t ICFGNode::estimatedEndAddr() const noexcept {
    return m_estimated_end_addr;
}

void ICFGNode::setName(const char *name) noexcept {
    // XXX: assuming name points to well-formed .dynstr section
    m_name = name;
}

void ICFGNode::setNonReturn(bool non_return) noexcept {
    m_non_return_proc = non_return;
}

void ICFGNode::setReturnsToCaller(bool returns_to_caller) noexcept {
    m_returns_to_caller = returns_to_caller;
}

const std::string &ICFGNode::name() const noexcept {
    return m_name;
}

ICFGProcedureType ICFGNode::type() const noexcept {
    return m_proc_type;
}

void ICFGNode::finalize() noexcept {
    m_valid = true;
}

bool ICFGNode::isNonReturnProcedure() const noexcept {
    return m_non_return_proc;
}

bool ICFGNode::isReturnsToCaller() const noexcept {
    return m_returns_to_caller;
}

const std::vector<std::pair<ICFGExitNodeType, CFGNode *>> &
ICFGNode::getExitNodes() const noexcept {
    return m_exit_nodes;
}
}
