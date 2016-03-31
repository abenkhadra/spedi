//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "ICFGNode.h"
#include "CFGNode.h"
#include <sstream>

namespace disasm {

ICFGNode::ICFGNode(addr_t entry_addr) :
    m_proc_type{ICFGProcedureType::kUnknown},
    m_entry_node{nullptr},
    m_entry_addr{entry_addr},
    m_end_addr{0},
    m_lr_store_idx{0},
    m_has_overlap{false} {
    std::ostringstream out;
    out << "proc_" << std::hex << m_entry_addr;
    m_name = out.str();
}

ICFGNode::ICFGNode(addr_t entry_addr, CFGNode *entry_node) :
    m_proc_type{ICFGProcedureType::kUnknown},
    m_entry_node{entry_node},
    m_entry_addr{entry_addr},
    m_end_addr{0},
    m_lr_store_idx{0},
    m_has_overlap{false} {
    if (m_entry_node == nullptr) {
        m_proc_type = ICFGProcedureType::kExternal;
    } else {
        entry_node->m_role_in_procedure = CFGNodeRoleInProcedure::kEntry;
        entry_node->m_procedure_entry_addr = entry_addr;
    }
    std::ostringstream out;
    out << "proc_" << std::hex << m_entry_addr;
    m_name = out.str();
}

ICFGNode::ICFGNode(CFGNode *entry_node) :
    m_proc_type{ICFGProcedureType::kUnknown},
    m_entry_node{entry_node},
    m_entry_addr{entry_node->getCandidateStartAddr()},
    m_end_addr{0},
    m_lr_store_idx{0},
    m_has_overlap{false} {
    if (m_entry_node == nullptr) {
        m_proc_type = ICFGProcedureType::kExternal;
    } else {
        entry_node->m_role_in_procedure = CFGNodeRoleInProcedure::kEntry;
        entry_node->m_procedure_entry_addr =
            entry_node->getCandidateStartAddr();
    }
    std::ostringstream out;
    out << "proc_" << std::hex << m_entry_addr;
    m_name = out.str();
}

bool ICFGNode::isWithinAddressSpace(const addr_t addr) const noexcept {
    return addr < m_end_addr
        && addr >= m_entry_addr;
}

void ICFGNode::addCaller(const CFGNode *caller) noexcept {
    m_callers.push_back(caller);
}

bool ICFGNode::operator==(const ICFGNode &src) const noexcept {
    return this->m_entry_addr == src.m_entry_addr;
}

CFGNode *ICFGNode::entryNode() const noexcept {
    return m_entry_node;
}

addr_t ICFGNode::entryAddr() const noexcept {
    return m_entry_addr;
}

const std::string &ICFGNode::name() const noexcept {
    return m_name;
}

ICFGProcedureType ICFGNode::type() const noexcept {
    return m_proc_type;
}

void ICFGNode::finalize() noexcept {
//    m_entry_node->setCandidateStartAddr(m_entry_addr);
    addr_t max_end_addr = 0;
    for (const auto &node_pair : m_exit_nodes) {
        if (max_end_addr < node_pair.second->maximalBlock()->endAddr()) {
            max_end_addr = node_pair.second->maximalBlock()->endAddr();
        }
    }
    m_end_addr = max_end_addr;
}
}
