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
        && addr <= m_entry_node->getCandidateStartAddr();
}

void ICFGNode::addCaller(const CFGNode *caller) noexcept {
    m_callers.push_back(caller);
}

bool ICFGNode::operator==(const ICFGNode &src) const noexcept {
    return this->m_entry_addr == src.m_entry_addr;
}
}
