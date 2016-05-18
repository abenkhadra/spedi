//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "DisassemblyCallGraph.h"
#include <algorithm>
#include <cassert>
#include <iostream>

namespace disasm {

DisassemblyCallGraph::DisassemblyCallGraph
    (addr_t sec_start_addr, addr_t sec_end_addr) :
    m_section_start_addr{sec_start_addr},
    m_section_end_addr{sec_end_addr},
    m_call_graph_ordered{false} {
}

void DisassemblyCallGraph::setSectionStartAddr(addr_t sec_start_addr) noexcept {
    m_section_start_addr = sec_start_addr;
}

void DisassemblyCallGraph::setSectionEndAddr(addr_t sec_end_addr) noexcept {
    m_section_end_addr = sec_end_addr;
}

ICFGNode *DisassemblyCallGraph::insertProcedure
    (const addr_t entry_addr, CFGNode *entry_node, ICFGProcedureType type) {

    auto result = m_call_graph_map.insert({entry_addr, nullptr});
    if (result.second) {
        if (type == ICFGProcedureType::kExternal) {
            m_external_procs.emplace_back
                (ICFGNode(entry_addr, entry_node, type));
            return &(m_external_procs.back());
        } else {
            m_unmerged_procs.emplace_back
                (ICFGNode(entry_addr, entry_node, type));
            return &(m_unmerged_procs.back());
        }
    }
    return nullptr;
}

void DisassemblyCallGraph::AddProcedure
    (const addr_t entry_addr,
     CFGNode *entry_node,
     ICFGProcedureType proc_type) {

    auto result = m_call_graph_map.insert({entry_addr, nullptr});
    if (result.second) {
        if (proc_type == ICFGProcedureType::kExternal) {
            m_external_procs.emplace_back
                (ICFGNode(entry_addr, entry_node, proc_type));
        } else {
            m_unmerged_procs.emplace_back
                (ICFGNode(entry_addr, entry_node, proc_type));
        }
    }
}

ICFGNode DisassemblyCallGraph::createProcedure
    (const addr_t entry_addr, CFGNode *entry_node) noexcept {
    return ICFGNode(entry_addr, entry_node, ICFGProcedureType::kDirectlyCalled);
}

void DisassemblyCallGraph::rebuildCallGraph() noexcept {
    for (auto &proc : m_unmerged_procs) {
        m_main_procs.push_back(proc);
    }
    m_unmerged_procs.clear();

    std::sort(m_main_procs.begin(), m_main_procs.end());
    for (auto proc_iter = m_main_procs.begin();
         proc_iter < m_main_procs.end() - 1;
         ++proc_iter) {
        for (auto &node_pair : (*proc_iter).m_exit_nodes) {
            if (node_pair.first == ICFGExitNodeType::kTailCallOrOverlap) {
                if (node_pair.second->remoteSuccessor()->isProcedureEntry()) {
                    node_pair.first = ICFGExitNodeType::kTailCall;
                } else {
                    node_pair.first = ICFGExitNodeType::kOverlap;
                }
            }
        }
        prettyPrintProcedure(*proc_iter);
    }
    m_call_graph_ordered = true;
}

bool DisassemblyCallGraph::isNonReturnProcedure(const ICFGNode &proc) const noexcept {
    if (proc.getExitNodes().size() != 1
        || proc.endNode()->remoteSuccessor() != nullptr) {
        // procedure is not a non-return procedure
        return false;
    }
    return false;
}

void DisassemblyCallGraph::checkNonReturnProcedureAndFixCallers
    (ICFGNode &proc) const noexcept {

    if (!proc.isReturnsToCaller()) {
        for (const auto &type_node_pair : proc.getExitNodes()) {
            if (type_node_pair.first != ICFGExitNodeType::kTailCall) {
                // indirect branches with unknown destination
                return;
            }
            if (!type_node_pair.second->maximalBlock()->branchInfo().isCall()) {
                // branch to procedure that is not well-known non-return procedure
                return;
            }
        }
//        printf("Set to non-return procedure\n");
        // TODO: recursively identify non-return procedures?
        proc.setNonReturn(true);
        for (auto &cfg_edge : proc.entryNode()->getDirectPredecessors()) {
            if (cfg_edge.type() == CFGEdgeType::kDirect
                && cfg_edge.node()->isCall()) {
                cfg_edge.node()->setIsCall(false);
            }
        }
    }
}

std::vector<ICFGNode> &DisassemblyCallGraph::buildInitialCallGraph() noexcept {
    assert(m_main_procs.size() == 0 && "Initial call graph is not empty!!");
    m_main_procs.swap(m_unmerged_procs);
    std::sort(m_main_procs.begin(), m_main_procs.end());
    // XXX: assuming that there is at least one proc
    for (auto &proc : m_external_procs) {
        m_call_graph_map.at(proc.entryAddr()) = &proc;
    }
    for (auto proc_iter = m_main_procs.begin();
         proc_iter < m_main_procs.end() - 1;
         ++proc_iter) {
        (*proc_iter).m_estimated_end_addr = (*(proc_iter + 1)).m_entry_addr;
        m_call_graph_map.insert({(*proc_iter).id(), &(*proc_iter)});
    }
    m_main_procs.back().m_estimated_end_addr = m_section_end_addr;
    m_call_graph_ordered = true;
    return m_main_procs;
}

void DisassemblyCallGraph::reserve(size_t procedure_count) {
    m_unmerged_procs.reserve(procedure_count);
    m_main_procs.reserve(procedure_count);
    m_call_graph_map.reserve(procedure_count);
}

void DisassemblyCallGraph::prettyPrintProcedure
    (const ICFGNode &proc_node) noexcept {
    std::cout << std::endl;
    printf("Function 0x%lx 0x%lx\n",
           proc_node.entryAddr(),
           proc_node.m_end_addr);
    for (auto &exitNodePair : proc_node.m_exit_nodes) {
        switch (exitNodePair.first) {
            case ICFGExitNodeType::kInvalidLR:
                printf("Exit_invalid node %lu at: 0x%lx /",
                       exitNodePair.second->id(),
                       exitNodePair.second->getCandidateStartAddr());
                break;
            case ICFGExitNodeType::kTailCall:
                printf("Exit_tail_call node %lu at: 0x%lx /",
                       exitNodePair.second->id(),
                       exitNodePair.second->getCandidateStartAddr());
                break;
            case ICFGExitNodeType::kOverlap:
                printf("Exit_overlap node %lu at: 0x%lx /",
                       exitNodePair.second->id(),
                       exitNodePair.second->getCandidateStartAddr());
                break;
            case ICFGExitNodeType::kTailCallOrOverlap:
                printf("Exit_overlap or tail call node %lu at: 0x%lx /",
                       exitNodePair.second->id(),
                       exitNodePair.second->getCandidateStartAddr());
                break;
            case ICFGExitNodeType::kReturn:
                printf("Exit_return node %lu at: 0x%lx /",
                       exitNodePair.second->id(),
                       exitNodePair.second->getCandidateStartAddr());
                break;
            case ICFGExitNodeType::kIndirect:
                printf("Exit_indirect node %lu at: 0x%lx /",
                       exitNodePair.second->id(),
                       exitNodePair.second->getCandidateStartAddr());
                break;
        }
        printf("\n");
    }
    printf("Procedure end ...\n");
}
}
