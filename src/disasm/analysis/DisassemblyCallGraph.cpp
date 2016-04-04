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

DisassemblyCallGraph::DisassemblyCallGraph(addr_t start_addr, addr_t end_addr) :
    m_start_addr{start_addr},
    m_section_end_addr{end_addr},
    m_call_graph_ordered{false} {
}

ICFGNode *DisassemblyCallGraph::insertProcedure
    (const addr_t entry_addr,
     CFGNode *entry_node,
     ICFGProcedureType type = ICFGProcedureType::kReturn) {

    auto result = m_call_graph_map.insert({entry_addr, nullptr});
    if (result.second) {
        m_unmerged_procs.emplace_back
            (ICFGNode(entry_addr, entry_node, type));
        m_call_graph_ordered = false;
        return &(m_unmerged_procs.back());
    }
    return nullptr;
}

void DisassemblyCallGraph::insertProcedure
    (const addr_t entry_addr, CFGNode *entry_node) {

    auto result = m_call_graph_map.insert({entry_addr, nullptr});
    if (result.second) {
        m_unmerged_procs.emplace_back
            (ICFGNode(entry_addr, entry_node, ICFGProcedureType::kReturn));
        m_call_graph_ordered = false;
    }
}

void DisassemblyCallGraph::buildCallGraph() noexcept {
    // Identify externally called procedures
    // If CFG node role in procedure is exit then its remote target is external
    // Fill the map between proc id and proc ptr
    // link callers and callees.

    for (auto &proc : m_unmerged_procs) {
        m_main_procs.push_back(proc);
    }
    m_unmerged_procs.clear();
    std::sort(m_main_procs.begin(), m_main_procs.end());
    for (auto proc_iter = m_main_procs.begin();
         proc_iter < m_main_procs.end() - 1;
         ++proc_iter) {
        prettyPrintProcedure(*proc_iter);
    }
    m_call_graph_ordered = true;
}

std::vector<ICFGNode> &DisassemblyCallGraph::buildInitialCallGraph() noexcept {
    assert(m_main_procs.size() == 0 && "Initial call graph is not empty!!");
    m_main_procs.swap(m_unmerged_procs);
    std::sort(m_main_procs.begin(), m_main_procs.end());
    for (auto proc_iter = m_main_procs.begin();
         proc_iter < m_main_procs.end() - 1;
         ++proc_iter) {
        (*proc_iter).m_estimated_end_addr = (*(proc_iter + 1)).m_entry_addr;
    }
    m_main_procs.back().m_estimated_end_addr = m_section_end_addr;
    m_call_graph_ordered = true;
    return m_main_procs;
}

void DisassemblyCallGraph::prettyPrintProcedure
    (const ICFGNode &proc_node) noexcept {
    std::cout << std::endl;
    printf("Function %lx %lx\n", proc_node.entryAddr(), proc_node.m_end_addr);
    for (auto &exitNodePair : proc_node.m_exit_nodes) {
        switch (exitNodePair.first) {
            case ICFGExitNodeType::kInvalidLR:
                printf("Exit_invalid node %lu at: %lx /",
                       exitNodePair.second->id(),
                       exitNodePair.second->getCandidateStartAddr());
                break;
            case ICFGExitNodeType::kTailCall:
                printf("Exit_tail_call node %lu at: %lx /",
                       exitNodePair.second->id(),
                       exitNodePair.second->getCandidateStartAddr());
                break;
            case ICFGExitNodeType::kOverlap:
                printf("Exit_overlap node %lu at: %lx /",
                       exitNodePair.second->id(),
                       exitNodePair.second->getCandidateStartAddr());
                break;
        }
        printf("\n");
    }
    printf("Procedure end ...\n");
}
}
