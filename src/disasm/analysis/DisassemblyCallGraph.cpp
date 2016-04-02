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

namespace disasm {

DisassemblyCallGraph::DisassemblyCallGraph(addr_t start_addr, addr_t end_addr) :
    m_start_addr{start_addr},
    m_section_end_addr{end_addr},
    m_call_graph_ordered{false} {
}

void DisassemblyCallGraph::insertProcedure
    (const addr_t entry_addr, CFGNode *entry_node) {
    auto result = m_call_graph_map.insert({entry_addr, nullptr});
    if (result.second) {
        m_unmerged_procs.emplace_back(ICFGNode(entry_addr, entry_node));
        m_call_graph_ordered = false;
    }
}

std::vector<ICFGNode *> DisassemblyCallGraph::mergeCallGraph() noexcept {
    std::vector<ICFGNode *> untraversed_procs;
    if (m_main_procs.size() == 0) {
        m_main_procs.swap(m_unmerged_procs);
    } else {
        m_main_procs.insert(
            m_main_procs.end(),
            std::make_move_iterator(m_unmerged_procs.begin()),
            std::make_move_iterator(m_unmerged_procs.end())
        );
    }
    std::sort(m_main_procs.begin(),
              m_main_procs.end());
    for (auto proc_iter = m_main_procs.begin();
         proc_iter < m_main_procs.end() - 1;
         ++proc_iter) {
        if (!(*proc_iter).isValid()) {
            (*proc_iter).m_estimated_end_addr = (*(proc_iter + 1)).m_entry_addr;
            if ((*proc_iter).m_proc_type == ICFGProcedureType::kExternal) {
                (*proc_iter).m_valid = true;
            } else {
                untraversed_procs.push_back(&(*proc_iter));
            }
        }
//        assert( (*proc_iter).m_section_end_addr <= (*(proc_iter + 1)).m_entry_addr);
    }
    if (!m_main_procs.back().isValid()) {
        untraversed_procs.push_back(&m_main_procs.back());
    }
    m_main_procs.back().m_estimated_end_addr = m_section_end_addr;
    m_call_graph_ordered = true;
    return untraversed_procs;
}
}
