//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "DisassemblyCallGraph.h"
namespace disasm {

ICFGNode *DisassemblyCallGraph::addProcedure
    (const addr_t entry_addr, CFGNode *entry_node) {
    auto result = m_call_graph_map.insert({entry_addr, entry_node});
    if (result.second) {
        m_graph_vec.emplace_back(ICFGNode(entry_addr, entry_node));
        return &(m_graph_vec.back());
    }
    return nullptr;
}
}
