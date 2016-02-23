//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "DisassemblyCallGraph.h"
namespace disasm{

void DisassemblyCallGraph::addProcedure(CFGNode *entry_node) {
    m_call_graph.emplace_back(ICFGNode(m_global_idx, entry_node));
    m_global_idx++;
}
}
