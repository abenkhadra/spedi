//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "ICFGNode.h"
#include <unordered_map>

namespace disasm {
/**
 * DisassemblyCallGraph
 */
class DisassemblyCallGraph {
public:
    /**
     * Construct a DisassemblyCallGraph that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    DisassemblyCallGraph() = default;
    virtual ~DisassemblyCallGraph() = default;
    DisassemblyCallGraph(const DisassemblyCallGraph &src) = default;
    DisassemblyCallGraph &operator=(const DisassemblyCallGraph &src) = default;
    DisassemblyCallGraph(DisassemblyCallGraph &&src) = default;

    std::vector<ICFGNode *> getCallers(const ICFGNode& node) const;
    std::vector<ICFGNode *> getCallees(const ICFGNode& node) const;
    /*
     * Constructs a new procedure and returns a pointer to it. Returns nullptr
     * If entry_addr was already used.
     */
    ICFGNode *addProcedure(const addr_t entry_addr, CFGNode *entry_node);
    friend class SectionDisassemblyAnalyzerARM;
private:
    std::vector<ICFGNode> m_graph_vec;
    std::unordered_map<addr_t, CFGNode *> m_call_graph_map;
};
}
