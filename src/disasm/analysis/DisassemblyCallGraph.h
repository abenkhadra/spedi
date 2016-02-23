//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "ICFGNode.h"

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

    void addProcedure(CFGNode *entry_node);

    bool valid() const { return false; }
private:
    std::vector<ICFGNode> m_call_graph;
    unsigned m_global_idx = 0;
};
}
