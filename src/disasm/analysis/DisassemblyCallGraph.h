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
    DisassemblyCallGraph() = delete;
    DisassemblyCallGraph(addr_t start_addr, addr_t end_addr);
    virtual ~DisassemblyCallGraph() = default;
    DisassemblyCallGraph(const DisassemblyCallGraph &src) = default;
    DisassemblyCallGraph &operator=(const DisassemblyCallGraph &src) = default;
    DisassemblyCallGraph(DisassemblyCallGraph &&src) = default;

    std::vector<ICFGNode *> getCallers(const ICFGNode &node) const;
    std::vector<ICFGNode *> getCallees(const ICFGNode &node) const;
    /*
     * Constructs a new procedure and returns a pointer to it. Returns nullptr
     * If entry_addr was already used.
     */
    void insertProcedure(const addr_t entry_addr, CFGNode *entry_node);
    ICFGNode *insertProcedure
        (const addr_t entry_addr, CFGNode *entry_node, ICFGProcedureType type);
    void insertProcedure(const ICFGNode &proc);
    ICFGNode createProcedure
        (const addr_t entry_addr, CFGNode *entry_node) noexcept;
    void prettyPrintProcedure(const ICFGNode &proc_node) noexcept;
    void reserve(size_t procedure_count);
    friend class SectionDisassemblyAnalyzerARM;
private:
    std::vector<ICFGNode> &buildInitialCallGraph() noexcept;
    void rebuildCallGraph() noexcept;
private:
    size_t m_start_addr;
    size_t m_section_end_addr;
    bool m_call_graph_ordered;
    std::vector<ICFGNode> m_main_procs;
    std::vector<ICFGNode> m_unmerged_procs;
    std::unordered_map<addr_t, ICFGNode *> m_call_graph_map;
};
}
