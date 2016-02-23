//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include <vector>

namespace disasm {
class CFGNode;

/**
 * ICFGNode
 */
class ICFGNode {
public:
    /**
     * Construct a ICFGNode that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    ICFGNode() = default;
    explicit ICFGNode(unsigned id);
    ICFGNode(unsigned id, CFGNode * entry_node);
    virtual ~ICFGNode() = default;
    ICFGNode(const ICFGNode &src) = default;
    ICFGNode &operator=(const ICFGNode &src) = default;
    ICFGNode(ICFGNode &&src) = default;

    bool isCallerAlreadyExists(const ICFGNode &caller) const noexcept;
    bool isCalleeAlreadyExists(const ICFGNode &callee) const noexcept;
    void addCaller(const ICFGNode &caller) const noexcept;
    void addCallee(const ICFGNode &callee) const noexcept;
    /*
     *
     */
    CFGNode *getEntryNode() const noexcept;

    std::vector<CFGNode *> getAllExitNodes() const noexcept;

    std::vector<CFGNode *> &getUniqueExitNodes() const noexcept;
    /*
     * if this node overlaps with another
     */
    std::vector<CFGNode *> getAllCFGNodes() const noexcept;
    /*
     * returns CFGNodes that belong only to this procedure
     */
    std::vector<CFGNode *> &getUniqueCFGNodes() const noexcept;

    bool hasOverlapWithOtherProcedure() const noexcept;

    friend class DisassemblyCallGraph;
private:
    // a procedure is valid iff it returns to the address designated by caller
    // in all of its exit nodes.
    bool m_valid;
    unsigned m_id;
    ICFGNode * m_overlap_procedure;
    CFGNode *m_overlap_cfg_node;
    std::vector<unsigned> m_callers;
    std::vector<unsigned> m_callees;
    // The first node in m_cfg_nodes should be the entry_node
    std::vector<CFGNode *> m_cfg_nodes;
    std::vector<CFGNode *> m_exits;
};
}
