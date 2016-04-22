//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include <vector>
#include <disasm/common.h>
#include <string>
#include "CFGNode.h"

namespace disasm {
class CFGNode;

enum class ICFGExitNodeType: unsigned char {
    kTailCall,    // Tail call to an entry which can be direct or indirect
    kOverlap, // direct branch to body of another procedure
    kInvalidLR,
    kTailCallOrOverlap
};

enum class ICFGProcedureType: unsigned char {
    kTail,
    kReturn,
    kExternal,
    kIndirect,
    kInner,
};

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
    ICFGNode();
    ICFGNode(addr_t entry_addr, CFGNode *entry_node, ICFGProcedureType type);
    ICFGNode(CFGNode *entry_node, ICFGProcedureType type);
    virtual ~ICFGNode() = default;
    ICFGNode(const ICFGNode &src) = default;
    ICFGNode &operator=(const ICFGNode &src) = default;
    ICFGNode(ICFGNode &&src) = default;
    bool operator==(const ICFGNode &src) const noexcept;
    bool operator<(const ICFGNode &src) const noexcept;

    bool isCallerAlreadyExists(const ICFGNode &caller) const noexcept;
    bool isCalleeAlreadyExists(const ICFGNode &callee) const noexcept;
    void addCaller(const CFGNode *caller) noexcept;
    void addCallee(const ICFGNode *callee) const noexcept;
    CFGNode *getEntryNode() const noexcept;
    std::vector<CFGNode *> getAllExitNodes() const noexcept;
    std::vector<CFGNode *> &getUniqueExitNodes() const noexcept;
    /*
     * if this node overlaps with another
     */
    std::vector<CFGNode *> getAllCFGNodes() const noexcept;

    bool hasOverlapWithOtherProcedure() const noexcept;
    bool isBuilt() const noexcept;
    bool isValid() const noexcept;
    size_t id() const noexcept;
    bool isWithinEstimatedAddressSpace(const addr_t addr) const noexcept;
    CFGNode *entryNode() const noexcept;
    CFGNode *endNode() const noexcept;
    addr_t entryAddr() const noexcept;
    addr_t endAddr() const noexcept;
    addr_t estimatedEndAddr() const noexcept;
    const std::string &name() const noexcept;
    ICFGProcedureType type() const noexcept;
    void finalize() noexcept;
    friend class DisassemblyCallGraph;
    friend class SectionDisassemblyAnalyzerARM;
private:
    // a procedure is valid iff it returns to the address designated by caller
    // in all of its exit nodes.
    ICFGProcedureType m_proc_type;
    bool m_valid;
    CFGNode *m_entry_node;
    CFGNode *m_end_node;
    addr_t m_entry_addr;
    addr_t m_end_addr; // actual end address of procedure
    addr_t m_estimated_end_addr; // initial overapproximated end address.
    unsigned m_lr_store_idx;
    bool m_has_overlap;
    std::string m_name;
    std::vector<const CFGNode *> m_callers;
    std::vector<const CFGNode *> m_callees;
    // The first node in m_cfg_nodes should be the entry_node
    std::vector<CFGNode *> m_cfg_nodes;
    std::vector<std::pair<ICFGExitNodeType, CFGNode *>> m_exit_nodes;
};
}
