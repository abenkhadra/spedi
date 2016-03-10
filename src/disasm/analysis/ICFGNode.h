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

namespace disasm {
class CFGNode;

enum class ICFGExitNodeType: unsigned char {
    kCall,  // direct call to an entry node, we expect it to return
    kTailCall,    // call to an entry, we expect the callee to return to original caller
    kOverlap, // direct branch/call to a node other than entry node
    kReturn,
    kIndirectCall,
    kInvalidLR
};

enum class ICFGProcedureType: unsigned char {
    kUnknown,
    kReturn,
    kExternal,
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
    ICFGNode() = delete;
    explicit ICFGNode(addr_t entry_addr);
    ICFGNode(addr_t entry_addr, CFGNode *entry_node);
    ICFGNode(CFGNode *entry_node);
    virtual ~ICFGNode() = default;
    ICFGNode(const ICFGNode &src) = default;
    ICFGNode &operator=(const ICFGNode &src) = default;
    ICFGNode(ICFGNode &&src) = default;
    bool operator==(const ICFGNode &src) const noexcept;

    bool isCallerAlreadyExists(const ICFGNode &caller) const noexcept;
    bool isCalleeAlreadyExists(const ICFGNode &callee) const noexcept;
    void addCaller(const CFGNode *caller) noexcept;
    void addCallee(const ICFGNode *callee) const noexcept;
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
    bool isWithinAddressSpace(const addr_t addr) const noexcept;
    friend class DisassemblyCallGraph;
    friend class SectionDisassemblyAnalyzerARM;
private:
    // a procedure is valid iff it returns to the address designated by caller
    // in all of its exit nodes.
    ICFGProcedureType m_proc_type;
    CFGNode *m_entry_node;
    addr_t m_entry_addr;
    addr_t m_end_addr; // end address of
    unsigned m_lr_store_idx;
    bool m_has_overlap;
    std::string m_name;
    std::vector<const CFGNode *> m_callers;
    std::vector<const CFGNode *> m_callees;
    // The first node in m_cfg_nodes should be the entry_node
    std::vector<CFGNode *> m_cfg_nodes;
    std::vector<std::pair<ICFGExitNodeType, const CFGNode *>> m_exit_nodes;
};
}
