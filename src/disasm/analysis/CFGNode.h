//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "disasm/common.h"
#include "disasm/MaximalBlock.h"
#include "CFGEdge.h"
#include <functional>

namespace disasm {
class ICFGNode;

enum class CFGNodeType: unsigned char {
    kData = 1,
    kUnknown = 2,
    kCode = 4
};

enum class CFGNodeRoleInProcedure: unsigned char {
    kUnknown,
    kEntry,
    kCall,
    kTailCall,
    kOverlapBranch,
    kIndirectCall,
    kReturn,
    kExit,          // call or tail call that exits the section (e.g, to plt)
    kBody,
    kInvalidBranch
};

enum class TraversalStatus: unsigned char {
    kUnvisited,
    kVisited,
    kFinished
};
/**
 * CFGNode
 */
class CFGNode {
public:
    /**
     * Construct a CFGNode that is initially not valid.  Calling
     * methods other than operator= on this results in
     * undefined behavior.
     */
    CFGNode();
    CFGNode(MaximalBlock *current_block);
    virtual ~CFGNode() = default;
    CFGNode(const CFGNode &src) = default;
    CFGNode &operator=(const CFGNode &src) = default;
    CFGNode(CFGNode &&src) = default;
    bool operator==(const CFGNode &src) const noexcept;

    const MaximalBlock *maximalBlock() const;
    const CFGNode *getOverlapNode() const;
    size_t id() const noexcept;
    addr_t procedure_id() const noexcept;

    void addRemotePredecessor(CFGNode *predecessor, addr_t target_addr);
    void addImmediatePredecessor(CFGNode *predecessor, addr_t target_addr);
    /*
     * should be set only for conditional branches
     */
    void setImmediateSuccessor(CFGNode *successor);
    /*
     * should be valid only for conditional branches
     */
    const CFGNode *immediateSuccessor() const;
    /*
     * should be set for direct branches (conditional/unconditional)
     */
    void setRemoteSuccessor(CFGNode *successor);
    const CFGNode *remoteSuccessor() const;

    const std::vector<CFGEdge> &getDirectPredecessors() const noexcept;
    const std::vector<CFGEdge> &getIndirectPredecessors() const noexcept;
    const std::vector<CFGEdge> &getIndirectSuccessors() const noexcept;
    bool hasOverlapWithOtherNode() const noexcept;
    bool isCandidateStartAddressSet() const noexcept;
    bool isProcedureEntry() const noexcept;

    /*
     * return the sequence of instructions in valid basic block starting from
     * the candidate start address. Throws exception in case valid basic block not set.
     */
    std::vector<const MCInst *> getCandidateInstructions() const;
    std::vector<const MCInst *> getCandidateInstructionsSatisfying
        (std::function<bool(const MCInst *inst)> predicate) const;
    size_t getCountOfCandidateInstructions() const noexcept;
    addr_t getCandidateStartAddr() const noexcept;
    void setCandidateStartAddr(addr_t candidate_start) noexcept;
    void setType(const CFGNodeType type);
    void setToDataAndInvalidatePredecessors();
    void resetCandidateStartAddress();
    CFGNodeType getType() const;
    bool isData() const;
    bool isCode() const;
    bool isSwitchBranchTarget() const noexcept;
    /*
     * returns true if the branch instruction belongs to the call_group of
     * ARM which is BL and BLX.
     */
    bool isCall() const noexcept;
    /*
     * returns true if immediate predecessor is a PossibleCall
     */
    bool isPossibleReturn() const noexcept;
    const CFGNode *getPreceedingCallNode() const noexcept;
    /*
     * returns a valid value only after recovering switch tables.
     */
    bool isSwitchStatement() const noexcept;
    bool isCandidateStartAddressValid(addr_t candidate_addr) const noexcept;
    bool isAssignedToProcedure() const noexcept;
    bool isRoleInProcedureSet() const noexcept;
    bool isImmediateSuccessorSet() const noexcept;
    bool isProcedureEntryNode() const noexcept;
    addr_t getMinTargetAddrOfValidPredecessor() const noexcept;
    bool isAppendableBy(const CFGNode *cfg_node) const;
    CFGNode *getReturnSuccessorNode() const noexcept;
    friend class SectionDisassemblyAnalyzerARM;
    friend class ICFGNode;
private:
    void setMaximalBlock(MaximalBlock *maximal_block) noexcept;
    CFGNode *getOverlapNodePtr() const noexcept;
    void setAsReturnNodeFrom(CFGNode &cfg_node);
    void setAsSwitchCaseFor(CFGNode *cfg_node, const addr_t target_addr);
private:
    CFGNodeType m_type;
    bool m_is_call;
    TraversalStatus m_traversal_status;
    CFGNodeRoleInProcedure m_role_in_procedure;
    addr_t m_candidate_start_addr;
    CFGNode *m_overlap_node;
    CFGNode *m_node_appendable_by_this;
    addr_t m_procedure_id;  // acts as an id for a procedure
    CFGNode *m_immediate_successor;
    CFGNode *m_remote_successor;
    MaximalBlock *m_max_block;
    std::vector<CFGEdge> m_direct_predecessors;
    std::vector<CFGEdge> m_indirect_preds;
    std::vector<CFGEdge> m_indirect_succs;

};
}
