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
#include <functional>

namespace disasm {
class ICFGNode;

enum class CFGNodeKind: unsigned char {
    kData = 1,
    kMaybe = 2,
    kCode = 4
};

/*
 * a special value used to identify types of indirect successors/predecessors
 */
enum class IndirectBranchType: unsigned char {
    kCall = 0,      // control reaches a node after a possible call
    kSwitchStatement = 1,   // control reaches a node after a possible switch
    kOther = 3              // none of the above
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

    const MaximalBlock *getMaximalBlock() const;
    const CFGNode *getOverlapNode() const;
    size_t id() const noexcept;

    void addDirectPredecessor(CFGNode *predecessor, addr_t target_addr);
    /*
     * should be set only for conditional branches
     */
    void setImmediateSuccessor(CFGNode *successor);
    /*
     * should be valid only for conditional branches
     */
    const CFGNode *getImmediateSuccessor() const;
    /*
     * should be set for direct branches (conditional/unconditional)
     */
    void setRemoteSuccessor(CFGNode *successor);
    const CFGNode *getRemoteSuccessor() const;

    const std::vector<std::pair<CFGNode *, addr_t>> &
        getDirectPredecessors() const noexcept;
    bool hasOverlapWithOtherNode() const noexcept;
    bool isCandidateStartAddressSet() const noexcept;

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
    void setType(const CFGNodeKind type);
    void setToDataAndInvalidatePredecessors();
    void resetCandidateStartAddress();
    CFGNodeKind getType() const;
    bool isData() const;
    bool isCode() const;
    bool isSwitchCaseStatement() const noexcept;
    /*
     * returns true if the branch instruction belongs to the call_group of
     * ARM which is BL and BLX.
     */
    bool isPossibleCall() const noexcept;
    /*
     * returns true if immediate predecessor is a PossibleCall
     */
    bool isPossibleReturn() const noexcept;
    /*
     * returns a valid value only after recovering switch tables.
     */
    bool isSwitchStatement() const noexcept;
    bool isCandidateStartAddressValid(addr_t candidate_addr) const noexcept;
    bool isAssignedToProcedure() const noexcept;
    friend class SectionDisassemblyAnalyzerARM;
private:
    void setMaximalBlock(MaximalBlock *maximal_block) noexcept;
    CFGNode *getOverlapNodePtr() const noexcept;
    void setAsReturnNodeFrom(CFGNode *cfg_node);
    void setAsSwitchCaseFor(CFGNode *cfg_node);
private:
    CFGNodeKind m_type;
    addr_t m_candidate_start_addr;
    CFGNode *m_overlap_node;
    ICFGNode *m_procedure;
    TraversalStatus m_traversal_status;
    CFGNode *m_immediate_successor;
    CFGNode *m_remote_successor;
    MaximalBlock *m_max_block;
    std::vector<std::pair<CFGNode *, addr_t>> m_direct_predecessors;
    std::pair<CFGNode *, IndirectBranchType> m_indirect_preds;
    std::vector<std::pair<CFGNode *, IndirectBranchType>> m_indirect_succs;
};
}
