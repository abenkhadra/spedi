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

enum class BlockCFGNodeType: unsigned {
    kData = 1,
    kMaybe = 2,
    kCode = 4
};

/*
 * a special value used to identify indirect predecessors
 */
enum class PredecessorType: unsigned short {
    kIndirectCall =
    0,      // control reaches this node through indirect call node
    kSwitchStatement = 1,   // control reaches this node from a switch statement
    kCallNode =
    2,          // control reaches this node after returning from call
    kOther = 3              // none of the above
};

enum class TraversalStatus: unsigned short {
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
    unsigned int id() const noexcept;

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
    addr_t getCandidateStartAddr() const noexcept;
    void setCandidateStartAddr(addr_t candidate_start) noexcept;
    void setType(const BlockCFGNodeType type);
    void setToDataAndInvalidatePredecessors();
    void resetCandidateStartAddress();
    BlockCFGNodeType getType() const;
    bool isData() const;
    bool isCode() const;
    /*
     * returns true if the branch instruction belongs to the call_group of
     * ARM which is BL and BLX.
     */
    bool isPossibleCall() const noexcept;
    /*
     * returns true if immediate predecessor is a PossibleCall
     */
    bool isPossibleReturn() const noexcept;

    bool isCandidateStartAddressValid(addr_t candidate_addr) const noexcept;
    bool isAssignedToProcedure() const noexcept;
    friend class SectionDisassemblyAnalyzerARM;
private:
    void setMaximalBlock(MaximalBlock *maximal_block) noexcept;
    CFGNode *getOverlapNodePtr() const noexcept;
private:
    BlockCFGNodeType m_type;
    addr_t m_candidate_start_addr;
    CFGNode *m_overlap_node;
    ICFGNode *m_procedure;
    TraversalStatus m_traversal_status;
    CFGNode *m_immediate_successor;
    CFGNode *m_remote_successor;
    MaximalBlock *m_max_block;
    std::vector<std::pair<CFGNode *, addr_t>> m_direct_predecessors;
    bool m_possible_return;
};
}
