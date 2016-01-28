//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once
#include "../common.h"
#include "../MaximalBlock.h"

namespace disasm {
/**
 * MaximalBlockCFGNode
 */
class MaximalBlockCFGNode {
public:
    /**
     * Construct a MaximalBlockCFGNode that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    MaximalBlockCFGNode();
    MaximalBlockCFGNode(MaximalBlock *current_block);
    virtual ~MaximalBlockCFGNode() = default;
    MaximalBlockCFGNode(const MaximalBlockCFGNode &src) = default;
    MaximalBlockCFGNode &operator=(const MaximalBlockCFGNode &src) = default;
    MaximalBlockCFGNode(MaximalBlockCFGNode &&src) = default;

    const MaximalBlock * getMaximalBlock() const;
    const MaximalBlockCFGNode * getOverlapCFGNode() const;
    unsigned int getId() const noexcept;

    void addPredecessor(MaximalBlockCFGNode *predecessor, addr_t target_addr);

    void setDirectSuccessor(MaximalBlockCFGNode *successor);
    const MaximalBlockCFGNode *getDirectSuccessor() const;
    void setRemoteSuccessor(MaximalBlockCFGNode *successor);
    const MaximalBlockCFGNode *getRemoteSuccessor() const;

    const std::vector<std::pair<MaximalBlockCFGNode *, addr_t>>
        &getPredecessors() const;

    /*
     * return the sequence of instructions starting from the known start address,
     * If address is invalid then return an empty vector
     */
    std::vector<MCInstSmall>
        getKnownInstructions() const;
    addr_t getKnownStartAddr() const;
    void setType(const MaximalBlockType type);
    MaximalBlockType getType() const;
    bool isData() const;
    bool isCode() const;
    friend class SectionDisassemblyAnalyzer;
private:
    void setMaximalBlock(MaximalBlock *maximal_block) noexcept;
    MaximalBlockCFGNode *ptrToOverlapNode() const;
private:
    MaximalBlockType m_type;
    addr_t m_known_start_addr;
    unsigned m_valid_basic_block_id;
    MaximalBlockCFGNode *m_overlap_node;
    /// valid only in case of conditional branch
    MaximalBlockCFGNode *m_direct_successor;
    MaximalBlockCFGNode *m_remote_successor;
    MaximalBlock *m_max_block;
    std::vector<std::pair<MaximalBlockCFGNode *, addr_t>> m_predecessors;
};
}
