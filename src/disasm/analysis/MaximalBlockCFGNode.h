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
    MaximalBlockCFGNode(MaximalBlock *current_block);
    virtual ~MaximalBlockCFGNode() = default;
    MaximalBlockCFGNode(const MaximalBlockCFGNode &src) = default;
    MaximalBlockCFGNode &operator=(const MaximalBlockCFGNode &src) = default;
    MaximalBlockCFGNode(MaximalBlockCFGNode &&src) = default;

    void setOverlapMaximalBlock(MaximalBlock * overlap_block);
    MaximalBlock * getOverlapMaximalBlock() const;

    void addPredecessor(MaximalBlock *predecessor, addr_t target_addr);

    void setDirectSuccessor(MaximalBlock *successor);

    void setRemoteSuccessor(MaximalBlock *successor);

    const MaximalBlock * getMaximalBlock() const;
private:
    MaximalBlock *m_overlap_mblock;
    /// valid only in case of conditional branch
    MaximalBlock *m_direct_successor;
    MaximalBlock *m_remote_successor;
    MaximalBlock *m_current;
    std::vector<std::pair<MaximalBlock *, addr_t>> m_predecessors;
};
}
