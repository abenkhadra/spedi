//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#pragma once

#include "MCInstSmall.h"
#include "MaximalBlock.h"
#include <vector>

namespace disasm {
/**
 * MaximalBlockBuilder
 */
class MaximalBlockBuilder {
public:
    /**
     * Construct a MaximalBlockBuilder that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    MaximalBlockBuilder() ;
    virtual ~MaximalBlockBuilder() = default;
    MaximalBlockBuilder(const MaximalBlockBuilder &src) = default;
    MaximalBlockBuilder &operator=(const MaximalBlockBuilder &src) = delete;
    MaximalBlockBuilder(MaximalBlockBuilder &&src) = default;

    /*
     * Checks if an instruction could be appendable at given address to already
     * existing basic blocks. If successful, return ids of basic blocks
     * otherwise returns empty vector.
     */
    std::vector<unsigned int> appendableBasicBlocksAt
        (const addr_t addr) const;

    /*
     * Add a new block with a single fragment containing the instruction. Used
     * when the given instruction is not appendable.
     */
    void createBasicBlockWith
        (const MCInstSmall &inst);

    /*
     * Add a new block with a single fragment containing a branch instruction.
     * Used when the given instruction is not appendable.
     */
    void createBasicBlockWith
        (const MCInstSmall &inst,
        const BranchInstType br_type,
        const addr_t br_target);

    /*
     * Look up appendable basic blocks first and then append instruction if possible.
     * Otherwise, create a new basic block.
     */
    void append(const MCInstSmall& inst);

    /*
     * Look up appendable basic blocks first and then append branch instruction
     * if possible. Otherwise, create a new basic block.
     */
    void append
        (const MCInstSmall &inst,
         const BranchInstType br_type,
         const addr_t br_target);

    /**
     * precondition: maximal block is buildable.
     */
    MaximalBlock build();

    /*
     * Reset the builder to its original state except in the case of
     * Maximal Block overlap. There, partial results will be kept to build
     * the next MB. Return true on clean (no overlap) reset, false otherwise.
     */
    bool reset();

private:
    // return index of the fragment
//    Fragment* findFragment
//        (const unsigned int frag_id) const;
//    BasicBlock* findBasicBlock
//        (const unsigned int bb_id) const;

private:
    bool m_buildable;
    unsigned int m_bb_idx;
    unsigned int m_max_block_idx;
    addr_t m_last_addr;
    std::vector<BasicBlock> m_bblocks;
    std::vector<MCInstSmall> m_insts;
};
}
