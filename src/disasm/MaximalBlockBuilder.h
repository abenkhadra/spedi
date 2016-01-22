//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#pragma once

#include "MCInstSmall.h"
#include "MaximalBlock.h"
#include "BranchData.h"
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
    MaximalBlockBuilder();
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
     * Add a new block with a single instruction. Used
     * when the given instruction is not appendable.
     */
    void createBasicBlockWith
        (const cs_insn *inst);

    /*
     * Add a new valid block with a single instruction.
     * precondition: inst is a branch instruction.
     */
    void createValidBasicBlockWith
        (const cs_insn *inst);
    /*
     * Look up appendable basic blocks first and then appendBranch instruction if possible.
     * Otherwise, create a new basic block.
     */
    void append(const cs_insn *inst);

    /*
     * Look up appendable basic blocks first and then appendBranch branch instruction
     * if possible. Otherwise, create a new basic block.
     */
    void appendBranch(const cs_insn *inst);

    /**
     * precondition: maximal block is buildable.
     */
    MaximalBlock build();

    /*
     * Return true on clean (no overlap) reset, false otherwise.
     */
    bool isCleanReset();
    /*
     * First address after the end of maximal block. Valid only if there are is
     * at least one instruction in the MaximalBlock.
     */
    addr_t endAddr() const;

    const std::vector<addr_t>
        getInstructionAddrsOf(const BasicBlock &bblock) const;

private:
    void setBranch(const cs_insn* inst);

private:
    bool m_buildable;
    unsigned int m_bb_idx;
    unsigned int m_max_block_idx;
    addr_t m_last_addr;
    BranchData m_branch;
    std::vector<BasicBlock> m_bblocks;
    std::vector<MCInstSmall> m_insts;
};
}
