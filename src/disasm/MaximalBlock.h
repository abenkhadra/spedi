//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#pragma once

#include "MCInst.h"
#include "BasicBlock.h"
#include "BranchData.h"
#include <vector>

namespace disasm {

/**
 * MaximalBlock
 */
class MaximalBlock {
public:
    MaximalBlock();
    virtual ~MaximalBlock() = default;
    MaximalBlock(const MaximalBlock &src) = default;
    MaximalBlock &operator=(const MaximalBlock &src) = default;
    MaximalBlock(MaximalBlock &&src) = default;
    bool operator==(const MaximalBlock& src) const noexcept;

    /**
     * MB is valid when all of its BBs are valid. A BB is valid when it
     * has a branch as last instruction.
     */
    bool isValid() const;

    const BasicBlock &getBasicBlockAt(const size_t bb_id) const;
    BasicBlock *ptrToBasicBlockAt(const unsigned bb_id);
    const std::vector<BasicBlock> &getBasicBlocks() const;
    // getting size and memsize of getFragments are provided by the fragment itself.
    // providing the same for BBs, however, requires MB intervention!
    size_t getBasicBlockMemSize(const unsigned int bb_id) const;

    size_t getBasicBlocksCount() const;
    size_t instructionsCount() const;

    /*
     * return all instructions contained in the MB
     */
    const std::vector<MCInst>
        &getAllInstructions() const;

    const std::vector<const MCInst *>
        getInstructionsOf(const BasicBlock &bblock) const;
    const std::vector<addr_t> &
        getInstructionAddressesOf(const BasicBlock &bblock) const noexcept;
    const std::vector<addr_t> &
        getInstructionAddressesOf(const BasicBlock *bblock) const noexcept;

    const BranchData &branchInfo() const;
    void setBranchToUnconditional() noexcept;
    size_t id() const;

    /*
     * return true if the given address falls inside the address space
     * covered by MB
     */
    bool isWithinAddressSpace(addr_t addr) const;

    addr_t addrOfFirstInst() const;
    addr_t addrOfLastInst() const;

    addr_t endAddr() const;
    bool isAddressOfInstruction(const addr_t inst_addr) const;
    bool startOverlapsWith(const MaximalBlock &prev_block) const;
    bool startOverlapsWith(const MaximalBlock *prev_block) const;
    bool coversAddressSpaceOf(const MaximalBlock &block) const;
    bool coversAddressSpaceOf(const MaximalBlock *block) const;
    const MCInst *branchInstruction() const noexcept;
    // returns true if this block aligns with the first (or second) instruction
    // of the given block.
    bool isAppendableBy(const MaximalBlock &block) const noexcept;

    friend class MaximalBlockBuilder;
private:
    explicit MaximalBlock(size_t id, const BranchData &branch);
private:
    size_t m_id;
    addr_t m_end_addr;
    BranchData m_branch;
    std::vector<MCInst> m_insts;
    std::vector<BasicBlock> m_bblocks;
};
}
