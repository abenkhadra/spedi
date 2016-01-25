//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#pragma once

#include "Fragment.h"
#include "BasicBlock.h"
#include "BranchData.h"
#include <vector>

namespace disasm {

enum class MaximalBlockType: unsigned {
    kData = 1,
    kMaybe = 2,
    kCode = 4
};

/**
 * MaximalBlock
 */
class MaximalBlock {
public:
    /**
     */
    MaximalBlock();
    virtual ~MaximalBlock() = default;
    MaximalBlock(const MaximalBlock &src) = default;
    MaximalBlock &operator=(const MaximalBlock &src) = default;
    MaximalBlock(MaximalBlock &&src) = default;

    friend class MaximalBlockBuilder;

    /**
     * MB is valid when all of its BBs are valid. A BB is valid when it
     * has a branch as last instruction.
     */
    bool isValid() const;
    void setType(const MaximalBlockType type);
    MaximalBlockType getType() const;

    const BasicBlock &getBasicBlockById(const unsigned bb_id) const;
    const std::vector<BasicBlock> &getBasicBlocks() const;
    // getting size and memsize of getFragments are provided by the fragment itself.
    // providing the same for BBs, however, requires MB intervention!
    size_t getBasicBlockMemSize(const unsigned int bb_id) const;

    size_t getBasicBlocksCount() const;
    unsigned instructionsCount() const;

    /*
     * return all instructions contained in the MB
     */
    const std::vector<MCInstSmall>
        &getAllInstructions() const;
    /*
     * return the sequence of instructions starting from the known start address,
     * If address is invalid then return an empty vector
     */
    std::vector<MCInstSmall>
        getKnownInstructions() const;

    const std::vector<const MCInstSmall *>
        getInstructionsOf(BasicBlock &bblock);
    const std::vector<addr_t> &
        getInstructionAddressesOf(const BasicBlock &bblock) const;

    const BranchData &getBranch() const;
    unsigned getId() const;

    /*
     * return true if the given address falls inside the address space
     * covered by MB
     */
    bool isWithinAddressSpace(addr_t addr) const;

    addr_t addrOfFirstInst() const;
    addr_t addrOfLastInst() const;

    addr_t endAddr() const;
    bool isInstructionAddress(const addr_t inst_addr) const;
    addr_t getKnownStartAddr() const;

    bool startOverlapsWith(const MaximalBlock &prev_block) const;
    bool startOverlapsWith(const MaximalBlock *prev_block) const;
    bool coversAddressSpaceOf(const MaximalBlock &block) const;
    bool coversAddressSpaceOf(const MaximalBlock *block) const;
    bool isData() const;

private:
    explicit MaximalBlock(unsigned int id, const BranchData &branch);

private:
    unsigned int m_id;
    MaximalBlockType m_type;
    addr_t m_start_addr;
    addr_t m_end_addr;
    BranchData m_branch;
    std::vector<MCInstSmall> m_insts;
    std::vector<BasicBlock> m_bblocks;
};
}
