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

enum class MaxBlockType{
    kData,
    kMaybe,
    kCode
};

/**
 * MaximalBlock
 */
class MaximalBlock {
public:
    /**
     */
    MaximalBlock() = default;
    virtual ~MaximalBlock() = default;
    MaximalBlock(const MaximalBlock &src) = default;
    MaximalBlock &operator=(const MaximalBlock &src) = default;
    MaximalBlock(MaximalBlock &&src) = default;

    friend class MaximalBlockBuilder;

    /**
     * MB is valid when all of its BBs are valid. A BB is valid when it
     * has a branch as last instruction.
     */
    bool valid() const;
    addr_t startAddr() const;
    void setType(const MaxBlockType type);

    const BasicBlock& getBasicBlockById(const unsigned bb_id) const;
    const std::vector<BasicBlock>& getBasicBlocks() const;
    // getting size and memsize of getFragments are provided by the fragment itself.
    // providing the same for BBs, however, requires MB intervention!
    size_t getBasicBlockMemSize(const unsigned int bb_id) const;

    unsigned getBasicBlocksCount() const;
    unsigned getInstructionCount() const;

    //XXX: access should be to an iterator instead of a collection?
    const std::vector<MCInstSmall> &getInstructions() const;
    const std::vector<MCInstSmall *> getInstructionsOf(BasicBlock &bblock);
    const std::vector<addr_t>
        getInstructionAddrsOf(const BasicBlock &bblock) const;

    const BranchData &branch() const {
        return m_branch;
    }
    const unsigned & id() const ;
    void setId(unsigned id);
    /*
     * return true if the given address falls inside the address space
     * covered by MB
     */
    const bool isCovered(addr_t addr) const;

    /*
     * return the address of last instruction
     */
    const addr_t lastInstAddr() const;

private:
    explicit MaximalBlock(unsigned int id, const BranchData &branch);

private:
    unsigned int m_id;
    MaxBlockType m_type;
    BranchData m_branch;
    std::vector<MCInstSmall> m_insts;
    std::vector<BasicBlock> m_bblocks;
};
}
