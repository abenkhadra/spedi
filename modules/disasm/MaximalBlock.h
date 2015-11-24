//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#pragma once

#include "Fragment.h"
#include "BasicBlock.h"
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
    virtual ~MaximalBlock() = default;
    MaximalBlock(const MaximalBlock &src) = default;
    MaximalBlock &operator=(const MaximalBlock &src) = default;
    MaximalBlock(MaximalBlock &&src) = default;

    friend class MaximalBlockBuilder;

    /**
     * MB is valid when all of its BBs are valid. A BB is valid when it
     * has a branch as last instruction.
     */
    bool valid();

    void setType(MaxBlockType type);

    // getting size and memsize of fragments are provided by the fragment itself.
    // providing the same for BBs, however, requires MB intervention!

    size_t getBasicBlockMemSize(unsigned int bb_id);

    const BasicBlock& getBasicBlock(unsigned int bb_id);


    addr_t getStartAddr() const;

private:
    MaximalBlock() = default;

private:
    MaxBlockType m_type;
    std::vector<Fragment> m_frags;
    std::vector<BasicBlock> m_bblocks;
};
}
