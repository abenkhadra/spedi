//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

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
    MaximalBlock(addr_t start_addr);
    virtual ~MaximalBlock() = default;
    MaximalBlock(const MaximalBlock &src) = default;
    MaximalBlock &operator=(const MaximalBlock &src) = default;
    MaximalBlock(MaximalBlock &&src) = default;

    // Adds an instruction to MB.
    // if inst continues a fragment then add instruction to fragment. Otherwise,
    // create a new basic block + fragment and append inst to fragment.
    bool addInst(const MCInstSmall & inst);

    bool isAppendable(const MCInstSmall & inst);

    void skipData(addr_t addr, addr_t end_addr);

    void setType(MaxBlockType type);

    size_t getBasicBlockMemSize(unsigned short bb_id);
    size_t getBasicBlockSize(unsigned short bb_id);

    size_t getFragmentSize(unsigned short frag_id);
    size_t getFragmentMemSize(unsigned short frag_id);

private:
    MaxBlockType m_type;
    addr_t m_start_addr;

    unsigned short m_inst_word_size;

    std::vector<Fragment> m_frags;
    std::vector<BasicBlock> m_bblocks;


};
}



