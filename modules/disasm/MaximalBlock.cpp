//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.


#include "MaximalBlock.h"
#include <cassert>

namespace disasm {

MaximalBlock::MaximalBlock(addr_t start_addr):
    m_type{MaxBlockType::kMaybe},
    m_start_addr{start_addr}
{

}

size_t
MaximalBlock::getBasicBlockSize(unsigned short bb_id) {
    assert(bb_id <= m_bblocks.size()
               && "Invalid Basic Block Id!!");
    return m_bblocks[bb_id].size();
}

size_t
MaximalBlock::getBasicBlockMemSize(unsigned short bb_id) {
    assert(bb_id <= m_bblocks.size()
               && "Invalid Basic Block Id!!");
    auto frags = m_bblocks[bb_id].getFragmentIds();
    size_t result = 0;
    for(auto index:frags){
        result += m_frags[index].memSize();
    }
    return result;
}

size_t
MaximalBlock::getFragmentSize(unsigned short frag_id) {
    assert(frag_id <= m_frags.size()
               && "Invalid Fragment Id!!");
    return m_frags[frag_id].size();
}

size_t
MaximalBlock::getFragmentMemSize(unsigned short frag_id) {
    assert(frag_id <= m_frags.size()
               && "Invalid Fragment Id!!");
    return m_frags[frag_id].memSize();
}

void MaximalBlock::skipData(addr_t addr, addr_t end_addr) {
    assert(addr < end_addr && "Inavlid address!!");
    while(addr < end_addr){

    }
}

void MaximalBlock::setType(MaxBlockType type) {
    m_type = type;
}
}