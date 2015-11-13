//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once
#include "common.h"
#include <vector>

namespace disasm {

class Fragment;
/**
 * BasicBlock
 */
class BasicBlock {
public:
    /**
     * Construct a BasicBlock that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    BasicBlock() = default;
    virtual ~BasicBlock() = default;
    BasicBlock(const BasicBlock &src) = default;
    BasicBlock &operator=(const BasicBlock &src) = default;
    BasicBlock(BasicBlock &&src) = default;

    bool valid() const { return false; }
private:
    addr_t m_start_addr;
    size_t size;
    std::vector<Fragment*> m_frags;

};
}



