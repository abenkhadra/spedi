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

enum class BranchInstType: unsigned short {
    kUnknown = 0,
    kDirect = 1,
    kInDirect = 2
};

/**
 * BasicBlock
 * a lightweight container for data relevant to basic blocks contained in
 * a maximal block.
 */
class BasicBlock {
public:
    /**
     * Construct a BasicBlock that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    BasicBlock();
    virtual ~BasicBlock() = default;
    BasicBlock(const BasicBlock &src) = default;
    BasicBlock &operator=(const BasicBlock &src) = default;
    BasicBlock(BasicBlock &&src) = default;

    bool valid() const { return m_valid; }

    bool ContainsFragment(unsigned short frag_id);

    size_t size() const {
        return m_frags.size();
    }

    unsigned short lastFragmentId();

    unsigned short firstFragmentId();

    unsigned short id() const;

    const BranchInstType &getBranchType() const;

    addr_t getBranchTarget() const;

    const std::vector<unsigned short>& getFragmentIds(){
        return m_frags;
    }

private:
    bool m_valid;
    unsigned short m_id;
    BranchInstType m_br_type;
    // contains a valid value only in the case of direct branch
    addr_t m_br_target;
    std::vector<unsigned short> m_frags;

};
}



