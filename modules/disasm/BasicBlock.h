//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#pragma once
#include "Common.h"
#include "Fragment.h"
#include <vector>

namespace disasm {

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
    explicit BasicBlock(unsigned int id);
    virtual ~BasicBlock() = default;
    BasicBlock(const BasicBlock &src) = default;
    BasicBlock &operator=(const BasicBlock &src) = default;
    BasicBlock(BasicBlock &&src) = default;

    friend class MaximalBlock;
    friend class MaximalBlockBuilder;

    unsigned int id() const;
    bool valid() const ;
    /**
    * return the number of fragments in the basic block.
    */
    size_t size() const;
    const BranchInstType& branchType() const;

    addr_t branchTarget() const;

    const std::vector<unsigned int>& getFragmentIds() const;

private:
    unsigned int m_id;
    BranchInstType m_br_type;
    // contains a valid value only in the case of a direct branch
    addr_t m_br_target;
    std::vector<unsigned int> m_frag_ids;
};
}
