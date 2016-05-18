//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#pragma once

#include <capstone/arm.h>
#include "common.h"
#include <string>
namespace disasm {

/**
 * BranchData
 */
class BranchData {
public:
    /**
      * Construct a BranchData that is initially not valid.  Calling
      * methods other than operator= and valid on this results in
      * undefined behavior.
      */
    BranchData();
    virtual ~BranchData() = default;
    BranchData(const BranchData &src) = default;
    BranchData &operator=(const BranchData &src) = default;
    BranchData(BranchData &&src) = default;

//    bool isValid() const;
    bool isConditional() const noexcept { return m_conditional_branch; }
    bool isDirect() const noexcept { return m_direct_branch; }
    bool isCall() const noexcept { return m_is_call; }
    // precondition: valid only for direct branch
    addr_t target() const { return m_target; }
    friend class MaximalBlockBuilder;
    friend class MaximalBlock;

private:
    bool m_direct_branch;
    bool m_conditional_branch;
    bool m_is_call;
    addr_t m_target;
};
}
