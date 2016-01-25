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
    bool isConditional() const { return m_conditional_branch; }
    bool isDirect() const { return m_direct_branch; }
    // precondition: valid only for direct branch
    addr_t getTarget() const { return m_target; }
    friend class MaximalBlockBuilder;

private:
    bool m_direct_branch;
    bool m_conditional_branch;
    addr_t m_target;
};
}



