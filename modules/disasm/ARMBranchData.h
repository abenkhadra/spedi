//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#pragma once

#include <capstone/arm.h>
#include "common.h"
#include <string>
namespace disasm {

/**
 * ARMBranchData
 */
class ARMBranchData {
public:
    virtual ~ARMBranchData() = default;
    ARMBranchData(const ARMBranchData &src);
    ARMBranchData &operator=(const ARMBranchData &src) = default;
    ARMBranchData(ARMBranchData &&src) = default;

    bool valid() const;
    bool isConditional() const;
    bool isDirect() const { return m_direct; }
    // precondition: valid only for direct branch
    int target() const { return m_target; }
    arm_cc condition() const { return m_condition; }
    const std::string conditionString() const;
    friend class MaximalBlockBuilder;
private:
    /**
     * Construct a ARMBranchData that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    ARMBranchData();
    ARMBranchData(int target, arm_cc condition = ARM_CC_AL);
    ARMBranchData(arm_op_mem *mem_operand, arm_cc condition = ARM_CC_AL);

private:
    bool m_direct;
    arm_cc m_condition;
    union {
        // valid only if direct branch.
        int m_target;
        // this field makes the class ARM specific
        arm_op_mem m_operand;
    };
};
}



