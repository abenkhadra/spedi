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

enum class ARMBranchType: uint {
    Invalid,
    Direct,
    IndirectMem,
    IndirectReg
};
/**
 * ARMBranchData
 */
class ARMBranchData {
public:
    ARMBranchData();
    virtual ~ARMBranchData() = default;
    ARMBranchData(const ARMBranchData &src);
    ARMBranchData &operator=(const ARMBranchData &src) = default;
    ARMBranchData(ARMBranchData &&src) = default;

    bool valid() const;
    bool isConditional() const;
    bool isDirect() const { return m_type == ARMBranchType::Direct; }
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
    ARMBranchData(int target, arm_cc condition = ARM_CC_AL);
    ARMBranchData(arm_op_mem *mem_operand, arm_cc condition = ARM_CC_AL);

private:
    ARMBranchType m_type;
    arm_cc m_condition;
    union {
        // valid only if direct branch.
        int m_target;
        // these fields makes the class ARM specific
        arm_op_mem m_operand;
        // XXX: capstone is using unsigned instead of arm_reg to represent this
        unsigned m_reg;
    };
};
}



