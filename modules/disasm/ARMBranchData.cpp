//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "ARMBranchData.h"
#include <cstring>

namespace disasm {

ARMBranchData::ARMBranchData() :
    m_direct{false},
    m_condition{ARM_CC_INVALID},
    m_target{0} {

}
ARMBranchData::ARMBranchData(int target,
                             arm_cc condition):
    m_direct{true},
    m_condition{condition},
    m_target{target} {
}
ARMBranchData::ARMBranchData(arm_op_mem *mem_operand,
                             arm_cc condition) :
    m_direct{false},
    m_condition{condition} {
    std::memcpy(&m_operand, mem_operand, sizeof(arm_op_mem));
}
bool ARMBranchData::valid() const {
    return m_condition != ARM_CC_INVALID;
}
bool ARMBranchData::isConditional() const {
    return (m_condition != ARM_CC_INVALID) && (m_condition != ARM_CC_AL);
}
ARMBranchData::ARMBranchData(const ARMBranchData &src) {
    m_condition = src.m_condition;
    if (src.m_direct) {
        m_direct = true;
        m_target = src.m_target;
    } else {
        m_direct = false;
        m_operand = src.m_operand;
    }
}
const std::string ARMBranchData::conditionString() const {
    switch (m_condition) {
        case ARM_CC_INVALID:
            return "Invalid";
        case ARM_CC_EQ:
            return "Equal";
        case ARM_CC_NE:
            return "Not equal";
        case ARM_CC_HS:
            return "Carry set";
        case ARM_CC_LO:
            return "Carry clear";
        case ARM_CC_MI:
            return "Minus";
        case ARM_CC_PL:
            return "Plus";
        case ARM_CC_VS:
            return "Overflow";
        case ARM_CC_VC:
            return "No overflow";
        case ARM_CC_HI:
            return "Unsigned higher";
        case ARM_CC_LS:
            return "Unsigned lower or same";
        case ARM_CC_GE:
            return "Greater than or equal";
        case ARM_CC_LT:
            return "Less than";
        case ARM_CC_GT:
            return "Greater than";
        case ARM_CC_LE:
            return "Less than or equal";
        case ARM_CC_AL:
            return "Always";
        default:
            return "Unknown";
    }
}
}
