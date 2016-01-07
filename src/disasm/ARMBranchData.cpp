//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#include "ARMBranchData.h"
#include <cstring>

namespace disasm {

ARMBranchData::ARMBranchData() :
    m_type{ARMBranchType::Invalid},
    m_condition{ARM_CC_INVALID},
    m_target{0} {

}
bool ARMBranchData::valid() const {
    return m_condition != ARM_CC_INVALID;
}
bool ARMBranchData::isConditional() const {
    return (m_condition != ARM_CC_INVALID) && (m_condition != ARM_CC_AL);
}
ARMBranchData::ARMBranchData(const ARMBranchData &src) {
    m_type = src.m_type;
    m_condition = src.m_condition;
    switch (src.m_type) {
        case ARMBranchType::Direct:
            m_target = src.m_target;
            break;
        case ARMBranchType::IndirectLoad:
            m_operand = src.m_operand;
            break;
        case ARMBranchType::IndirectPop:
            break;
        case ARMBranchType::IndirectReg:
            m_reg = src.m_reg;
            break;
        default:
            m_type = ARMBranchType::Invalid;
    }
}
const std::string ARMBranchData::conditionToString() const {
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
