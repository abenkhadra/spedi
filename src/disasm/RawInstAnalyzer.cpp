//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#include "RawInstAnalyzer.h"

namespace disasm {

RawInstAnalyzer::RawInstAnalyzer(ISAType isa) :
    m_isa{isa},
    m_inst_width{getMinxInstWidth(isa)} {
}

bool RawInstAnalyzer::isBranch(const cs_insn *inst) const {
    if (inst->detail == NULL) return false;

    cs_detail *detail = inst->detail;
    // assuming that each instruction should belong to at least one group
    if (detail->groups[detail->groups_count - 1] == ARM_GRP_JUMP)
        return true;
    if (inst->id == ARM_INS_POP) {
        // pop accepts a register list. If pc was among them then this a branch
        for (int i = 0; i < detail->arm.op_count; ++i) {
            if (detail->arm.operands[i].reg == ARM_REG_PC) return true;
        }
    }

    if ((detail->arm.operands[0].type == ARM_OP_REG)
        && (detail->arm.operands[0].reg == ARM_REG_PC)) {
        if (inst->id == ARM_INS_STR) {
            return false;
        }
        return true;
    }
    return false;
}

bool RawInstAnalyzer::isValid(const cs_insn *inst) const {

    for (int i = 0; i < inst->detail->arm.op_count; ++i) {
        if (inst->detail->arm.operands[i].type == ARM_OP_REG) {
            if (inst->detail->arm.operands[i].reg == ARM_REG_PC) {
                // We do no apply PC, SP restrictions to load instructions
                if (ARM_INS_LDA <= inst->id && inst->id <= ARM_INS_LDR) {
                    continue;
                }
                // PC usage restrictions based on manual A2-46
                // and Table D9.5 details.

                // use of pc in 16 bit add is deprecated D9.5
                switch (inst->id) {
                    case ARM_INS_ADD:
                    case ARM_INS_ADR:
                    case ARM_INS_BX:
                    case ARM_INS_BLX:
                    case ARM_INS_MOV:
                    case ARM_INS_SUB:
                    case ARM_INS_SUBS:
                    case ARM_INS_MOVS:
                    case ARM_INS_POP:
                        // XXX more restrictions can be applied here
                        break;
                    default:
                        // TODO: make logging consistent and configurable
//                        printf("Found invalid pc at 0x%lx, %s, %s\n",
//                               inst->address,
//                               inst->mnemonic,
//                               inst->op_str);
                        return false;
                }
            } else if (inst->detail->arm.operands[i].reg == ARM_REG_SP) {
                // We do not apply PC, SP restrictions to load instructions
                if (ARM_INS_LDA <= inst->id && inst->id <= ARM_INS_LDR) {
                    continue;
                }
                // restrictions on SP usage
                switch (inst->id) {
                    case ARM_INS_MOV:
                    case ARM_INS_ADD:
                    case ARM_INS_ADDW:
                    case ARM_INS_SUB:
                    case ARM_INS_SUBW:
                    case ARM_INS_CMN:
                    case ARM_INS_CMP:
                        break;
                    default:
                        // we allow stores to use SP
                        if (!(ARM_INS_STMDA <= inst->id
                            && inst->id <= ARM_INS_STR)) {
//                            printf("Found invalid sp at 0x%lx, %s, %s\n",
//                                   inst->address,
//                                   inst->mnemonic,
//                                   inst->op_str);
                            return false;
                        }
                        break;
                }
            }
        } else if (inst->detail->arm.operands[i].type == ARM_OP_CIMM
            || inst->detail->arm.operands[i].type == ARM_OP_PIMM) {
//            printf("Found invalid co-register at 0x%lx, %s, %s\n",
//                   inst->address,
//                   inst->mnemonic,
//                   inst->op_str);
            return false;
        }
//        else if (!(
//            ((ARM_REG_R0 <= inst->detail->arm.operands[i].reg) &&
//                (inst->detail->arm.operands[i].reg <= ARM_REG_R12))
//                || inst->detail->arm.operands[i].reg == ARM_REG_LR)) {
//            // XXX: using unusual registers such as co-processor registers
//            // is currently allowed. For example, we do not allow access
//            // to registers of system control co-processor (CP15). Note that
//            // only some instructions like MRC, MCREQ & MCR can use
//            // co-processor registers
//            printf("Found invalid register at 0x%lx, %s, %s\n",
//                   inst->address,
//                   inst->mnemonic,
//                   inst->op_str);
//            return false;
//        }
    }
    return true;
}

bool RawInstAnalyzer::isConditional(const cs_insn *inst) const {
    return inst->detail->arm.cc != ARM_CC_AL;
}

ISAInstWidth RawInstAnalyzer::getMinxInstWidth(ISAType isa) const {
    switch (isa) {
        case ISAType::kx86:
        case ISAType::kx86_64:
            return ISAInstWidth::kByte;
        case ISAType::kThumb:
        case ISAType::kTriCore:
            return ISAInstWidth::kHWord;
        default:
            return ISAInstWidth::kWord;
    }
}

const std::string RawInstAnalyzer::conditionCodeToString(const arm_cc &condition) const {
    switch (condition) {
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
bool RawInstAnalyzer::isDirectBranch(const cs_insn *inst) const {
    if (inst->id == ARM_INS_CBZ || inst->id == ARM_INS_CBNZ) {
        return true;
    }
    if (inst->detail->arm.op_count == 1
        && inst->detail->arm.operands[0].type == ARM_OP_IMM) {
        return true;
    }
    return false;
}
void RawInstAnalyzer::setISA(const ISAType isa) {
    m_isa = isa;
    m_inst_width = getMinxInstWidth(isa);
}
void RawInstAnalyzer::changeModeTo(const ISAType &isa) {
    if (isa == ISAType::kARM) {
        m_isa = ISAType::kARM;
    } else {
        m_isa = ISAType::kThumb;
    }
}
}
