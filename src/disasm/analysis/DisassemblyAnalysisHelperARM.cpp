//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "DisassemblyAnalysisHelperARM.h"
#include "CFGNode.h"

namespace disasm {

DisassemblyAnalysisHelperARM::DisassemblyAnalysisHelperARM() :
    m_isa{ISAType::kThumb} {
}

DisassemblyAnalysisHelperARM::DisassemblyAnalysisHelperARM(ISAType isa) :
    m_isa{isa} {
}

std::vector<const MCInst *>
DisassemblyAnalysisHelperARM::getPCRelativeLoadInstructions
    (const CFGNode *cfg_node) const noexcept {
    // XXX: assuming pc-relative loads can happen only in LDR, VLDR, and LDRD
    auto predicate = [](const MCInst *inst) -> bool {
        if ((inst->id() == ARM_INS_LDR ||
            inst->id() == ARM_INS_VLDR) &&
            inst->detail().arm.operands[1].mem.base == ARM_REG_PC) {
            return true;
        }
        return false;
    };
    return cfg_node->getCandidateInstructionsSatisfying(predicate);
}

addr_t DisassemblyAnalysisHelperARM::recoverLDRSwitchBaseAddr
    (const CFGNode &node) const {
    const auto &switch_inst = node.maximalBlock()->branchInstruction();
    if (switch_inst->detail().arm.operands[1].mem.base == ARM_REG_PC) {
        if (switch_inst->addr() % 4 == 0) {
            return switch_inst->addr() + 4;
        } else {
            return switch_inst->addr() + 6;
        }
    } else {
        for (const auto &inst:node.maximalBlock()->getInstructions()) {
            if (inst.id() == ARM_INS_ADR
                && (inst.detail().arm.operands[0].reg
                    == switch_inst->detail().arm.operands[1].mem.base)) {
                addr_t base =
                    inst.addr() + inst.detail().arm.operands[1].imm + 4;
                if (base % 4 == 0) {
                    return base;
                } else {
                    return base - 2;
                }
            } else if (inst.id() == ARM_INS_ADDW
                && (inst.detail().arm.operands[0].reg
                    == switch_inst->detail().arm.operands[1].mem.base)) {
                addr_t base =
                    inst.addr() + inst.detail().arm.operands[2].imm + 4;
                if (base % 4 == 0) {
                    return base;
                } else {
                    return base - 2;
                }
            }
        }
        return 0;
    }
}

unsigned DisassemblyAnalysisHelperARM::getLRStackStoreIndex
    (const CFGNode *cfg_node) const noexcept {
    auto predicate = [](const MCInst *inst) -> bool {
        return inst->id() == ARM_INS_PUSH;
    };
    auto stack_pushes = cfg_node->getCandidateInstructionsSatisfying(predicate);
    // LR is normally the last one to be saved
    for (const auto inst_ptr: stack_pushes) {
        for (int i = (inst_ptr->detail().arm.op_count - 1);
             i > -1; --i) {
            if (inst_ptr->detail().arm.operands[i].reg == ARM_REG_LR) {
                return (unsigned) i + 1;
            }
        }
    }
    return 0;
}

bool DisassemblyAnalysisHelperARM::isReturnToCaller
    (const MCInst *inst) const noexcept {
    if (inst->id() == ARM_INS_B || inst->id() == ARM_INS_BX) {
        if (inst->detail().arm.operands[0].reg == ARM_REG_LR) {
            return true;
        }
    }
    if (inst->id() == ARM_INS_POP) {
        for (int i = inst->detail().arm.op_count - 1; 0 <= i; --i) {
            if (inst->detail().arm.operands[i].reg == ARM_REG_PC) {
                return true;
            }
        }
    }
    // TODO: ldr pc, [sp], imm is another type of return calls?
    return false;
}

bool DisassemblyAnalysisHelperARM::isIndirectTailCall
    (const MCInst *inst) const noexcept {
    if (inst->id() == ARM_INS_B || inst->id() == ARM_INS_BX) {
        if (inst->detail().arm.operands[0].reg != ARM_REG_LR) {
            return true;
        }
    }
    return false;
}
}
