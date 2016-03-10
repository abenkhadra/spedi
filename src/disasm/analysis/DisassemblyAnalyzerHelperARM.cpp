//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "DisassemblyAnalyzerHelperARM.h"
#include "CFGNode.h"
#include <cassert>

namespace disasm {

DisassemblyAnalyzerHelperARM::DisassemblyAnalyzerHelperARM() :
    m_isa{ISAType::kThumb} {
}

DisassemblyAnalyzerHelperARM::DisassemblyAnalyzerHelperARM(ISAType isa) :
    m_isa{isa} {
}

std::vector<const MCInst *>
DisassemblyAnalyzerHelperARM::getPCRelativeLoadsInstructions
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

addr_t DisassemblyAnalyzerHelperARM::recoverLDRSwitchBaseAddr
    (const CFGNode &node) const {
    const auto &switch_inst = node.maximalBlock()->branchInstruction();
    if (switch_inst->detail().arm.operands[1].mem.base == ARM_REG_PC) {
        if (switch_inst->addr() % 4 == 0) {
            return switch_inst->addr() + 4;
        } else {
            return switch_inst->addr() + 6;
        }
    } else {
        for (const auto &inst:node.maximalBlock()->getAllInstructions()) {
            if (inst.id() == ARM_INS_ADR
                && (inst.detail().arm.operands[0].reg
                    == switch_inst->detail().arm.operands[1].mem.base)) {
                if (inst.addr() % 4 == 0) {
                    return inst.addr() + inst.detail().arm.operands[1].imm + 8;
                } else {
                    return inst.addr() + inst.detail().arm.operands[1].imm + 10;
                }
            }
        }
        return 0;
    }
}

unsigned DisassemblyAnalyzerHelperARM::getLRStackStoreIndex
    (const CFGNode *cfg_node) const noexcept {
    auto predicate = [](const MCInst *inst) -> bool {
        if (inst->id() == ARM_INS_PUSH) {
            return true;
        }
        return false;
    };
    auto stack_pushes = cfg_node->getCandidateInstructionsSatisfying(predicate);
    assert(stack_pushes.size() < 2
               && "Too many stack allocations in a single MB!!");
    for (const auto inst_ptr: stack_pushes) {
        for (unsigned char i = 0; i < inst_ptr->detail().arm.op_count; ++i) {
            if (inst_ptr->detail().arm.operands[i].reg == ARM_REG_LR) {
                return i + 1;
            }
        }
    }
    return 0;
}

bool DisassemblyAnalyzerHelperARM::isReturn(const MCInst *inst) const noexcept {
    if (inst->id() == ARM_INS_B || inst->id() == ARM_INS_BX) {
        if (inst->detail().arm.operands[0].reg == ARM_REG_LR) {
            return true;
        }
    }
    if (inst->id() == ARM_INS_POP) {
        for (int i = 0; i < inst->detail().arm.op_count; ++i) {
            if (inst->detail().arm.operands[i].reg == ARM_REG_PC) {
                return true;
            }
        }
    }
    return false;
}

bool DisassemblyAnalyzerHelperARM::isCall(const MCInst *inst) const noexcept {
    return inst->id() == ARM_INS_BLX || inst->id() == ARM_INS_BL;
}
}
