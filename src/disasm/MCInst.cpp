//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#include "MCInst.h"

namespace disasm {

MCInst::MCInst(const cs_insn *inst) :
    m_id{inst->id},
    m_addr{inst->address},
    m_size{inst->size},
    m_mnemonic{inst->mnemonic},
    m_operands{inst->op_str} {
    m_detail = *(inst->detail);
}

unsigned
MCInst::id() const {
    return m_id;
}

addr_t
MCInst::addr() const {
    return m_addr;
}

size_t
MCInst::size() const {
    return m_size;
}

bool
MCInst::operator<(MCInst other) const {
    return m_addr < other.addr();
}

bool
MCInst::operator==(MCInst &other) const {
    return (m_addr == other.addr());
}

const arm_cc &MCInst::condition() const {
    return m_detail.arm.cc;
}
}
