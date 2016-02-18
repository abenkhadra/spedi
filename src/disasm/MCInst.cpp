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

unsigned MCInst::id() const noexcept {
    return m_id;
}

addr_t MCInst::addr() const noexcept {
    return m_addr;
}

size_t MCInst::size() const noexcept {
    return m_size;
}

bool MCInst::operator<(MCInst other) const noexcept {
    return m_addr < other.addr();
}

bool MCInst::operator==(MCInst &other) const noexcept {
    return (m_addr == other.addr());
}

arm_cc MCInst::condition() const noexcept {
    return m_detail.arm.cc;
}

const cs_detail &MCInst::detail() const noexcept {
    return m_detail;
}

addr_t MCInst::endAddr() const noexcept {
    return m_addr + m_size;
}

const std::string &MCInst::mnemonic() const noexcept {
    return m_mnemonic;
}

const std::string &MCInst::operands() const noexcept {
    return m_operands;
}
}
