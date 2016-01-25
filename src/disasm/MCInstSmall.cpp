//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#include "MCInstSmall.h"
#include <capstone/capstone.h>
#include <cstring>

namespace disasm {

MCInstSmall::MCInstSmall(const cs_insn *inst) :
    m_id{inst->id},
    m_addr{inst->address},
    m_size{inst->size},
    m_condition{inst->detail->arm.cc},
    m_mnemonic{inst->mnemonic},
    m_operands{inst->op_str} {

//    std::memcpy(m_bytes, inst->bytes, inst->size);
}

unsigned
MCInstSmall::id() const {
    return m_id;
}

addr_t
MCInstSmall::addr() const {
    return m_addr;
}

size_t
MCInstSmall::size() const {
    return m_size;
}

bool
MCInstSmall::operator<(MCInstSmall other) const {
    return m_addr < other.addr();
}

bool
MCInstSmall::operator==(MCInstSmall &other) const {
    return (m_addr == other.addr());
}

const arm_cc &MCInstSmall::condition() const {
    return m_condition;
}
}
