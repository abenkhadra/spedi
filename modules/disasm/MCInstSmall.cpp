//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "MCInstSmall.h"
#include <capstone/capstone.h>
#include <cstring>

namespace disasm {

MCInstSmall::MCInstSmall(cs_insn *inst)
    : m_id{inst->id},
      m_addr{inst->address},
      m_size{inst->size} {

    std::memcpy(m_bytes, inst->bytes, inst->size);
}

unsigned int
MCInstSmall::id() const {
    return m_id;
}

size_t
MCInstSmall::size() const {
    return m_size;
}

addr_t
MCInstSmall::addr() const {
    return m_addr;
}

bool
MCInstSmall::operator<(MCInstSmall other) const {
    return m_addr < other.addr();
}

bool
MCInstSmall::operator==(MCInstSmall &other) const {
    return (m_addr == other.addr());
}

const uint8_t*
MCInstSmall::bytes() const {
    return m_bytes;
}

void
MCInstSmall::reset(cs_insn *inst) {
    m_id = inst->id;
    m_addr = inst->address;
    m_size = inst->size;
    std::memcpy(m_bytes, inst->bytes, inst->size);
}
}
