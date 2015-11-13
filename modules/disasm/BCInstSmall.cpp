//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.


#include "BCInstSmall.h"
#include <capstone/capstone.h>
#include <cstring>

namespace disasm {

BCInstSmall::BCInstSmall(cs_insn *inst)
    : m_inst_id{inst->id},
      m_addr{inst->address},
      m_size{inst->size} {

    std::memcpy(m_bytes, inst->bytes, inst->size);
}

unsigned int
BCInstSmall::getInstId() const {
    return m_inst_id;
}

size_t
BCInstSmall::getSize() const {
    return m_size;
}

size_t
BCInstSmall::getAddr() const {
    return m_addr;
}

bool
BCInstSmall::operator<(BCInstSmall other) const {
    return m_addr < other.getAddr();
}

bool
BCInstSmall::operator==(BCInstSmall &other) const {
    return (m_addr == other.getAddr());
}

const uint8_t*
BCInstSmall::getBytes() const {
    return m_bytes;
}
}
