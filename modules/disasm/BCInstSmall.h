//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once

#include "common.h"

namespace disasm {

// avoid including
struct cs_insn;
/**
 * BCInstSmall
 */
class BCInstSmall {
public:
    BCInstSmall() = delete;
    BCInstSmall(cs_insn* inst);
    virtual ~BCInstSmall() = default;
    BCInstSmall(const BCInstSmall &src) = default;
    BCInstSmall &operator=(const BCInstSmall &src) = default;
    BCInstSmall(BCInstSmall &&src) = default;

    unsigned int getInstId() const;

    size_t getSize() const;

    size_t getAddr() const;

    const uint8_t* getBytes() const;

    bool operator<(BCInstSmall other) const;
    bool operator==(BCInstSmall &other) const;

private:
    unsigned int m_inst_id;
    addr_t m_addr;
    uint16_t m_size;
    // Practically, we only need 4 bytes for RISC ISA. We follow Capstone
    // to accommodate x86_64 which can reach 15 bytes.
    uint8_t m_bytes[16];
};
}



