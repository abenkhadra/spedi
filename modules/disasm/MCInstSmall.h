//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once

#include <capstone/capstone.h>
#include "Common.h"

// Forward declaration to avoid including capstone.h as much as possible
struct cs_insn;

namespace disasm {

/**
 * MCInstSmall
 */
class MCInstSmall {
public:
    MCInstSmall() = delete;
    explicit MCInstSmall(cs_insn* inst);
    virtual ~MCInstSmall() = default;
    MCInstSmall(const MCInstSmall &src) = default;
    MCInstSmall &operator=(const MCInstSmall &src) = default;
    MCInstSmall(MCInstSmall &&src) = default;

    void reset(cs_insn *inst);

    unsigned int id() const;

    size_t size() const;

    addr_t addr() const;

    const uint8_t* bytes() const;

    bool operator<(MCInstSmall other) const;
    bool operator==(MCInstSmall &other) const;

private:
    unsigned int m_id;
    addr_t m_addr;
    unsigned int m_size;
    // Practically, we only need 4 bytes for RISC ISA. We follow Capstone
    // to accommodate x86_64 which can reach 15 bytes.
    uint8_t m_bytes[16];
};
}
