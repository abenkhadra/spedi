//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#pragma once

#include <bits/stringfwd.h>
#include "common.h"
#include <string>

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

    const unsigned int & id() const;

    const size_t & size() const;

    const addr_t & addr() const;

    const uint8_t* bytes() const;

    bool operator<(MCInstSmall other) const;
    bool operator==(MCInstSmall &other) const;

    const std::string &mnemonic() const {
        return m_mnemonic;
    }
    const std::string &operands() const {
        return m_operands;
    }

private:
    unsigned int m_id;
    addr_t m_addr;
    unsigned int m_size;
    // Practically, we only need 4 bytes for RISC ISA. We can follow Capstone
    // to accommodate x86_64 which can reach 15 bytes.
    uint8_t m_bytes[4];
    std::string m_mnemonic;
    std::string m_operands;
};
}
