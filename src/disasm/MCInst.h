//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#pragma once

#include "common.h"
#include "capstone/capstone.h"
#include <string>

namespace disasm {

/**
 * MCInst
 */
class MCInst {
public:
    // TODO: this class should be refactored to MCInst. It should be the base of
    // class hierarchy. Derived classes include MCInstARM and MCInstX86.
    MCInst() = delete;
    explicit MCInst(const cs_insn *inst);
    virtual ~MCInst() = default;
    MCInst(const MCInst &src) = default;
    MCInst &operator=(const MCInst &src) = default;
    MCInst(MCInst &&src) = default;

    unsigned id() const;

    size_t size() const;

    addr_t addr() const;

    const arm_cc &condition() const;

    bool operator<(MCInst other) const;
    bool operator==(MCInst &other) const;

    const std::string &mnemonic() const {
        return m_mnemonic;
    }
    const std::string &operands() const {
        return m_operands;
    }

private:
    unsigned int m_id;
    addr_t m_addr;
    unsigned m_size;
    // Practically, we only need 4 bytes for RISC ISA. We can follow Capstone
    // to accommodate x86_64 which can reach 15 bytes.
//    uint8_t m_bytes[4];
    arm_cc m_condition;
    std::string m_mnemonic;
    std::string m_operands;
};
}
