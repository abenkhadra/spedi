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
    MCInst() = delete;
    explicit MCInst(const cs_insn *inst);
    virtual ~MCInst() = default;
    MCInst(const MCInst &src) = default;
    MCInst &operator=(const MCInst &src) = default;
    MCInst(MCInst &&src) = default;

    unsigned id() const noexcept;
    size_t size() const noexcept;
    addr_t addr() const noexcept;
    arm_cc condition() const noexcept;
    addr_t endAddr() const noexcept;
    const cs_detail &detail() const noexcept;

    bool operator<(MCInst other) const noexcept;
    bool operator==(MCInst &other) const noexcept;

    const std::string &mnemonic() const noexcept;

    const std::string &operands() const noexcept;

private:
    unsigned int m_id;
    addr_t m_addr;
    unsigned m_size;
    std::string m_mnemonic;
    std::string m_operands;
    cs_detail m_detail;
};
}
