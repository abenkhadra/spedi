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

    unsigned id() const;

    size_t size() const;

    addr_t addr() const;

    arm_cc condition() const;

    const cs_detail &detail() const;

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
    std::string m_mnemonic;
    std::string m_operands;
    cs_detail m_detail;
};
}
