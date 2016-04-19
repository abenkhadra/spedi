//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#pragma once

#include "common.h"
#include <capstone/capstone.h>

namespace disasm {

class RawInstWrapper;
/**
 * MCParser
 */
class MCParser {
public:
    /**
     * Construct a MCParser that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    MCParser() = default;
    virtual ~MCParser();
    MCParser(const MCParser &src) = delete;
    MCParser &operator=(const MCParser &src) = delete;
    MCParser(MCParser &&src) = default;
    MCParser &operator=(MCParser &&src) = default;

    void initialize(cs_arch arch, cs_mode mode,
                    addr_t end_addr);

    void reset(cs_arch arch, cs_mode);

    void changeModeTo(cs_mode);

    bool valid() const { return m_valid; }

    bool disasm(const uint8_t *code, size_t size, addr_t address, cs_insn *inst)
        const noexcept;

    bool disasm2(const uint8_t **code,
                 size_t *size,
                 addr_t *address,
                 cs_insn *inst) const noexcept;

    const cs_arch &arch() const {
        return m_arch;
    }

    const cs_mode &mode() const {
        return m_mode;
    }

    const csh &handle() const {
        return m_handle;
    }

private:
    bool m_valid;
    csh m_handle;
    cs_arch m_arch;
    cs_mode m_mode;
    addr_t m_end_addr;
};
}
