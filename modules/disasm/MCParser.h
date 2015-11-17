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

namespace disasm {
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
    MCParser(cs_arch arch, cs_mode mode);
    virtual ~MCParser();
    MCParser(const MCParser &src) = delete;
    MCParser &operator=(const MCParser &src) = delete;
    MCParser(MCParser &&src) = default;
    MCParser &operator=(MCParser &&src) = default;

    void initialize();

    void reset(cs_arch arch, cs_mode);
    void changeMode(cs_mode);

    bool valid() const { return m_valid; }

    const cs_arch& arch() const {
        return m_arch;
    }

    const cs_mode& mode() const {
        return m_mode;
    }

private:
    bool m_valid;
    void * m_code;

    csh m_handle;
    cs_arch m_arch;
    cs_mode m_mode;

};
}



