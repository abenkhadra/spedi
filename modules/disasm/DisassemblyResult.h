//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#pragma once

#include "Common.h"
#include <string>

namespace disasm {
/**
 * DisassemblyResult
 */
class DisassemblyResult {
public:
    /**
     * Construct a DisassemblyResult that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */

    explicit DisassemblyResult();
    virtual ~DisassemblyResult() = default;
    DisassemblyResult(const DisassemblyResult &src) = default;
    DisassemblyResult &operator=(const DisassemblyResult &src) = default;
    DisassemblyResult(DisassemblyResult &&src) = default;

    bool valid() const { return m_valid; }

    const std::string &getName() const;

private:
    bool m_valid;
    std::string m_name;
    addr_t m_start_addr;
    size_t m_size;

};
}
