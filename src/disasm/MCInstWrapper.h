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
#include <memory>

namespace disasm {

/**
 * MCInstWrapper
 * A wrapper around capstone's cs_insn, composition was used instead of
 * inheritance to ensure compatiblity with C API.
 */
class MCInstWrapper final {
public:
    /**
     * Allocates memory for cs_insn and frees memory in destructor.
     */
    MCInstWrapper();
    /**
     * Owns a pointer to an already allocated cs_insn.
     */
    explicit MCInstWrapper(cs_insn *instruction);
    ~MCInstWrapper() = default;
    MCInstWrapper(const MCInstWrapper &src) = delete;
    MCInstWrapper &operator=(const MCInstWrapper &src) = delete;
    MCInstWrapper(MCInstWrapper &&src) = default;
    cs_insn *rawPtr();

    bool isValid() const;

private:
    class DefaultDeleter {
    public:
        void operator()(cs_insn *inst) {
            if (inst->detail != NULL) {
                // memory for instruction details could have been allocated
                // by capstone API.
                free(inst->detail);
            }
            free(inst);
        }
    };
    std::unique_ptr<cs_insn, MCInstWrapper::DefaultDeleter> m_inst;
};
}
