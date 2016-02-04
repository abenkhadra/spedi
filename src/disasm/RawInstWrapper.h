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
 * RawInstWrapper
 * A wrapper around capstone's cs_insn, composition was used instead of
 * inheritance to ensure compatiblity with C API.
 */
class RawInstWrapper final {
public:
    /**
     * Allocates memory for cs_insn and frees memory in destructor.
     */
    RawInstWrapper();
    /**
     * Owns a pointer to an already allocated cs_insn.
     */
    explicit RawInstWrapper(cs_insn *instruction);
    ~RawInstWrapper() = default;
    RawInstWrapper(const RawInstWrapper &src) = delete;
    RawInstWrapper &operator=(const RawInstWrapper &src) = delete;
    RawInstWrapper(RawInstWrapper &&src) = default;
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
    std::unique_ptr<cs_insn, RawInstWrapper::DefaultDeleter> m_inst;
};
}
