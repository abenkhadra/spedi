//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once

#include <capstone/capstone.h>
#include <memory>

namespace disasm {
/**
 * MCInst
 * A wrapper around capstone's cs_insn, composition was used instead of
 * inheritance to ensure compatiblity with C API.
 */

class MCInst final{
public:
    /// Allocates memory for cs_insn and frees memory in destructor.
    MCInst();

    /// Owns a pointer to an already allocated cs_insn.
    MCInst(cs_insn * instruction);
    ~MCInst() = default;
    MCInst(const MCInst &src) = delete;
    MCInst &operator=(const MCInst &src) = delete;
    MCInst(MCInst &&src) = default;
    cs_insn* getRawPtr();


private:
    class MCInstDefaultDeleter {
    public:
        void operator()(cs_insn *inst) {
            if (inst->detail != NULL) {
                // memory for instruction details should have been allocated
                // by capstone API.
                free(inst->detail);
            }
            free(inst);
        }
    };
    std::unique_ptr <cs_insn, MCInst::MCInstDefaultDeleter> m_inst;
};

}

