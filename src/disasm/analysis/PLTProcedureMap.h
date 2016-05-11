//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#pragma once

#include "binutils/elf/elf++.hh"
#include "disasm/common.h"
#include "disasm/MCParser.h"
#include <unordered_map>

namespace disasm {
/**
 * PLTProcedureMap
 * Provides mapping between .got offsets, procedure names,
 * and procedure addresses.
 */
class PLTProcedureMap {
public:
    /**
     * Construct a PLTProcedureMap that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    PLTProcedureMap() = delete;
    PLTProcedureMap(const elf::elf *elf_file);
    virtual ~PLTProcedureMap() = default;
    PLTProcedureMap(const PLTProcedureMap &src) = default;
    PLTProcedureMap &operator=(const PLTProcedureMap &src) = default;
    PLTProcedureMap(PLTProcedureMap &&src) = default;

    std::pair<addr_t, bool> addProcedure(addr_t proc_entry_addr) noexcept;
    bool isNonReturning(addr_t proc_entry_addr) noexcept;
    const char * getName(addr_t proc_entry_addr) const noexcept;
    bool isNonReturning(const char * proc_name) const noexcept;
    addr_t calculateGotOffset(addr_t proc_entry_addr) const noexcept;
    bool valid() const { return m_elf_file->valid(); }
    bool isWithinPLTSection(addr_t addr) const noexcept;
private:
    const elf::elf *m_elf_file;
    std::unordered_map<addr_t, const char *> m_got_to_proc_name_map;
    std::unordered_map<addr_t, std::pair<addr_t, bool>> m_addr_got_map;
    MCParser m_parser;
    const uint8_t *m_start_plt_code_ptr;
    addr_t m_start_plt_addr;
    addr_t m_end_plt_addr;
};
}
