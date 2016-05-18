//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2016 University of Kaiserslautern.

#include "PLTProcedureMap.h"
#include <elf.h>
#include <cassert>

namespace disasm {

PLTProcedureMap::PLTProcedureMap(const elf::elf *elf_file) :
    m_elf_file{elf_file} {

    std::vector<const char *> dyn_func_names;
    // ELF standard: sections and segments have no specified order
    for (const auto &sec : m_elf_file->sections()) {
        if (sec.get_name() == ".dynsym") {
            auto dynsymtab = sec.as_symtab();
            size_t len;
            for (auto sym : dynsymtab) {
                dyn_func_names.push_back(sym.get_name(&len));
            }
            break;
        }
    }

    for (const auto &sec : m_elf_file->sections()) {
        if (sec.get_name() == ".rel.plt") {
            for (const Elf32_Rel
                     *rel_iter = static_cast<const Elf32_Rel *> (sec.data());
                 rel_iter < reinterpret_cast<const Elf32_Rel *>
                 (static_cast<const uint8_t *>(sec.data()) + sec.size());
                 ++rel_iter) {
                auto func_name = dyn_func_names[ELF32_M_SYM(rel_iter->r_info)];
                m_got_proc_name_map.insert({rel_iter->r_offset, func_name});
            }
            break;
        }
    }
    for (const auto &sec : m_elf_file->sections()) {
        if (sec.get_name() == ".plt") {
            m_start_plt_addr = sec.get_hdr().addr;
            m_start_plt_code_ptr = static_cast<const uint8_t *>(sec.data());
            m_end_plt_addr = m_start_plt_addr + sec.get_hdr().size;
            m_parser.initialize(CS_ARCH_ARM, CS_MODE_ARM, m_end_plt_addr);
            break;
        }
    }
}

const char *PLTProcedureMap::getName(addr_t proc_entry_addr) const noexcept {
    auto res_find_entry = m_addr_got_map.find(proc_entry_addr);
    if (res_find_entry != m_addr_got_map.end()) {
        auto res_find_proc_name =
            m_got_proc_name_map.find((*res_find_entry).second.first);
        return (*res_find_proc_name).second;
    }
    return nullptr;
}

std::pair<const char *, bool> PLTProcedureMap::addProcedure
    (addr_t proc_entry_addr) noexcept {
    // first check if procedure is already found
    auto res_addr_got_return = m_addr_got_map.find(proc_entry_addr);
    if (res_addr_got_return != m_addr_got_map.end()) {
        auto res_got_name =
            m_got_proc_name_map.find((*res_addr_got_return).second.first);
        return {(*res_got_name).second, (*res_addr_got_return).second.second};
    }
    addr_t got_offset = calculateGotOffset(proc_entry_addr);
    auto res_got_name = m_got_proc_name_map.find(got_offset);
    assert(res_got_name != m_got_proc_name_map.end()
               && "Invalid GOT offset calculated!");
    bool non_returning = isNonReturnProcedure((*res_got_name).second);
    m_addr_got_map.insert({proc_entry_addr, {got_offset, non_returning}});
    return {(*res_got_name).second, non_returning};
}

bool PLTProcedureMap::isNonReturnProcedure(addr_t proc_entry_addr) noexcept {
    auto res_find_entry = m_addr_got_map.find(proc_entry_addr);
    if (res_find_entry != m_addr_got_map.end()) {
        return (*res_find_entry).second.second;
    }
    return false;
}

bool PLTProcedureMap::isNonReturnProcedure(const char *proc_name) const noexcept {
    // compares procedure name with well-known non-returning procedures
    if (strcmp(proc_name, "__assert_fail") == 0) {
        return true;
    }
    if (strcmp(proc_name, "__stack_chk_fail") == 0) {
        return true;
    }
    if (strcmp(proc_name, "_exit") == 0) {
        return true;
    }
    if (strcmp(proc_name, "abort") == 0) {
        return true;
    }
    if (strcmp(proc_name, "exit") == 0) {
        return true;
    }
    return false;
}

addr_t PLTProcedureMap::calculateGotOffset(addr_t proc_entry_addr) const noexcept {
    const uint8_t *code_ptr =
        m_start_plt_code_ptr - m_start_plt_addr + proc_entry_addr;
    cs_insn inst;
    cs_detail detail;
    inst.detail = &detail;
    size_t size = 12;
    m_parser.disasm2(&code_ptr, &size, &proc_entry_addr, &inst);
    if (inst.id != ARM_INS_ADD) {
        // handling inline veneer that performs a state mode change only
        m_parser.disasm2(&code_ptr, &size, &proc_entry_addr, &inst);
        size = 8;
    }
    assert(inst.id == ARM_INS_ADD && "Invalid PLT entry!!");
    // This instruction should actually be ADR
    addr_t result = inst.address + 8; // PC value
    m_parser.disasm2(&code_ptr, &size, &proc_entry_addr, &inst);
    assert(inst.id == ARM_INS_ADD && "Invalid PLT entry!!");
    result += detail.arm.operands[2].imm;
    m_parser.disasm2(&code_ptr, &size, &proc_entry_addr, &inst);
    assert(inst.id == ARM_INS_LDR && "Invalid PLT entry!!");
    result += detail.arm.operands[1].mem.disp;
    return result;
}

bool PLTProcedureMap::isWithinPLTSection(addr_t addr) const noexcept {
    return m_start_plt_addr <= addr && addr < m_end_plt_addr;
}
}
