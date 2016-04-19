//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015-2016 University of Kaiserslautern.

#include "MCParser.h"
#include "RawInstWrapper.h"
#include <cassert>

namespace disasm {

void MCParser::initialize(cs_arch arch, cs_mode mode,
                addr_t end_addr) {
    m_arch = arch;
    m_mode = mode;
    m_end_addr = end_addr;
    cs_err err_no;
    err_no = cs_open(m_arch, m_mode, &m_handle);
    if (err_no) {
        throw std::runtime_error("Failed on cs_open() "
                                     "with error returned:" + err_no);
    }
    cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
    m_valid = true;
}

MCParser::~MCParser() {
    cs_close(&m_handle);
}

void MCParser::reset(cs_arch arch, cs_mode mode) {
    if(valid())
        cs_close(&m_handle);
    m_arch = arch;
    m_mode = mode;
    cs_err err_no;
    err_no = cs_open(m_arch, m_mode, &m_handle);
    if (err_no) {
        throw std::runtime_error("Failed on cs_open() "
                                     "with error returned:" + err_no);
    }
    cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
    m_valid = true;
}

void MCParser::changeModeTo(cs_mode mode) {
    m_mode = mode;
    cs_option(m_handle, CS_OPT_MODE, mode);
}

bool MCParser::disasm(const uint8_t *code,
                      size_t size,
                      addr_t address,
                      cs_insn *inst) const noexcept {
    assert(address <= m_end_addr && "Address out of bound");
    auto result = cs_disasm_iter(m_handle, &code, &size, &address, inst);
    switch (inst->id) {
        case ARM_INS_CBNZ:
            inst->detail->arm.cc = ARM_CC_NE;
            break;
        case ARM_INS_CBZ:
            inst->detail->arm.cc = ARM_CC_EQ;
            break;
        default:
            break;
    }
    return result;
}

bool MCParser::disasm2(const uint8_t **code,
                       size_t *size,
                       addr_t *address,
                       cs_insn *inst) const noexcept {
    assert(*address <= m_end_addr && "Address out of bound");
    auto result = cs_disasm_iter(m_handle, code, size, address, inst);
    switch (inst->id) {
        case ARM_INS_CBNZ:
            inst->detail->arm.cc = ARM_CC_NE;
            break;
        case ARM_INS_CBZ:
            inst->detail->arm.cc = ARM_CC_EQ;
            break;
        default:
            break;
    }
    return result;
}
}
