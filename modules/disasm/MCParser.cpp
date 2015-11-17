//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#include "MCParser.h"
#include <stdexcept>

namespace disasm {

MCParser::MCParser(cs_arch arch, cs_mode mode):
    m_arch{arch},
    m_mode{mode}{
}

void MCParser::initialize() {
    cs_err err_no;
    err_no = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &m_handle);
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
    initialize();
}

void MCParser::changeMode(cs_mode mode) {
    m_mode = mode;
    cs_option(m_handle, CS_OPT_MODE, mode);
}
}