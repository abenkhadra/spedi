//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#pragma once
#include <stddef.h>
#include <stdint.h>

namespace disasm {
// memory address type
using addr_t = size_t ;

enum class ARMCodeSymbolType: unsigned short {
    kThumb = 1,
    kARM = 2,
    kData = 4
};

enum class ISAType: unsigned short {
    kUnknown = 0,
    kThumb = 1,
    kARM = 2,
    kTriCore = 3,
    kx86 = 4,
    kMIPS = 5,
    kPPC = 6,
    kSPARC = 7,
    kx86_64 = 8,
};

enum class ISAInstWidth: unsigned short{
    kByte = 1,
    kHWord = 2,  // half-word
    kWord = 4,
};
}
