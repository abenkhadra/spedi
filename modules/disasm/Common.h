//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once
#include <stddef.h>
#include <stdint.h>

namespace disasm {
// memory address type
using addr_t = uint64_t;

enum class BranchInstType: unsigned short {
    kUnknown = 0,
    kDirect = 1,
    kInDirect = 2,
    kConditional = 4,
    kUnconditional = 8
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

enum class ARMCodeSymbolType: unsigned short {
    kThumb = 1,
    kARM = 2,
    kData = 4
};
}
