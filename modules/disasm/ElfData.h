//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once

namespace elf {
enum class ElfABI: unsigned char {
    kSystem_V = 0x00,
    kHP_UX = 0x01,
    kNetBSD = 0x02,
    kLinux = 0x03,
    kSolaris = 0x06,
    kAIX = 0x07,
    kIRIX = 0x08,
    kFreeBSD = 0x09,
    kOpenBSD = 0x0C,
    kOpenVMS = 0x0D
};

//template<typename E = Elf64>
enum class ElfISA: ElfTypes::Half {
    kSPARC = 0x02,
    kx86 = 0x03,
    kMIPS = 0x08,
    kPowerPC = 0x14,
    kARM = 0x28,
    kSuperH = 0x2A,
    kIA_64 = 0x32,
    kx86_64 = 0x3E,
    kAArch64 = 0xB7
};

}
