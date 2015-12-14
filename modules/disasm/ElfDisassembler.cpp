//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under BSD License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 University of Kaiserslautern.

#include "ElfDisassembler.h"
#include "MCInst.h"
#include "MCParser.h"
#include "MaximalBlock.h"
#include "MCInstAnalyzer.h"
#include "MaximalBlockBuilder.h"
#include <inttypes.h>
#include <algorithm>

namespace disasm {

ElfDisassembler::ElfDisassembler() : m_valid{false} { }

ElfDisassembler::ElfDisassembler(const elf::elf &elf_file) :
    m_valid{true},
    m_inst_width{ISAInstWidth::kHWord},
    m_elf_file{&elf_file},
    m_isa{getInitialISAType()} {
//    m_inst_width = getISAMinWidth(m_isa);
}

void
printHex(unsigned char *str, size_t len) {
    unsigned char *c;

    printf("Code: ");
    for (c = str; c < str + len; c++) {
        printf("0x%02x ", *c & 0xff);
    }
    printf("\n");
}


void prettyPrintInst(const csh &handle, cs_insn *inst) {

    cs_detail *detail;
    int n;

    printf("0x%" PRIx64 ":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
           inst->address, inst->mnemonic, inst->op_str,
           inst->id, cs_insn_name(handle, inst->id));

    // print implicit registers used by this instruction
    detail = inst->detail;

    if (detail == NULL) return;

    if (detail->regs_read_count > 0) {
        printf("\tImplicit registers read: ");
        for (n = 0; n < detail->regs_read_count; n++) {
            printf("%s ", cs_reg_name(handle, detail->regs_read[n]));
        }
        printf("\n");
    }

    // print implicit registers modified by this instruction
    if (detail->regs_write_count > 0) {
        printf("\tImplicit registers modified: ");
        for (n = 0; n < detail->regs_write_count; n++) {
            printf("%s ", cs_reg_name(handle, detail->regs_write[n]));
        }
        printf("\n");
    }

    // print the groups this instruction belong to
    if (detail->groups_count > 0) {
        printf("\tThis instruction belongs to groups: ");
        for (n = 0; n < detail->groups_count; n++) {
            printf("%s ", cs_group_name(handle, detail->groups[n]));
        }
        printf("\n");
    }
}

void prettyPrintMaximalBlock
    (const MaximalBlock &mblock) {
    printf("**************************************\n");
    printf("MB No. %u, starts at %#6x, Direct branch: %d, Condition: %s",
           mblock.id(),
           static_cast<unsigned int> (mblock.startAddr()),
           mblock.branch().isDirect(),
           mblock.branch().conditionString().c_str());
    printf(" / BB count. %u, Total inst count %u: \n",
           mblock.getBasicBlocksCount(), mblock.getInstructionCount());
    for (auto &block :mblock.getBasicBlocks()) {
        printf("Basic Block Id %u, inst count %lu\n / ",
               block.id(), block.instCount());
        for (auto addr : block.getInstAddresses()) {
            printf(" Inst Addr: %#6x", static_cast<unsigned>(addr));
        }
        printf("\n");
    }
    for (auto &inst :mblock.getInstructions()) {
        printf("0x%" PRIx64 ":\t%s\t\t%s // insn-ID: %u \n",
               inst.addr(), inst.mnemonic().c_str(), inst.operands().c_str(),
               inst.id());

    }
}

void
ElfDisassembler::disassembleSectionUsingSymbols
    (const elf::section &sec) const {

    // a type_mismatch exception would thrown in case symbol table was not found
    auto symbols = getCodeSymbolsForSection(sec);

//    printf("Symbols size is %lu \n", symbols.size());
//
//    for (auto& symbol : symbols) {
//        printf("Type %d, Addrd, 0x%#x \n", symbol.second, symbol.first);
//    }

    size_t start_addr = sec.get_hdr().addr;
    size_t last_addr = start_addr + sec.get_hdr().size;

    MCParser parser{};
    parser.initialize(CS_ARCH_ARM, CS_MODE_THUMB, last_addr);

    const uint8_t *code_ptr = (const uint8_t *) sec.data();

    MCInst inst;
    cs_insn *inst_ptr = inst.rawPtr();

    printf("Section Name: %s\n", sec.get_name().c_str());

    // We assume that symbols are ordered by their address.
    size_t index = 0;
    size_t address = 0;
    size_t size = 0;

    for (auto &symbol : symbols) {
        index++;
        if (symbol.second == ARMCodeSymbolType::kData) {
            if (index < symbols.size())
                // adjust code_ptr to start of next symbol.
                code_ptr += (symbols[index].first - symbol.first);
            continue;
        }
        address = symbol.first;
        if (index < symbols.size())
            size = symbols[index].first - symbol.first;
        else
            size = last_addr - symbol.first;

        if (symbol.second == ARMCodeSymbolType::kARM)
            parser.changeModeTo(CS_MODE_ARM);
        else
            // We assume that the value of code symbol type is strictly
            // either Data, ARM, or Thumb.
            parser.changeModeTo(CS_MODE_THUMB);

        while (parser.disasm2(&code_ptr, &size, &address, &inst)) {
            prettyPrintInst(parser.handle(), inst_ptr);
        }
    }
}

void
ElfDisassembler::disassembleSectionbyName(std::string sec_name) const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_name() == sec_name) {
            disassembleSectionUsingSymbols(sec);
            break;
        }
    }
}

void
ElfDisassembler::disassembleSectionbyNameSpeculative(std::string sec_name) const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_name() == sec_name) {
            disassembleSectionSpeculative(sec);
            break;
        }
    }
}

void
ElfDisassembler::disassembleCodeUsingSymbols() const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.is_alloc() && sec.is_exec()) {
            disassembleSectionUsingSymbols(sec);
        }
    }
}

void
ElfDisassembler::disassembleSectionSpeculative(const elf::section &sec) const {

    printf("Section Name: %s\n", sec.get_name().c_str());
    size_t current = sec.get_hdr().addr;
    size_t temp_addr = 0;
    size_t last_addr = current + sec.get_hdr().size;
    size_t buf_size = 4;
    const uint8_t *code_ptr = (const uint8_t *) sec.data();

    MCParser parser;
    parser.initialize(CS_ARCH_ARM, CS_MODE_THUMB, last_addr);

    MCInst inst;
    cs_insn *inst_ptr = inst.rawPtr();

    MaximalBlockBuilder max_block_builder;

    MCInstAnalyzer analyzer(ISAType::kThumb);

    while (current < last_addr) {
        temp_addr = current;
        if (parser.disasm(code_ptr, &buf_size, &temp_addr, &inst)) {
            if (analyzer.isValid(inst_ptr)) {
                if (analyzer.isBranch(inst_ptr)) {
                    max_block_builder.appendBranch(inst_ptr);
                    prettyPrintMaximalBlock(max_block_builder.build());
                    max_block_builder.reset();
                } else {
                    max_block_builder.append(inst_ptr);
                }
            }
        }
        buf_size = 4; // code buf size should be reset after each read
        current += static_cast<unsigned>(m_inst_width);
        code_ptr += static_cast<unsigned>(m_inst_width);
    }
}

void
ElfDisassembler::disassembleCodeSpeculative() const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.is_alloc() && sec.is_exec()) {
            disassembleSectionSpeculative(sec);
        }
    }
}

std::vector<std::pair<size_t, ARMCodeSymbolType>>
ElfDisassembler::getCodeSymbolsForSection(const elf::section &sec) const {

    std::vector<std::pair<size_t, ARMCodeSymbolType>> result;
    // Check for symbol table, if none was found then
    // the instance is invalid.
    elf::section sym_sec = m_elf_file->get_section(".symtab");
    // Returning a valid section means that there was no symbol table
    //  provided in ELF file.
    if (!sym_sec.valid())
        return result;

    size_t start_addr = sec.get_hdr().addr;
    size_t end_addr = start_addr + sec.get_hdr().size;

    // The following can throw a type_mismatch exception in case
    // of corrupted symbol table in ELF.

    for (auto symbol: sym_sec.as_symtab()) {
        size_t value = symbol.get_data().value;
        // we assume that the start addr of each section is available in
        // code symbols.
        if ((start_addr <= value) && (value < end_addr)) {
            if (symbol.get_name() == ARMCodeSymbolVal::kThumb()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbolType::kThumb));

            } else if (symbol.get_name() == ARMCodeSymbolVal::kARM()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbolType::kARM));

            } else if (symbol.get_name() == ARMCodeSymbolVal::kData()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbolType::kData));

            }
        }
    }
    // Symbols are not necessary sorted, this step is required to
    // avoid potential SEGEV.
    std::sort(result.begin(), result.end());
    return result;
}

bool
ElfDisassembler::isSymbolTableAvailable() {
    elf::section sym_sec = m_elf_file->get_section(".symtab");
    // Returning a invalid section means that there was no symbol table
    //  provided in ELF file.

    return sym_sec.valid();
}

ISAType
ElfDisassembler::getInitialISAType() const {
    if (m_elf_file->get_hdr().entry & 1) return ISAType::kThumb;
    else return ISAType::kARM;
}

ISAInstWidth ElfDisassembler::getISAMinWidth(ISAType isa) const {
    switch (isa) {
        case ISAType::kx86:
        case ISAType::kx86_64:
            return ISAInstWidth::kByte;
        case ISAType::kThumb:
        case ISAType::kTriCore:
            return ISAInstWidth::kHWord;
        default:
            return ISAInstWidth::kWord;
    }
}
}
