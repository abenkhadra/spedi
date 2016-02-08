#include "binutils/elf/elf++.hh"
#include "disasm/ElfDisassembler.h"
#include "disasm/ElfData.h"
#include <disasm/analysis/SectionDisassemblyAnalyzer.h>
#include <fcntl.h>
#include <util/cmdline.h>


struct ConfigConsts {
    const std::string kFile;
    const std::string kNoSymbols;
    const std::string kSpeculative;
    const std::string kText;

    ConfigConsts() : kFile{"file"},
                     kNoSymbols{"no-symbols"},
                     kSpeculative{"speculative"},
                     kText{"text"} { }
};

int main(int argc, char **argv) {
    ConfigConsts config;

    cmdline::parser cmd_parser;
    cmd_parser.add<std::string>(config.kFile,
                                'f',
                                "Path to an ARM ELF file to be disassembled",
                                true,
                                "");
    cmd_parser.add(config.kSpeculative, 's',
                   "Show all 'valid' disassembly");

    cmd_parser.add(config.kText, 't',
                   "Disassemble .text section only");

    cmd_parser.parse_check(argc, argv);

    auto file_path = cmd_parser.get<std::string>(config.kFile);

    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    elf::elf elf_file(elf::create_mmap_loader(fd));

    // We disassmble ARM/Thumb executables only
    if (static_cast<elf::ElfISA>(elf_file.get_hdr().machine)
        != elf::ElfISA::kARM) {
        fprintf(stderr, "%s : Elf file architecture is not ARM!\n", argv[1]);
        return 3;
    }

    disasm::ElfDisassembler disassembler{elf_file};
    if (cmd_parser.exist(config.kSpeculative)) {
        std::cout << "Speculative disassembly of file: "
            << file_path << "\n";
        if (cmd_parser.exist(config.kText)) {
            auto result =
                disassembler.disassembleSectionbyNameSpeculative(".text");
            disasm::SectionDisassemblyAnalyzer
                analyzer{&result, disassembler.getExecutableRegion()};
            analyzer.buildCFG();
            analyzer.refineCFG();
            // analyzer.buildCallGraph();
            disassembler.prettyPrintSectionCFG(&analyzer.getCFG());
        } else {
            disassembler.disassembleCodeSpeculative();
        }

    } else if (disassembler.isSymbolTableAvailable()) {
        std::cout << "Disassembly using symbol table of file: "
            << file_path << "\n";
        if (cmd_parser.exist(config.kText)) {
            auto result = disassembler.disassembleSectionbyName(".text");
            disassembler.prettyPrintSectionDisassembly(&result);
        } else
            disassembler.disassembleCodeUsingSymbols();
    } else
        std::cout << "Symbol table was not found!!" << "\n";

    return 0;
}
