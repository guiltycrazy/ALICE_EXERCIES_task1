import angr

# Create an Angr project for the specified binary
binary_path = "/home/poom/Desktop/Binary_Project/ALICE-exercise/bin/md5-O2"
p = angr.Project(binary_path, auto_load_libs=False)
cfg = p.analyses.CFGFast()

# Define constants to find
constants_to_find = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}

section_name = ".rodata"

# Get the section object for .rodata
rodata_section = p.loader.main_object.sections_map.get(section_name)

if rodata_section:
    # Load the content of .rodata section
    content = p.loader.memory.load(rodata_section.vaddr, rodata_section.memsize)

    # Disassemble and print the instructions in the .rodata section
    disassembly = p.arch.capstone.disasm(bytearray(content), rodata_section.vaddr)

    # Iterate through the disassembled instructions
    for func_addr, func_obj in cfg.functions.items():
        # Iterate through blocks in the function
        for block in func_obj.blocks:
            # Iterate through instructions in the block
            for insn in block.capstone.insns:
                # Check if the instruction contains "movdqa" or "lea"
                if "movdqa" in insn.mnemonic or "lea" in insn.mnemonic:
                    # Print the operand string
                    if "xmmword ptr" in f"{insn.op_str}":
                        print(f"{hex(insn.address)} (Memory Size: {insn.size} bytes):\t{insn.mnemonic}\t{insn.op_str}")
                        max_len = len(insn.op_str)
                        replace_address = "0x" + insn.op_str[25:max_len-2]
                        new_address = int(replace_address, 16)

                        # Calculate the result address
                        result_address = insn.address + new_address + insn.size

                        print(f"Constant found at address {hex(result_address)}")
                        print(f"Instruction address: {hex(insn.address)}")
