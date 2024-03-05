import angr

p = angr.Project("/home/poom/Desktop/Binary_Project/ALICE-exercise/bin/md5-O0-s", auto_load_libs=False)
cfg = p.analyses.CFGFast()

# List of constants to search for
target_constant = ["67452301", "efcdab89", "98badcfe", "10325476"]

# Iterate through functions in the CFG
for func_addr, func_obj in cfg.functions.items():
    # Iterate through blocks in the function
    for block in func_obj.blocks:
        # Iterate through instructions in the block
        for insn in block.capstone.insns:
            # Check if any of the constants are in the op_str
            for constant in target_constant:
                if constant in insn.op_str:
                    print("---------------------------------------------------------")
                    print(f"FOUND CONSTANT \"{constant}\"")
                    print(f"[{func_obj.name}] at {hex(block.addr)}")
                    print(f"{hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}")
                    print("---------------------------------------------------------")
