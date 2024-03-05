import angr

# Create an Angr project for the specified binary
binary_path = "/home/poom/Desktop/Binary_Project/ALICE-exercise/bin/md5-O2-s"
p = angr.Project(binary_path, auto_load_libs=False)

# Perform function analysis
cfg = p.analyses.CFGFast()

# Define constants to find
constants_to_find = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}

# List to store found constants
check_constants = []

# Iterate through sections to find .rodata
for section in p.loader.main_object.sections:
    if ".rodata" in section.name:
        content = p.loader.memory.load(section.vaddr, section.memsize)

        # Iterate through constants to find
        for constant in constants_to_find:
            # Check both little-endian and big-endian interpretations
            for endian in ['little', 'big']:
                try:
                    # Convert constant to bytes
                    constant_bytes = constant.to_bytes(4, byteorder=endian)

                    # Search for the constant in the content
                    offset = content.find(constant_bytes)

                    if offset != -1:
                        address = section.vaddr + offset
                        print(f"Constant {hex(constant)} found at address {hex(address)} (Endianness: {endian})")
                        check_constants.append(hex(address))
                        # Check if the address corresponds to a known function
                        for func_addr, func in cfg.kb.functions.items():
                            if func_addr <= address < func_addr + func.size:
                                function_name = func.name if func.name else f"Unnamed_{hex(func_addr)}"
                                print(f"Address: {hex(address)}, Constant: {hex(constant)}, Function: {function_name}")

                except ValueError as e:
                    # Print the exception
                    print(f"Error processing constant {hex(constant)}: {e}")

# Print the final list of found constants outside the loop
print("Final list of found constants:", check_constants)
