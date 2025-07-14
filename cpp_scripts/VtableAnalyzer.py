# VtableAnalyzer.py - Ghidra Script for C++ Vtable Analysis
# @author: AI Assistant
# @category: C++
# @keybinding: 
# @menupath: 
# @toolbar: 

"""
Ghidra script to analyze C++ virtual function tables (vtables) in binaries without RTTI.
Allows users to specify vtable addresses and extracts function information.
"""

import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import *
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.program.model.mem import *
from ghidra.util.exception import CancelledException
from java.lang import Exception as JavaException

class VtableAnalyzer(GhidraScript):
    
    def __init__(self):
        super(VtableAnalyzer, self).__init__()
        self.vtable_info = {}
        self.function_manager = None
        self.data_type_manager = None
        self.memory = None
        
    def run(self):
        """Main execution method for the script."""
        try:
            self.initialize()
            
            # Get vtable address from user
            vtable_addr = self.get_vtable_address()
            if vtable_addr is None:
                self.popup("No vtable address specified. Exiting.")
                return
                
            # Analyze the vtable
            vtable_data = self.analyze_vtable(vtable_addr)
            if vtable_data is None:
                self.popup("Failed to analyze vtable at address: {}".format(vtable_addr))
                return
                
            # Create vtable structure in Ghidra
            self.create_vtable_structure(vtable_addr, vtable_data)
            
            # Display results
            self.display_results(vtable_addr, vtable_data)
            
        except CancelledException:
            self.println("Script cancelled by user.")
        except Exception as e:
            self.popup("Error: {}".format(str(e)))
            
    def initialize(self):
        """Initialize script components."""
        self.function_manager = currentProgram.getFunctionManager()
        self.data_type_manager = currentProgram.getDataTypeManager()
        self.memory = currentProgram.getMemory()
        self.println("VtableAnalyzer initialized successfully.")
        
    def get_vtable_address(self):
        """Get vtable address from user input or current selection."""
        # Try to get address from current cursor position
        current_addr = currentAddress
        if current_addr is not None:
            use_current = askYesNo("Use Current Address", 
                                 "Use current address {} as vtable?".format(current_addr))
            if use_current:
                return current_addr
                
        # Ask user for vtable address
        addr_str = askString("Vtable Address", "Enter vtable address (hex):")
        if addr_str is None or addr_str.strip() == "":
            return None
            
        try:
            # Parse address string
            if addr_str.startswith("0x"):
                addr_str = addr_str[2:]
            addr_long = long(addr_str, 16)
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_long)
        except:
            self.popup("Invalid address format: {}".format(addr_str))
            return None
            
    def analyze_vtable(self, vtable_addr):
        """Analyze vtable structure and extract function information."""
        self.println("Analyzing vtable at address: {}".format(vtable_addr))
        
        # Validate vtable address
        if not self.validate_vtable_address(vtable_addr):
            return None
            
        vtable_data = {
            'address': vtable_addr,
            'functions': [],
            'size': 0,
            'offset_to_top': 0,
            'rtti_pointer': None,
            'is_primary': True
        }
        
        # Check for Itanium ABI structure (offset_to_top, rtti_pointer, functions...)
        current_addr = vtable_addr
        
        # Read offset_to_top (may be 0 for primary vtables)
        try:
            offset_to_top = self.read_signed_int(current_addr)
            vtable_data['offset_to_top'] = offset_to_top
            current_addr = current_addr.add(self.get_pointer_size())
            
            # Read RTTI pointer (should be 0 if RTTI disabled)
            rtti_ptr = self.read_pointer(current_addr)
            vtable_data['rtti_pointer'] = rtti_ptr
            current_addr = current_addr.add(self.get_pointer_size())
            
            # If RTTI pointer is not 0, this might not be a vtable without RTTI
            if rtti_ptr != 0:
                self.println("Warning: RTTI pointer is not zero. This might be a vtable with RTTI.")
                
        except:
            # If we can't read the header, assume it's a simple function pointer array
            current_addr = vtable_addr
            
        # Extract function pointers
        function_count = 0
        while True:
            try:
                func_ptr = self.read_pointer(current_addr)
                
                # Check if this looks like a valid function pointer
                if not self.is_valid_function_pointer(func_ptr):
                    break
                    
                vtable_data['functions'].append({
                    'address': func_ptr,
                    'offset': function_count * self.get_pointer_size(),
                    'name': self.get_function_name(func_ptr)
                })
                
                function_count += 1
                current_addr = current_addr.add(self.get_pointer_size())
                
                # Safety check to prevent infinite loops
                if function_count > 100:
                    self.println("Warning: Vtable seems unusually large (>100 functions). Stopping analysis.")
                    break
                    
            except:
                break
                
        vtable_data['size'] = function_count * self.get_pointer_size()
        
        if function_count == 0:
            self.println("No valid function pointers found in vtable.")
            return None
            
        self.println("Found {} function pointers in vtable.".format(function_count))
        return vtable_data
        
    def validate_vtable_address(self, addr):
        """Validate that the address could contain a vtable."""
        if addr is None:
            return False
            
        # Check if address is in a readable memory block
        if not self.memory.contains(addr):
            self.popup("Address {} is not in program memory.".format(addr))
            return False
            
        # Check if address is properly aligned
        pointer_size = self.get_pointer_size()
        if addr.getOffset() % pointer_size != 0:
            self.popup("Address {} is not properly aligned for pointer size {}.".format(addr, pointer_size))
            return False
            
        # Check if we can read at least one pointer from this address
        try:
            self.read_pointer(addr)
            return True
        except:
            self.popup("Cannot read data from address {}.".format(addr))
            return False
            
    def read_pointer(self, addr):
        """Read a pointer value from the given address."""
        pointer_size = self.get_pointer_size()
        if pointer_size == 4:
            return getInt(addr) & 0xFFFFFFFF
        elif pointer_size == 8:
            return getLong(addr)
        else:
            raise Exception("Unsupported pointer size: {}".format(pointer_size))
            
    def read_signed_int(self, addr):
        """Read a signed 32-bit integer from the given address."""
        value = getInt(addr)
        # Convert to signed
        if value > 0x7FFFFFFF:
            value = value - 0x100000000
        return value
        
    def get_pointer_size(self):
        """Get the pointer size for the current program."""
        return currentProgram.getDefaultPointerSize()
        
    def is_valid_function_pointer(self, ptr_value):
        """Check if a pointer value could be a valid function pointer."""
        if ptr_value == 0:
            return False
            
        try:
            # Convert to address
            addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
            func_addr = addr_space.getAddress(ptr_value)
            
            # Check if address is in program memory
            if not self.memory.contains(func_addr):
                return False
                
            # Check if there's executable code at this address
            memory_block = self.memory.getBlock(func_addr)
            if memory_block is None or not memory_block.isExecute():
                return False
                
            return True
            
        except:
            return False
            
    def get_function_name(self, func_addr_value):
        """Get the name of a function at the given address."""
        try:
            addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
            func_addr = addr_space.getAddress(func_addr_value)
            
            # Check if there's already a function defined here
            function = self.function_manager.getFunctionAt(func_addr)
            if function is not None:
                return function.getName()
                
            # Check for symbols
            symbol = getSymbolAt(func_addr)
            if symbol is not None:
                return symbol.getName()
                
            # Return address as string if no name found
            return "func_{}".format(func_addr)
            
        except:
            return "func_{:x}".format(func_addr_value)
            
    def create_vtable_structure(self, vtable_addr, vtable_data):
        """Create vtable data structure in Ghidra."""
        try:
            # Create a structure for the vtable
            vtable_name = "vtable_{}".format(vtable_addr).replace(":", "_")
            
            # Create structure data type
            struct_dt = StructureDataType(vtable_name, 0)
            
            # Add offset_to_top and rtti_pointer if present
            if vtable_data['offset_to_top'] != 0 or vtable_data['rtti_pointer'] is not None:
                struct_dt.add(IntegerDataType.dataType, "offset_to_top", "Offset to top of object")
                struct_dt.add(PointerDataType.dataType, "rtti_pointer", "RTTI pointer (should be 0)")
                
            # Add function pointers
            for i, func_info in enumerate(vtable_data['functions']):
                field_name = "func_{}".format(i)
                if func_info['name'] != "func_{}".format(func_info['address']):
                    field_name = func_info['name']
                struct_dt.add(PointerDataType.dataType, field_name, "Virtual function pointer")
                
            # Add the structure to the data type manager
            final_struct = self.data_type_manager.addDataType(struct_dt, None)
            
            # Apply the structure to the vtable address
            createData(vtable_addr, final_struct)
            
            # Set a label for the vtable
            createLabel(vtable_addr, vtable_name, True)
            
            self.println("Created vtable structure '{}' at address {}".format(vtable_name, vtable_addr))
            
        except Exception as e:
            self.println("Error creating vtable structure: {}".format(str(e)))
            
    def display_results(self, vtable_addr, vtable_data):
        """Display analysis results to the user."""
        self.println("\\n=== Vtable Analysis Results ===")
        self.println("Vtable Address: {}".format(vtable_addr))
        self.println("Vtable Size: {} bytes ({} function pointers)".format(
            vtable_data['size'], len(vtable_data['functions'])))
        self.println("Offset to Top: {}".format(vtable_data['offset_to_top']))
        self.println("RTTI Pointer: {}".format(vtable_data['rtti_pointer']))
        
        self.println("\\nFunction Pointers:")
        for i, func_info in enumerate(vtable_data['functions']):
            self.println("  [{}] {} - {}".format(i, func_info['address'], func_info['name']))
            
        self.println("\\nVtable structure created successfully!")

# Create an instance and run if this script is executed directly
if __name__ == "__main__":
    analyzer = VtableAnalyzer()
    analyzer.run()

