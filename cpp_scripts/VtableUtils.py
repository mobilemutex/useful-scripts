# VtableUtils.py - Utility functions for C++ Vtable Analysis
# @author: AI Assistant
# @category: C++

"""
Utility functions for C++ vtable analysis in Ghidra scripts.
This module provides common functionality for vtable detection and analysis.
"""

import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import *
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.program.model.mem import *

class VtableUtils:
    """Utility class for vtable analysis operations."""
    
    def __init__(self, current_program):
        self.program = current_program
        self.memory = current_program.getMemory()
        self.function_manager = current_program.getFunctionManager()
        self.pointer_size = current_program.getDefaultPointerSize()
        
    def validate_vtable_address(self, addr):
        """
        Check if address contains a valid vtable.
        
        Args:
            addr: Address to check
            
        Returns:
            bool: True if address appears to contain a vtable
        """
        if addr is None:
            return False
            
        # Check if address is in readable memory
        if not self.memory.contains(addr):
            return False
            
        # Check alignment
        if addr.getOffset() % self.pointer_size != 0:
            return False
            
        # Check if we can read at least 2 consecutive function pointers
        try:
            ptr1 = self._read_pointer(addr)
            ptr2 = self._read_pointer(addr.add(self.pointer_size))
            
            return (self._is_valid_function_pointer(ptr1) and 
                   self._is_valid_function_pointer(ptr2))
        except:
            return False
            
    def extract_function_pointers(self, vtable_addr, max_size=None):
        """
        Extract function pointers from a vtable.
        
        Args:
            vtable_addr: Starting address of vtable
            max_size: Maximum number of pointers to extract (None for auto-detect)
            
        Returns:
            list: List of function addresses
        """
        functions = []
        current_addr = vtable_addr
        count = 0
        
        while True:
            if max_size is not None and count >= max_size:
                break
                
            try:
                func_ptr = self._read_pointer(current_addr)
                
                if not self._is_valid_function_pointer(func_ptr):
                    break
                    
                addr_space = self.program.getAddressFactory().getDefaultAddressSpace()
                func_addr = addr_space.getAddress(func_ptr)
                functions.append(func_addr)
                
                count += 1
                current_addr = current_addr.add(self.pointer_size)
                
                # Safety limit
                if count > 200:
                    break
                    
            except:
                break
                
        return functions
        
    def detect_vtable_group(self, addr):
        """
        Find related vtables for multiple inheritance (vtable groups).
        
        Args:
            addr: Address of a vtable in the group
            
        Returns:
            list: List of vtable addresses in the group
        """
        vtables = []
        
        # Start from the given address and look backwards for the primary vtable
        current_addr = addr
        
        # Look backwards to find the start of the vtable group
        while True:
            # Check if previous location could be another vtable
            prev_addr = current_addr.subtract(self.pointer_size * 3)  # Minimum vtable size
            if not self._could_be_vtable_start(prev_addr):
                break
            current_addr = prev_addr
            
        # Now scan forward to find all vtables in the group
        while True:
            if self.validate_vtable_address(current_addr):
                vtable_info = self._analyze_vtable_header(current_addr)
                if vtable_info is not None:
                    vtables.append({
                        'address': current_addr,
                        'offset_to_top': vtable_info['offset_to_top'],
                        'is_primary': vtable_info['offset_to_top'] == 0
                    })
                    
                    # Move to next potential vtable
                    vtable_size = self._estimate_vtable_size(current_addr)
                    current_addr = current_addr.add(vtable_size)
                else:
                    break
            else:
                break
                
        return vtables
        
    def get_vtable_size(self, addr):
        """
        Determine the size of a vtable.
        
        Args:
            addr: Vtable address
            
        Returns:
            int: Size in bytes
        """
        return self._estimate_vtable_size(addr)
        
    def find_vtable_references(self, vtable_addr):
        """
        Find all references to a vtable address.
        
        Args:
            vtable_addr: Vtable address to search for
            
        Returns:
            list: List of addresses that reference the vtable
        """
        references = []
        
        # Get all references to this address
        ref_manager = self.program.getReferenceManager()
        refs = ref_manager.getReferencesTo(vtable_addr)
        
        for ref in refs:
            from_addr = ref.getFromAddress()
            references.append(from_addr)
            
        return references
        
    def _read_pointer(self, addr):
        """Read a pointer value from memory."""
        if self.pointer_size == 4:
            bytes_data = self.memory.getBytes(addr, 4)
            # Convert bytes to int (little endian)
            value = 0
            for i in range(4):
                value |= (bytes_data[i] & 0xFF) << (i * 8)
            return value & 0xFFFFFFFF
        elif self.pointer_size == 8:
            bytes_data = self.memory.getBytes(addr, 8)
            # Convert bytes to long (little endian)
            value = 0
            for i in range(8):
                value |= (bytes_data[i] & 0xFF) << (i * 8)
            return value
        else:
            raise Exception("Unsupported pointer size: {}".format(self.pointer_size))
            
    def _read_signed_int(self, addr):
        """Read a signed 32-bit integer from memory."""
        bytes_data = self.memory.getBytes(addr, 4)
        value = 0
        for i in range(4):
            value |= (bytes_data[i] & 0xFF) << (i * 8)
        # Convert to signed
        if value > 0x7FFFFFFF:
            value = value - 0x100000000
        return value
        
    def _is_valid_function_pointer(self, ptr_value):
        """Check if a value could be a valid function pointer."""
        if ptr_value == 0:
            return False
            
        try:
            addr_space = self.program.getAddressFactory().getDefaultAddressSpace()
            func_addr = addr_space.getAddress(ptr_value)
            
            if not self.memory.contains(func_addr):
                return False
                
            memory_block = self.memory.getBlock(func_addr)
            if memory_block is None or not memory_block.isExecute():
                return False
                
            return True
        except:
            return False
            
    def _could_be_vtable_start(self, addr):
        """Check if address could be the start of a vtable."""
        try:
            # Check if we can read vtable header
            offset_to_top = self._read_signed_int(addr)
            rtti_ptr = self._read_pointer(addr.add(4))
            
            # For vtables without RTTI, RTTI pointer should be 0
            # Offset to top should be reasonable (not too large)
            return (rtti_ptr == 0 and abs(offset_to_top) < 0x10000)
        except:
            return False
            
    def _analyze_vtable_header(self, addr):
        """Analyze vtable header (Itanium ABI format)."""
        try:
            offset_to_top = self._read_signed_int(addr)
            rtti_ptr = self._read_pointer(addr.add(4))
            
            return {
                'offset_to_top': offset_to_top,
                'rtti_pointer': rtti_ptr,
                'functions_start': addr.add(8)
            }
        except:
            return None
            
    def _estimate_vtable_size(self, addr):
        """Estimate the size of a vtable by counting function pointers."""
        # Skip header if present
        current_addr = addr
        
        # Check if this looks like Itanium ABI format
        try:
            offset_to_top = self._read_signed_int(current_addr)
            rtti_ptr = self._read_pointer(current_addr.add(4))
            if rtti_ptr == 0:  # Likely Itanium format without RTTI
                current_addr = current_addr.add(8)  # Skip header
        except:
            pass
            
        # Count function pointers
        count = 0
        while True:
            try:
                func_ptr = self._read_pointer(current_addr)
                if not self._is_valid_function_pointer(func_ptr):
                    break
                count += 1
                current_addr = current_addr.add(self.pointer_size)
                
                if count > 200:  # Safety limit
                    break
            except:
                break
                
        # Return total size including header
        header_size = 8 if current_addr != addr else 0
        return header_size + (count * self.pointer_size)
        
    def get_function_name_at_address(self, func_addr):
        """Get the name of a function at the given address."""
        function = self.function_manager.getFunctionAt(func_addr)
        if function is not None:
            return function.getName()
            
        # Check for symbols
        symbol_table = self.program.getSymbolTable()
        symbol = symbol_table.getPrimarySymbol(func_addr)
        if symbol is not None:
            return symbol.getName()
            
        return "func_{}".format(func_addr)
        
    def create_vtable_data_type(self, name, function_addresses):
        """Create a data type for a vtable structure."""
        data_type_manager = self.program.getDataTypeManager()
        
        struct_dt = StructureDataType(name, 0)
        
        # Add function pointers
        for i, func_addr in enumerate(function_addresses):
            field_name = "func_{}".format(i)
            func_name = self.get_function_name_at_address(func_addr)
            if func_name != "func_{}".format(func_addr):
                field_name = func_name
                
            struct_dt.add(PointerDataType.dataType, field_name, 
                         "Virtual function pointer to {}".format(func_addr))
                         
        return data_type_manager.addDataType(struct_dt, None)

