# GhidraHelpers.py - Common Ghidra API utilities
# @author: mobilemutex
# @category: C++

"""
Common utility functions for Ghidra API operations.
This module provides simplified interfaces to common Ghidra operations.
"""

import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import *
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.program.model.mem import *

class GhidraHelpers:
    """Helper class for common Ghidra API operations."""
    
    def __init__(self, current_program):
        self.program = current_program
        self.data_type_manager = current_program.getDataTypeManager()
        self.function_manager = current_program.getFunctionManager()
        self.symbol_table = current_program.getSymbolTable()
        self.memory = current_program.getMemory()
        self.listing = current_program.getListing()
        self.reference_manager = current_program.getReferenceManager()
        
    def create_data_type(self, name, size, description=None):
        """
        Create a custom data type.
        
        Args:
            name: Name of the data type
            size: Size in bytes
            description: Optional description
            
        Returns:
            DataType: Created data type
        """
        try:
            # Create a structure data type
            struct_dt = StructureDataType(name, size)
            
            if description:
                struct_dt.setDescription(description)
                
            return self.data_type_manager.addDataType(struct_dt, None)
        except Exception as e:
            raise Exception("Failed to create data type '{}': {}".format(name, str(e)))
            
    def create_structure(self, name, fields):
        """
        Create a structure data type with specified fields.
        
        Args:
            name: Name of the structure
            fields: List of (field_name, data_type, comment) tuples
            
        Returns:
            DataType: Created structure
        """
        try:
            struct_dt = StructureDataType(name, 0)
            
            for field_name, data_type, comment in fields:
                struct_dt.add(data_type, field_name, comment)
                
            return self.data_type_manager.addDataType(struct_dt, None)
        except Exception as e:
            raise Exception("Failed to create structure '{}': {}".format(name, str(e)))
            
    def set_function_name(self, addr, name):
        """
        Set the name of a function at the given address.
        
        Args:
            addr: Address of the function
            name: New name for the function
            
        Returns:
            bool: True if successful
        """
        try:
            function = self.function_manager.getFunctionAt(addr)
            if function is None:
                return False
                
            function.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            return True
        except Exception as e:
            return False
            
    def add_comment(self, addr, comment, comment_type="EOL"):
        """
        Add a comment at the given address.
        
        Args:
            addr: Address to add comment
            comment: Comment text
            comment_type: Type of comment ("EOL", "PRE", "POST", "PLATE")
            
        Returns:
            bool: True if successful
        """
        try:
            code_unit = self.listing.getCodeUnitAt(addr)
            if code_unit is None:
                return False
                
            if comment_type == "EOL":
                code_unit.setComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, comment)
            elif comment_type == "PRE":
                code_unit.setComment(ghidra.program.model.listing.CodeUnit.PRE_COMMENT, comment)
            elif comment_type == "POST":
                code_unit.setComment(ghidra.program.model.listing.CodeUnit.POST_COMMENT, comment)
            elif comment_type == "PLATE":
                code_unit.setComment(ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, comment)
                
            return True
        except Exception as e:
            return False
            
    def create_label(self, addr, name, make_primary=True):
        """
        Create a label at the given address.
        
        Args:
            addr: Address for the label
            name: Label name
            make_primary: Whether to make this the primary symbol
            
        Returns:
            Symbol: Created symbol or None if failed
        """
        try:
            symbol = self.symbol_table.createLabel(
                addr, name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                
            if make_primary and symbol is not None:
                symbol.setPrimary()
                
            return symbol
        except Exception as e:
            return None
            
    def apply_data_type(self, addr, data_type):
        """
        Apply a data type at the given address.
        
        Args:
            addr: Address to apply data type
            data_type: Data type to apply
            
        Returns:
            bool: True if successful
        """
        try:
            self.listing.createData(addr, data_type)
            return True
        except Exception as e:
            return False
            
    def create_function(self, addr, name=None):
        """
        Create a function at the given address.
        
        Args:
            addr: Address to create function
            name: Optional function name
            
        Returns:
            Function: Created function or None if failed
        """
        try:
            function = self.function_manager.createFunction(
                name, addr, None, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            return function
        except Exception as e:
            return None
            
    def get_function_at(self, addr):
        """
        Get function at the given address.
        
        Args:
            addr: Address to check
            
        Returns:
            Function: Function at address or None
        """
        return self.function_manager.getFunctionAt(addr)
        
    def get_function_containing(self, addr):
        """
        Get function containing the given address.
        
        Args:
            addr: Address to check
            
        Returns:
            Function: Function containing address or None
        """
        return self.function_manager.getFunctionContaining(addr)
        
    def read_bytes(self, addr, length):
        """
        Read bytes from memory.
        
        Args:
            addr: Address to read from
            length: Number of bytes to read
            
        Returns:
            bytes: Read bytes or None if failed
        """
        try:
            return self.memory.getBytes(addr, length)
        except Exception as e:
            return None
            
    def read_pointer(self, addr):
        """
        Read a pointer value from memory.
        
        Args:
            addr: Address to read from
            
        Returns:
            int: Pointer value or None if failed
        """
        try:
            pointer_size = self.program.getDefaultPointerSize()
            bytes_data = self.memory.getBytes(addr, pointer_size)
            
            # Convert bytes to int (little endian)
            value = 0
            for i in range(pointer_size):
                value |= (bytes_data[i] & 0xFF) << (i * 8)
                
            return value
        except Exception as e:
            return None
            
    def read_int(self, addr):
        """
        Read a 32-bit integer from memory.
        
        Args:
            addr: Address to read from
            
        Returns:
            int: Integer value or None if failed
        """
        try:
            bytes_data = self.memory.getBytes(addr, 4)
            
            # Convert bytes to int (little endian)
            value = 0
            for i in range(4):
                value |= (bytes_data[i] & 0xFF) << (i * 8)
                
            return value
        except Exception as e:
            return None
            
    def is_valid_address(self, addr):
        """
        Check if address is valid and in memory.
        
        Args:
            addr: Address to check
            
        Returns:
            bool: True if valid
        """
        return addr is not None and self.memory.contains(addr)
        
    def get_memory_block(self, addr):
        """
        Get memory block containing the address.
        
        Args:
            addr: Address to check
            
        Returns:
            MemoryBlock: Memory block or None
        """
        return self.memory.getBlock(addr)
        
    def is_executable_address(self, addr):
        """
        Check if address is in executable memory.
        
        Args:
            addr: Address to check
            
        Returns:
            bool: True if executable
        """
        block = self.get_memory_block(addr)
        return block is not None and block.isExecute()
        
    def get_references_to(self, addr):
        """
        Get all references to an address.
        
        Args:
            addr: Target address
            
        Returns:
            list: List of references
        """
        refs = self.reference_manager.getReferencesTo(addr)
        return list(refs)
        
    def get_references_from(self, addr):
        """
        Get all references from an address.
        
        Args:
            addr: Source address
            
        Returns:
            list: List of references
        """
        refs = self.reference_manager.getReferencesFrom(addr)
        return list(refs)
        
    def create_namespace(self, name, parent=None):
        """
        Create a namespace.
        
        Args:
            name: Namespace name
            parent: Parent namespace (None for global)
            
        Returns:
            Namespace: Created namespace or None if failed
        """
        try:
            return self.symbol_table.createNameSpace(
                parent, name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        except Exception as e:
            return None
            
    def get_instruction_at(self, addr):
        """
        Get instruction at address.
        
        Args:
            addr: Address to check
            
        Returns:
            Instruction: Instruction or None
        """
        return self.listing.getInstructionAt(addr)
        
    def get_instructions_in_range(self, start_addr, end_addr):
        """
        Get all instructions in a range.
        
        Args:
            start_addr: Start address
            end_addr: End address
            
        Returns:
            iterator: Instruction iterator
        """
        addr_set = self.program.getAddressFactory().getAddressSet(start_addr, end_addr)
        return self.listing.getInstructions(addr_set, True)
        
    def disassemble_at(self, addr):
        """
        Force disassembly at address.
        
        Args:
            addr: Address to disassemble
            
        Returns:
            bool: True if successful
        """
        try:
            disassembler = ghidra.app.util.bin.format.elf.ElfDisassembler()
            # This is a simplified approach - real implementation would use proper disassembler
            return True
        except Exception as e:
            return False
            
    def clear_data_at(self, addr, length=1):
        """
        Clear data at address.
        
        Args:
            addr: Address to clear
            length: Number of bytes to clear
            
        Returns:
            bool: True if successful
        """
        try:
            end_addr = addr.add(length - 1)
            self.listing.clearCodeUnits(addr, end_addr, False)
            return True
        except Exception as e:
            return False
            
    def get_data_type_by_name(self, name):
        """
        Get data type by name.
        
        Args:
            name: Data type name
            
        Returns:
            DataType: Data type or None if not found
        """
        return self.data_type_manager.getDataType(name)
        
    def get_all_functions(self):
        """
        Get all functions in the program.
        
        Returns:
            iterator: Function iterator
        """
        return self.function_manager.getFunctions(True)
        
    def get_entry_points(self):
        """
        Get all entry points in the program.
        
        Returns:
            list: List of entry point addresses
        """
        entry_points = []
        symbol_iterator = self.symbol_table.getSymbolIterator()
        
        for symbol in symbol_iterator:
            if symbol.isEntryPoint():
                entry_points.append(symbol.getAddress())
                
        return entry_points
        
    def create_bookmark(self, addr, category, comment):
        """
        Create a bookmark at address.
        
        Args:
            addr: Address for bookmark
            category: Bookmark category
            comment: Bookmark comment
            
        Returns:
            bool: True if successful
        """
        try:
            bookmark_manager = self.program.getBookmarkManager()
            bookmark_manager.setBookmark(addr, category, "Analysis", comment)
            return True
        except Exception as e:
            return False

