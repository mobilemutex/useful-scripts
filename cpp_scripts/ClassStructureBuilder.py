# ClassStructureBuilder.py - Ghidra Script for C++ Class Structure Creation
# @author: mobilemutex
# @category: C++
# @keybinding: 
# @menupath: 
# @toolbar: 

"""
Ghidra script to create C++ class data structures and organize analysis results.
Creates class data types, organizes constructors and member functions, and establishes relationships.
"""

import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import *
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.program.model.mem import *
from ghidra.util.exception import CancelledException
from java.lang import Exception as JavaException

class ClassStructureBuilder(GhidraScript):
    
    def __init__(self):
        super(ClassStructureBuilder, self).__init__()
        self.class_info = {}
        self.data_type_manager = None
        self.function_manager = None
        self.symbol_table = None
        
    def run(self):
        """Main execution method for the script."""
        try:
            self.initialize()
            
            # Get class information from user or previous analysis
            class_data = self.gather_class_information()
            if not class_data:
                self.popup("No class information available. Run vtable and constructor analysis first.")
                return
                
            # Create class structures
            created_classes = []
            for class_info in class_data:
                class_struct = self.create_class_structure(class_info)
                if class_struct is not None:
                    created_classes.append(class_struct)
                    
            # Establish inheritance relationships
            self.establish_inheritance_relationships(created_classes)
            
            # Organize member functions
            self.organize_member_functions(created_classes)
            
            # Display results
            self.display_results(created_classes)
            
        except CancelledException:
            self.println("Script cancelled by user.")
        except Exception as e:
            self.popup("Error: {}".format(str(e)))
            
    def initialize(self):
        """Initialize script components."""
        self.data_type_manager = currentProgram.getDataTypeManager()
        self.function_manager = currentProgram.getFunctionManager()
        self.symbol_table = currentProgram.getSymbolTable()
        self.println("ClassStructureBuilder initialized successfully.")
        
    def gather_class_information(self):
        """Gather class information from previous analysis or user input."""
        class_data = []
        
        # Try to find existing vtable structures and constructor labels
        existing_data = self.find_existing_analysis_data()
        if existing_data:
            use_existing = askYesNo("Use Existing Data", 
                                  "Found {} existing class analyses. Use this data?".format(len(existing_data)))
            if use_existing:
                return existing_data
                
        # Manual input mode
        self.println("Manual class definition mode.")
        while True:
            class_info = self.get_class_info_from_user()
            if class_info is None:
                break
            class_data.append(class_info)
            
            continue_input = askYesNo("Continue", "Add another class?")
            if not continue_input:
                break
                
        return class_data
        
    def find_existing_analysis_data(self):
        """Find existing vtable and constructor analysis data."""
        existing_data = []
        
        # Look for vtable structures
        vtable_structures = self.find_vtable_structures()
        
        # Look for constructor functions
        constructor_functions = self.find_constructor_functions()
        
        # Combine into class information
        for vtable_info in vtable_structures:
            class_info = {
                'name': self.generate_class_name(vtable_info['address']),
                'vtable_address': vtable_info['address'],
                'vtable_functions': vtable_info['functions'],
                'constructors': [],
                'member_functions': [],
                'base_classes': [],
                'size_estimate': 0
            }
            
            # Find constructors for this vtable
            for ctor in constructor_functions:
                if ctor.get('vtable_address') == vtable_info['address']:
                    class_info['constructors'].append(ctor)
                    
            existing_data.append(class_info)
            
        return existing_data
        
    def find_vtable_structures(self):
        """Find existing vtable data structures."""
        vtables = []
        
        # Look for data types with "vtable" in the name
        data_types = self.data_type_manager.getAllDataTypes()
        for data_type in data_types:
            if "vtable" in data_type.getName().lower():
                # Try to find where this structure is applied
                vtable_info = self.analyze_vtable_structure(data_type)
                if vtable_info:
                    vtables.append(vtable_info)
                    
        return vtables
        
    def find_constructor_functions(self):
        """Find functions labeled as constructors."""
        constructors = []
        
        function_iterator = self.function_manager.getFunctions(True)
        for function in function_iterator:
            func_name = function.getName().lower()
            
            # Look for constructor-like names
            if any(pattern in func_name for pattern in [
                "constructor", "ctor", "_ctor", "__ctor"
            ]):
                ctor_info = {
                    'function': function,
                    'address': function.getEntryPoint(),
                    'name': function.getName(),
                    'vtable_address': self.extract_vtable_from_constructor(function)
                }
                constructors.append(ctor_info)
                
        return constructors
        
    def get_class_info_from_user(self):
        """Get class information from user input."""
        # Get class name
        class_name = askString("Class Name", "Enter class name:")
        if class_name is None or class_name.strip() == "":
            return None
            
        # Get vtable address
        vtable_str = askString("Vtable Address", "Enter vtable address (hex):")
        if vtable_str is None or vtable_str.strip() == "":
            return None
            
        try:
            if vtable_str.startswith("0x"):
                vtable_str = vtable_str[2:]
            vtable_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(long(vtable_str, 16))
        except:
            self.popup("Invalid vtable address: {}".format(vtable_str))
            return None
            
        # Get constructor addresses (optional)
        constructors = []
        while True:
            ctor_str = askString("Constructor Address", 
                               "Enter constructor address (hex) or 'done':")
            if ctor_str is None or ctor_str.strip().lower() == "done":
                break
                
            try:
                if ctor_str.startswith("0x"):
                    ctor_str = ctor_str[2:]
                ctor_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(long(ctor_str, 16))
                ctor_func = self.function_manager.getFunctionAt(ctor_addr)
                if ctor_func is not None:
                    constructors.append({
                        'function': ctor_func,
                        'address': ctor_addr,
                        'name': ctor_func.getName()
                    })
            except:
                self.popup("Invalid constructor address: {}".format(ctor_str))
                
        return {
            'name': class_name,
            'vtable_address': vtable_addr,
            'constructors': constructors,
            'member_functions': [],
            'base_classes': [],
            'size_estimate': 0
        }
        
    def create_class_structure(self, class_info):
        """Create a class data structure in Ghidra."""
        class_name = class_info['name']
        self.println("Creating class structure for: {}".format(class_name))
        
        try:
            # Create the main class structure
            class_struct = self.create_class_data_type(class_info)
            
            # Create vtable structure if not exists
            vtable_struct = self.create_vtable_data_type(class_info)
            
            # Apply structures to memory
            self.apply_class_structure(class_info, class_struct)
            self.apply_vtable_structure(class_info, vtable_struct)
            
            # Label constructors and member functions
            self.label_class_functions(class_info)
            
            # Create namespace for the class
            namespace = self.create_class_namespace(class_name)
            
            result = {
                'name': class_name,
                'class_struct': class_struct,
                'vtable_struct': vtable_struct,
                'namespace': namespace,
                'info': class_info
            }
            
            self.println("Successfully created class structure for {}".format(class_name))
            return result
            
        except Exception as e:
            self.println("Error creating class structure for {}: {}".format(class_name, str(e)))
            return None
            
    def create_class_data_type(self, class_info):
        """Create the main class data type."""
        class_name = class_info['name']
        
        # Create structure for the class
        class_struct = StructureDataType(class_name, 0)
        
        # Add vtable pointer as first member
        vtable_ptr_type = PointerDataType.dataType
        class_struct.add(vtable_ptr_type, "vftable", "Virtual function table pointer")
        
        # Estimate class size and add padding if needed
        estimated_size = self.estimate_class_size(class_info)
        if estimated_size > currentProgram.getDefaultPointerSize():
            remaining_size = estimated_size - currentProgram.getDefaultPointerSize()
            if remaining_size > 0:
                # Add undefined bytes for unknown members
                undefined_array = ArrayDataType(UndefinedDataType.dataType, remaining_size, 1)
                class_struct.add(undefined_array, "members", "Class member variables")
                
        # Add to data type manager
        return self.data_type_manager.addDataType(class_struct, None)
        
    def create_vtable_data_type(self, class_info):
        """Create vtable data type for the class."""
        vtable_name = "{}_vtable".format(class_info['name'])
        
        # Get vtable functions
        vtable_functions = self.get_vtable_functions(class_info['vtable_address'])
        
        # Create structure for vtable
        vtable_struct = StructureDataType(vtable_name, 0)
        
        # Add function pointers
        for i, func_addr in enumerate(vtable_functions):
            func_name = self.get_function_name(func_addr)
            field_name = "func_{}_{}".format(i, func_name)
            
            # Create function pointer type
            func_ptr_type = PointerDataType.dataType
            vtable_struct.add(func_ptr_type, field_name, 
                            "Virtual function pointer to {}".format(func_addr))
                            
        # Add to data type manager
        return self.data_type_manager.addDataType(vtable_struct, None)
        
    def apply_class_structure(self, class_info, class_struct):
        """Apply class structure to instances in memory."""
        # This would typically be applied where class instances are found
        # For now, we'll just create a label for the class type
        try:
            # Create a symbol for the class type
            class_symbol = self.symbol_table.createLabel(
                class_info['vtable_address'], 
                "{}_type".format(class_info['name']), 
                ghidra.program.model.symbol.SourceType.USER_DEFINED
            )
            
            # Add comment about the class
            comment = "Class: {} - vtable at {}".format(
                class_info['name'], class_info['vtable_address'])
            setEOLComment(class_info['vtable_address'], comment)
            
        except Exception as e:
            self.println("Warning: Could not apply class structure: {}".format(str(e)))
            
    def apply_vtable_structure(self, class_info, vtable_struct):
        """Apply vtable structure to the vtable address."""
        try:
            # Apply the vtable structure to the vtable address
            createData(class_info['vtable_address'], vtable_struct)
            
            # Create label for the vtable
            vtable_label = "{}_vtable".format(class_info['name'])
            createLabel(class_info['vtable_address'], vtable_label, True)
            
        except Exception as e:
            self.println("Warning: Could not apply vtable structure: {}".format(str(e)))
            
    def label_class_functions(self, class_info):
        """Label constructors and member functions."""
        class_name = class_info['name']
        
        # Label constructors
        for i, ctor in enumerate(class_info['constructors']):
            try:
                ctor_name = "{}::constructor_{}".format(class_name, i)
                ctor['function'].setName(ctor_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                
                # Add comment
                comment = "Constructor for class {}".format(class_name)
                ctor['function'].setComment(comment)
                
            except Exception as e:
                self.println("Warning: Could not label constructor {}: {}".format(ctor['address'], str(e)))
                
        # Label virtual functions
        vtable_functions = self.get_vtable_functions(class_info['vtable_address'])
        for i, func_addr in enumerate(vtable_functions):
            try:
                function = self.function_manager.getFunctionAt(func_addr)
                if function is not None:
                    func_name = "{}::virtual_func_{}".format(class_name, i)
                    function.setName(func_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                    
                    # Add comment
                    comment = "Virtual function {} for class {}".format(i, class_name)
                    function.setComment(comment)
                    
            except Exception as e:
                self.println("Warning: Could not label virtual function {}: {}".format(func_addr, str(e)))
                
    def create_class_namespace(self, class_name):
        """Create a namespace for the class."""
        try:
            # Create namespace for the class
            namespace = self.symbol_table.createNameSpace(
                None, class_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            return namespace
        except Exception as e:
            self.println("Warning: Could not create namespace for {}: {}".format(class_name, str(e)))
            return None
            
    def establish_inheritance_relationships(self, created_classes):
        """Establish inheritance relationships between classes."""
        self.println("Analyzing inheritance relationships...")
        
        for class_data in created_classes:
            class_info = class_data['info']
            
            # Analyze constructors for base class constructor calls
            for ctor in class_info['constructors']:
                base_classes = self.find_base_classes_from_constructor(ctor['function'], created_classes)
                class_info['base_classes'].extend(base_classes)
                
            # Update class structure with inheritance info
            if class_info['base_classes']:
                self.update_class_with_inheritance(class_data)
                
    def find_base_classes_from_constructor(self, constructor, all_classes):
        """Find base classes by analyzing constructor calls."""
        base_classes = []
        
        try:
            # Look for calls to other constructors
            listing = currentProgram.getListing()
            instructions = listing.getInstructions(constructor.getBody(), True)
            
            for instruction in instructions:
                if instruction.getFlowType().isCall():
                    flows = instruction.getFlows()
                    for flow_addr in flows:
                        # Check if this call is to another constructor
                        for other_class in all_classes:
                            for ctor in other_class['info']['constructors']:
                                if ctor['address'] == flow_addr:
                                    base_classes.append(other_class['name'])
                                    break
                                    
        except Exception as e:
            self.println("Warning: Error analyzing base classes: {}".format(str(e)))
            
        return base_classes
        
    def update_class_with_inheritance(self, class_data):
        """Update class structure to reflect inheritance."""
        try:
            class_info = class_data['info']
            self.println("Class {} inherits from: {}".format(
                class_info['name'], ", ".join(class_info['base_classes'])))
                
            # Add comment about inheritance
            comment = "Inherits from: {}".format(", ".join(class_info['base_classes']))
            setEOLComment(class_info['vtable_address'], comment)
            
        except Exception as e:
            self.println("Warning: Could not update inheritance info: {}".format(str(e)))
            
    def organize_member_functions(self, created_classes):
        """Organize and categorize member functions."""
        self.println("Organizing member functions...")
        
        for class_data in created_classes:
            class_info = class_data['info']
            
            # Get all virtual functions from vtable
            vtable_functions = self.get_vtable_functions(class_info['vtable_address'])
            
            # Categorize functions
            for i, func_addr in enumerate(vtable_functions):
                function = self.function_manager.getFunctionAt(func_addr)
                if function is not None:
                    func_category = self.categorize_member_function(function, i)
                    
                    # Update function name based on category
                    self.update_function_name_by_category(function, class_info['name'], func_category, i)
                    
    def categorize_member_function(self, function, vtable_index):
        """Categorize a member function based on its characteristics."""
        func_name = function.getName().lower()
        
        # Check for destructor patterns (usually first few entries)
        if vtable_index <= 1 and ("destructor" in func_name or "dtor" in func_name):
            return "destructor"
            
        # Check for common virtual function patterns
        if "get" in func_name or "set" in func_name:
            return "accessor"
        elif "run" in func_name or "execute" in func_name or "process" in func_name:
            return "action"
        elif "init" in func_name or "setup" in func_name:
            return "initialization"
        else:
            return "virtual_method"
            
    def update_function_name_by_category(self, function, class_name, category, index):
        """Update function name based on its category."""
        try:
            if category == "destructor":
                new_name = "{}::~{}".format(class_name, class_name)
            elif category == "accessor":
                new_name = "{}::accessor_{}".format(class_name, index)
            elif category == "action":
                new_name = "{}::action_{}".format(class_name, index)
            elif category == "initialization":
                new_name = "{}::init_{}".format(class_name, index)
            else:
                new_name = "{}::virtual_{}".format(class_name, index)
                
            function.setName(new_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            
        except Exception as e:
            self.println("Warning: Could not update function name: {}".format(str(e)))
            
    def get_vtable_functions(self, vtable_addr):
        """Get function addresses from a vtable."""
        functions = []
        
        try:
            current_addr = vtable_addr
            pointer_size = currentProgram.getDefaultPointerSize()
            
            # Skip potential header (offset_to_top, rtti_pointer)
            # Try to detect if this is Itanium ABI format
            try:
                first_val = getInt(current_addr) if pointer_size == 4 else getLong(current_addr)
                second_val = getInt(current_addr.add(pointer_size)) if pointer_size == 4 else getLong(current_addr.add(pointer_size))
                
                # If second value is 0 (RTTI pointer), skip header
                if second_val == 0:
                    current_addr = current_addr.add(pointer_size * 2)
            except:
                pass
                
            # Extract function pointers
            for i in range(100):  # Safety limit
                try:
                    if pointer_size == 4:
                        func_ptr = getInt(current_addr) & 0xFFFFFFFF
                    else:
                        func_ptr = getLong(current_addr)
                        
                    if func_ptr == 0:
                        break
                        
                    # Validate function pointer
                    addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()
                    func_addr = addr_space.getAddress(func_ptr)
                    
                    if self.is_valid_function_address(func_addr):
                        functions.append(func_addr)
                    else:
                        break
                        
                    current_addr = current_addr.add(pointer_size)
                    
                except:
                    break
                    
        except Exception as e:
            self.println("Warning: Error reading vtable functions: {}".format(str(e)))
            
        return functions
        
    def is_valid_function_address(self, addr):
        """Check if address points to a valid function."""
        try:
            memory = currentProgram.getMemory()
            if not memory.contains(addr):
                return False
                
            block = memory.getBlock(addr)
            return block is not None and block.isExecute()
        except:
            return False
            
    def get_function_name(self, func_addr):
        """Get a meaningful name for a function."""
        function = self.function_manager.getFunctionAt(func_addr)
        if function is not None:
            return function.getName()
            
        symbol = getSymbolAt(func_addr)
        if symbol is not None:
            return symbol.getName()
            
        return "func_{}".format(func_addr)
        
    def estimate_class_size(self, class_info):
        """Estimate the size of a class based on available information."""
        # Start with vtable pointer size
        size = currentProgram.getDefaultPointerSize()
        
        # Add estimated size based on constructor analysis
        # This is a simplified estimation - real implementation could be more sophisticated
        if class_info['constructors']:
            # Analyze constructor for member initialization patterns
            for ctor in class_info['constructors']:
                ctor_size = self.estimate_size_from_constructor(ctor['function'])
                size = max(size, ctor_size)
                
        return max(size, currentProgram.getDefaultPointerSize())
        
    def estimate_size_from_constructor(self, constructor):
        """Estimate class size from constructor analysis."""
        max_offset = currentProgram.getDefaultPointerSize()
        
        try:
            listing = currentProgram.getListing()
            instructions = listing.getInstructions(constructor.getBody(), True)
            
            for instruction in instructions:
                # Look for offset accesses that might indicate member variables
                inst_str = str(instruction)
                if '[' in inst_str and '+' in inst_str:
                    # Try to extract offset values
                    # This is a simplified pattern matching
                    import re
                    offset_matches = re.findall(r'\+0x([0-9a-fA-F]+)', inst_str)
                    for match in offset_matches:
                        try:
                            offset = int(match, 16)
                            max_offset = max(max_offset, offset + 4)  # Assume 4-byte members
                        except:
                            pass
                            
        except Exception as e:
            self.println("Warning: Error estimating size from constructor: {}".format(str(e)))
            
        return max_offset
        
    def analyze_vtable_structure(self, data_type):
        """Analyze an existing vtable data structure."""
        # This would analyze an existing vtable structure to extract information
        # Simplified implementation for now
        return None
        
    def extract_vtable_from_constructor(self, constructor):
        """Extract vtable address from constructor analysis."""
        # This would analyze the constructor to find which vtable it sets
        # Simplified implementation for now
        return None
        
    def display_results(self, created_classes):
        """Display class structure creation results."""
        self.println("\\n=== Class Structure Creation Results ===")
        self.println("Created {} class structures:\\n".format(len(created_classes)))
        
        for class_data in created_classes:
            class_info = class_data['info']
            self.println("Class: {}".format(class_info['name']))
            self.println("  Vtable: {}".format(class_info['vtable_address']))
            self.println("  Constructors: {}".format(len(class_info['constructors'])))
            self.println("  Base classes: {}".format(", ".join(class_info['base_classes']) if class_info['base_classes'] else "None"))
            self.println("  Virtual functions: {}".format(len(self.get_vtable_functions(class_info['vtable_address']))))
            self.println("")
            
        self.println("Class structures created successfully!")

# Create an instance and run if this script is executed directly
if __name__ == "__main__":
    builder = ClassStructureBuilder()
    builder.run()

