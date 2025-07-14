# ConstructorFinder.py - Ghidra Script for C++ Constructor Identification
# @author: AI Assistant
# @category: C++
# @keybinding: 
# @menupath: 
# @toolbar: 

"""
Ghidra script to identify C++ constructors based on vtable usage patterns.
Analyzes functions that set vtable pointers and identifies constructor patterns.
"""

import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import *
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.program.model.mem import *
from ghidra.program.model.pcode import *
from ghidra.util.exception import CancelledException
from java.lang import Exception as JavaException

class ConstructorFinder(GhidraScript):
    
    def __init__(self):
        super(ConstructorFinder, self).__init__()
        self.vtable_addresses = []
        self.constructor_candidates = []
        self.function_manager = None
        self.memory = None
        self.reference_manager = None
        
    def run(self):
        """Main execution method for the script."""
        try:
            self.initialize()
            
            # Get vtable addresses from user
            vtable_addrs = self.get_vtable_addresses()
            if not vtable_addrs:
                self.popup("No vtable addresses specified. Exiting.")
                return
                
            # Find constructor candidates for each vtable
            all_constructors = []
            for vtable_addr in vtable_addrs:
                constructors = self.find_constructors_for_vtable(vtable_addr)
                all_constructors.extend(constructors)
                
            if not all_constructors:
                self.popup("No constructor candidates found.")
                return
                
            # Analyze and rank constructor candidates
            ranked_constructors = self.analyze_constructor_candidates(all_constructors)
            
            # Display results and optionally apply findings
            self.display_results(ranked_constructors)
            self.apply_constructor_labels(ranked_constructors)
            
        except CancelledException:
            self.println("Script cancelled by user.")
        except Exception as e:
            self.popup("Error: {}".format(str(e)))
            
    def initialize(self):
        """Initialize script components."""
        self.function_manager = currentProgram.getFunctionManager()
        self.memory = currentProgram.getMemory()
        self.reference_manager = currentProgram.getReferenceManager()
        self.println("ConstructorFinder initialized successfully.")
        
    def get_vtable_addresses(self):
        """Get vtable addresses from user input."""
        addresses = []
        
        # Check if there's a current selection or address
        current_addr = currentAddress
        if current_addr is not None:
            use_current = askYesNo("Use Current Address", 
                                 "Use current address {} as vtable?".format(current_addr))
            if use_current:
                addresses.append(current_addr)
                return addresses
                
        # Ask for multiple vtable addresses
        while True:
            addr_str = askString("Vtable Address", 
                               "Enter vtable address (hex) or 'done' to finish:")
            if addr_str is None or addr_str.strip().lower() == "done":
                break
                
            try:
                if addr_str.startswith("0x"):
                    addr_str = addr_str[2:]
                addr_long = long(addr_str, 16)
                addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_long)
                addresses.append(addr)
                self.println("Added vtable address: {}".format(addr))
            except:
                self.popup("Invalid address format: {}".format(addr_str))
                
        return addresses
        
    def find_constructors_for_vtable(self, vtable_addr):
        """Find constructor candidates for a specific vtable."""
        self.println("Finding constructors for vtable at: {}".format(vtable_addr))
        
        constructors = []
        
        # Find all references to the vtable
        references = self.reference_manager.getReferencesTo(vtable_addr)
        
        for ref in references:
            from_addr = ref.getFromAddress()
            
            # Get the function containing this reference
            function = self.function_manager.getFunctionContaining(from_addr)
            if function is None:
                continue
                
            # Analyze this function for constructor patterns
            constructor_info = self.analyze_function_for_constructor_patterns(function, vtable_addr, from_addr)
            if constructor_info is not None:
                constructors.append(constructor_info)
                
        # Also look for dynamic allocation patterns (new + constructor)
        dynamic_constructors = self.find_dynamic_allocation_constructors(vtable_addr)
        constructors.extend(dynamic_constructors)
        
        self.println("Found {} constructor candidates for vtable {}".format(len(constructors), vtable_addr))
        return constructors
        
    def analyze_function_for_constructor_patterns(self, function, vtable_addr, ref_addr):
        """Analyze a function for constructor patterns."""
        func_addr = function.getEntryPoint()
        func_name = function.getName()
        
        # Initialize constructor info
        constructor_info = {
            'function': function,
            'address': func_addr,
            'name': func_name,
            'vtable_address': vtable_addr,
            'vtable_ref_address': ref_addr,
            'confidence': 0,
            'patterns': [],
            'type': 'unknown'
        }
        
        # Pattern 1: Check if vtable is set early in function
        vtable_set_early = self.check_vtable_set_early(function, vtable_addr, ref_addr)
        if vtable_set_early:
            constructor_info['confidence'] += 30
            constructor_info['patterns'].append('vtable_set_early')
            
        # Pattern 2: Check for 'this' pointer usage
        this_pointer_usage = self.check_this_pointer_usage(function)
        if this_pointer_usage:
            constructor_info['confidence'] += 20
            constructor_info['patterns'].append('this_pointer_usage')
            
        # Pattern 3: Check for base class constructor calls
        base_constructor_calls = self.find_base_constructor_calls(function)
        if base_constructor_calls:
            constructor_info['confidence'] += 25
            constructor_info['patterns'].append('base_constructor_calls')
            constructor_info['base_constructors'] = base_constructor_calls
            
        # Pattern 4: Check for member initialization patterns
        member_init = self.check_member_initialization(function)
        if member_init:
            constructor_info['confidence'] += 15
            constructor_info['patterns'].append('member_initialization')
            
        # Pattern 5: Check calling context (called after new, or on stack variables)
        calling_context = self.analyze_calling_context(function)
        if calling_context['after_new']:
            constructor_info['confidence'] += 35
            constructor_info['patterns'].append('called_after_new')
            constructor_info['type'] = 'dynamic'
        elif calling_context['stack_allocation']:
            constructor_info['confidence'] += 25
            constructor_info['patterns'].append('stack_allocation')
            constructor_info['type'] = 'local'
        elif calling_context['global_context']:
            constructor_info['confidence'] += 20
            constructor_info['patterns'].append('global_context')
            constructor_info['type'] = 'global'
            
        # Pattern 6: Check function name patterns
        name_patterns = self.check_function_name_patterns(func_name)
        if name_patterns:
            constructor_info['confidence'] += 10
            constructor_info['patterns'].append('name_pattern')
            
        # Only return if confidence is above threshold
        if constructor_info['confidence'] >= 20:
            return constructor_info
        else:
            return None
            
    def check_vtable_set_early(self, function, vtable_addr, ref_addr):
        """Check if vtable is set early in the function (constructor pattern)."""
        try:
            # Get function body
            func_body = function.getBody()
            func_start = function.getEntryPoint()
            
            # Calculate offset of vtable reference from function start
            offset = ref_addr.subtract(func_start)
            
            # If vtable is set within first 50 bytes, it's likely early
            return offset < 50
        except:
            return False
            
    def check_this_pointer_usage(self, function):
        """Check for typical 'this' pointer usage patterns."""
        try:
            # Look for ECX register usage (common 'this' pointer register in x86)
            # This is a simplified check - real implementation would need more sophisticated analysis
            
            # Get function instructions
            listing = currentProgram.getListing()
            instructions = listing.getInstructions(function.getBody(), True)
            
            ecx_usage_count = 0
            for instruction in instructions:
                mnemonic = instruction.getMnemonicString()
                # Look for instructions that use ECX register
                if "ecx" in str(instruction).lower():
                    ecx_usage_count += 1
                    
            # If ECX is used multiple times, likely 'this' pointer usage
            return ecx_usage_count >= 3
        except:
            return False
            
    def find_base_constructor_calls(self, function):
        """Find calls to other constructors (base class constructors)."""
        base_calls = []
        
        try:
            # Get all function calls within this function
            listing = currentProgram.getListing()
            instructions = listing.getInstructions(function.getBody(), True)
            
            for instruction in instructions:
                if instruction.getFlowType().isCall():
                    # Get the called address
                    flows = instruction.getFlows()
                    for flow_addr in flows:
                        called_function = self.function_manager.getFunctionAt(flow_addr)
                        if called_function is not None:
                            # Check if this could be another constructor
                            if self.could_be_constructor(called_function):
                                base_calls.append(called_function)
                                
        except:
            pass
            
        return base_calls
        
    def could_be_constructor(self, function):
        """Quick heuristic to check if a function could be a constructor."""
        # This is a simplified check - could be enhanced with more sophisticated analysis
        func_name = function.getName().lower()
        
        # Check for constructor-like names
        if "ctor" in func_name or "constructor" in func_name:
            return True
            
        # Check if function sets vtable pointers (simplified check)
        # In a real implementation, this would analyze the function body
        return False
        
    def check_member_initialization(self, function):
        """Check for member variable initialization patterns."""
        try:
            # Look for patterns of writing to offsets from 'this' pointer
            # This is a simplified implementation
            listing = currentProgram.getListing()
            instructions = listing.getInstructions(function.getBody(), True)
            
            offset_writes = 0
            for instruction in instructions:
                # Look for MOV instructions with offset addressing
                if instruction.getMnemonicString().upper() == "MOV":
                    operands = instruction.getOpObjects(0)  # Get destination operand
                    if len(operands) > 0:
                        # Check if it's writing to an offset (simplified check)
                        if "[" in str(instruction) and "+" in str(instruction):
                            offset_writes += 1
                            
            return offset_writes >= 2
        except:
            return False
            
    def analyze_calling_context(self, function):
        """Analyze how and where this function is called."""
        context = {
            'after_new': False,
            'stack_allocation': False,
            'global_context': False
        }
        
        try:
            # Get all references to this function
            func_addr = function.getEntryPoint()
            references = self.reference_manager.getReferencesTo(func_addr)
            
            for ref in references:
                calling_addr = ref.getFromAddress()
                calling_function = self.function_manager.getFunctionContaining(calling_addr)
                
                if calling_function is not None:
                    # Check if called after 'new' operator
                    if self.is_called_after_new(calling_function, calling_addr):
                        context['after_new'] = True
                        
                    # Check if called in stack allocation context
                    if self.is_stack_allocation_context(calling_function, calling_addr):
                        context['stack_allocation'] = True
                        
                else:
                    # Called outside of any function - might be global initialization
                    context['global_context'] = True
                    
        except:
            pass
            
        return context
        
    def is_called_after_new(self, calling_function, call_addr):
        """Check if function is called shortly after a 'new' operator call."""
        try:
            # Look backwards from call address for 'new' operator calls
            listing = currentProgram.getListing()
            
            # Check previous 20 instructions
            current_addr = call_addr
            for i in range(20):
                current_addr = current_addr.previous()
                if current_addr is None:
                    break
                    
                instruction = listing.getInstructionAt(current_addr)
                if instruction is not None and instruction.getFlowType().isCall():
                    # Check if this is a call to operator new
                    flows = instruction.getFlows()
                    for flow_addr in flows:
                        called_function = self.function_manager.getFunctionAt(flow_addr)
                        if called_function is not None:
                            func_name = called_function.getName().lower()
                            if "new" in func_name or "malloc" in func_name:
                                return True
                                
        except:
            pass
            
        return False
        
    def is_stack_allocation_context(self, calling_function, call_addr):
        """Check if function is called in a stack allocation context."""
        try:
            # Look for LEA instructions that load stack addresses before the call
            listing = currentProgram.getListing()
            
            current_addr = call_addr
            for i in range(10):
                current_addr = current_addr.previous()
                if current_addr is None:
                    break
                    
                instruction = listing.getInstructionAt(current_addr)
                if instruction is not None:
                    mnemonic = instruction.getMnemonicString().upper()
                    if mnemonic == "LEA":
                        # Check if LEA is loading a stack address (contains EBP or ESP)
                        if "ebp" in str(instruction).lower() or "esp" in str(instruction).lower():
                            return True
                            
        except:
            pass
            
        return False
        
    def check_function_name_patterns(self, func_name):
        """Check if function name suggests it's a constructor."""
        name_lower = func_name.lower()
        
        # Common constructor name patterns
        constructor_patterns = [
            "ctor", "constructor", "_ctor", "__ctor",
            "init", "_init", "__init"
        ]
        
        for pattern in constructor_patterns:
            if pattern in name_lower:
                return True
                
        return False
        
    def find_dynamic_allocation_constructors(self, vtable_addr):
        """Find constructors called after dynamic allocation (new operator)."""
        constructors = []
        
        try:
            # Find all calls to operator new
            new_functions = self.find_new_operator_functions()
            
            for new_func in new_functions:
                # Find references to this new function
                new_addr = new_func.getEntryPoint()
                references = self.reference_manager.getReferencesTo(new_addr)
                
                for ref in references:
                    calling_addr = ref.getFromAddress()
                    # Look for constructor calls after this new call
                    constructor = self.find_constructor_after_new(calling_addr, vtable_addr)
                    if constructor is not None:
                        constructors.append(constructor)
                        
        except:
            pass
            
        return constructors
        
    def find_new_operator_functions(self):
        """Find operator new functions in the program."""
        new_functions = []
        
        # Look for functions with 'new' in their name
        function_iterator = self.function_manager.getFunctions(True)
        for function in function_iterator:
            func_name = function.getName().lower()
            if "new" in func_name and ("operator" in func_name or "@@ya" in func_name):
                new_functions.append(function)
                
        return new_functions
        
    def find_constructor_after_new(self, new_call_addr, vtable_addr):
        """Find constructor call that follows a new operator call."""
        try:
            listing = currentProgram.getListing()
            
            # Look forward from new call for constructor call
            current_addr = new_call_addr
            for i in range(20):  # Look ahead 20 instructions
                current_addr = current_addr.next()
                if current_addr is None:
                    break
                    
                instruction = listing.getInstructionAt(current_addr)
                if instruction is not None and instruction.getFlowType().isCall():
                    flows = instruction.getFlows()
                    for flow_addr in flows:
                        called_function = self.function_manager.getFunctionAt(flow_addr)
                        if called_function is not None:
                            # Check if this function references our vtable
                            if self.function_references_vtable(called_function, vtable_addr):
                                return {
                                    'function': called_function,
                                    'address': flow_addr,
                                    'name': called_function.getName(),
                                    'vtable_address': vtable_addr,
                                    'confidence': 40,  # High confidence for new+constructor pattern
                                    'patterns': ['called_after_new'],
                                    'type': 'dynamic'
                                }
                                
        except:
            pass
            
        return None
        
    def function_references_vtable(self, function, vtable_addr):
        """Check if a function references a specific vtable."""
        references = self.reference_manager.getReferencesTo(vtable_addr)
        func_body = function.getBody()
        
        for ref in references:
            if func_body.contains(ref.getFromAddress()):
                return True
                
        return False
        
    def analyze_constructor_candidates(self, candidates):
        """Analyze and rank constructor candidates."""
        # Sort by confidence score
        ranked = sorted(candidates, key=lambda x: x['confidence'], reverse=True)
        
        # Additional analysis could be added here
        # - Remove duplicates
        # - Cross-reference with other analysis
        # - Apply additional heuristics
        
        return ranked
        
    def display_results(self, constructors):
        """Display constructor analysis results."""
        self.println("\\n=== Constructor Analysis Results ===")
        self.println("Found {} constructor candidates:\\n".format(len(constructors)))
        
        for i, ctor in enumerate(constructors):
            self.println("{}. {} (Confidence: {})".format(i+1, ctor['name'], ctor['confidence']))
            self.println("   Address: {}".format(ctor['address']))
            self.println("   Vtable: {}".format(ctor['vtable_address']))
            self.println("   Type: {}".format(ctor['type']))
            self.println("   Patterns: {}".format(", ".join(ctor['patterns'])))
            if 'base_constructors' in ctor:
                self.println("   Base constructors: {}".format(len(ctor['base_constructors'])))
            self.println("")
            
    def apply_constructor_labels(self, constructors):
        """Apply constructor labels to identified functions."""
        if not constructors:
            return
            
        apply_labels = askYesNo("Apply Labels", 
                              "Apply constructor labels to {} identified functions?".format(len(constructors)))
        if not apply_labels:
            return
            
        for ctor in constructors:
            if ctor['confidence'] >= 30:  # Only label high-confidence constructors
                try:
                    # Create a meaningful constructor name
                    vtable_name = "vtable_{}".format(ctor['vtable_address']).replace(":", "_")
                    class_name = vtable_name.replace("vtable_", "Class_")
                    ctor_name = "{}_constructor".format(class_name)
                    
                    # Set function name
                    function = ctor['function']
                    function.setName(ctor_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                    
                    # Add comment
                    comment = "Constructor for {} (Confidence: {}, Patterns: {})".format(
                        class_name, ctor['confidence'], ", ".join(ctor['patterns']))
                    function.setComment(comment)
                    
                    self.println("Labeled {} as {}".format(ctor['address'], ctor_name))
                    
                except Exception as e:
                    self.println("Error labeling {}: {}".format(ctor['address'], str(e)))

# Create an instance and run if this script is executed directly
if __name__ == "__main__":
    finder = ConstructorFinder()
    finder.run()

