# ConstructorUtils.py - Utility functions for C++ Constructor Analysis
# @author: mobilemutex
# @category: C++

"""
Utility functions for C++ constructor identification in Ghidra scripts.
This module provides common functionality for constructor pattern detection.
"""

import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import *
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.program.model.mem import *

class ConstructorUtils:
    """Utility class for constructor analysis operations."""
    
    def __init__(self, current_program):
        self.program = current_program
        self.memory = current_program.getMemory()
        self.function_manager = current_program.getFunctionManager()
        self.reference_manager = current_program.getReferenceManager()
        self.listing = current_program.getListing()
        self.pointer_size = current_program.getDefaultPointerSize()
        
    def find_vtable_references(self, vtable_addr):
        """
        Find all code references to a vtable address.
        
        Args:
            vtable_addr: Address of the vtable
            
        Returns:
            list: List of reference objects to the vtable
        """
        references = []
        refs = self.reference_manager.getReferencesTo(vtable_addr)
        
        for ref in refs:
            # Only include code references (not data references)
            if ref.getReferenceType().isRead() or ref.getReferenceType().isWrite():
                references.append(ref)
                
        return references
        
    def analyze_function_pattern(self, func_addr):
        """
        Check if function matches constructor patterns.
        
        Args:
            func_addr: Address of function to analyze
            
        Returns:
            dict: Analysis results with confidence score and detected patterns
        """
        function = self.function_manager.getFunctionAt(func_addr)
        if function is None:
            return None
            
        analysis = {
            'function': function,
            'confidence': 0,
            'patterns': [],
            'details': {}
        }
        
        # Pattern 1: Early vtable assignment
        if self._has_early_vtable_assignment(function):
            analysis['confidence'] += 25
            analysis['patterns'].append('early_vtable_assignment')
            
        # Pattern 2: This pointer usage
        this_usage = self._analyze_this_pointer_usage(function)
        if this_usage['score'] > 0:
            analysis['confidence'] += this_usage['score']
            analysis['patterns'].append('this_pointer_usage')
            analysis['details']['this_usage'] = this_usage
            
        # Pattern 3: Member initialization
        member_init = self._analyze_member_initialization(function)
        if member_init['score'] > 0:
            analysis['confidence'] += member_init['score']
            analysis['patterns'].append('member_initialization')
            analysis['details']['member_init'] = member_init
            
        # Pattern 4: Base constructor calls
        base_calls = self._find_base_constructor_calls(function)
        if base_calls:
            analysis['confidence'] += len(base_calls) * 10
            analysis['patterns'].append('base_constructor_calls')
            analysis['details']['base_calls'] = base_calls
            
        # Pattern 5: Function prologue analysis
        prologue = self._analyze_function_prologue(function)
        if prologue['is_constructor_like']:
            analysis['confidence'] += prologue['score']
            analysis['patterns'].append('constructor_prologue')
            analysis['details']['prologue'] = prologue
            
        return analysis
        
    def find_new_operator_calls(self):
        """
        Locate dynamic allocation patterns (operator new calls).
        
        Returns:
            list: List of addresses where operator new is called
        """
        new_calls = []
        
        # Find operator new functions
        new_functions = self._find_operator_new_functions()
        
        for new_func in new_functions:
            # Find all calls to this operator new
            new_addr = new_func.getEntryPoint()
            references = self.reference_manager.getReferencesTo(new_addr)
            
            for ref in references:
                if ref.getReferenceType().isCall():
                    new_calls.append(ref.getFromAddress())
                    
        return new_calls
        
    def identify_base_constructor_calls(self, func_addr):
        """
        Find base class constructor calls within a function.
        
        Args:
            func_addr: Address of function to analyze
            
        Returns:
            list: List of potential base constructor calls
        """
        function = self.function_manager.getFunctionAt(func_addr)
        if function is None:
            return []
            
        return self._find_base_constructor_calls(function)
        
    def analyze_calling_context(self, func_addr):
        """
        Analyze how and where a function is called to determine if it's a constructor.
        
        Args:
            func_addr: Address of function to analyze
            
        Returns:
            dict: Calling context analysis
        """
        context = {
            'dynamic_allocation': [],
            'stack_allocation': [],
            'global_initialization': [],
            'confidence_boost': 0
        }
        
        # Get all references to this function
        references = self.reference_manager.getReferencesTo(func_addr)
        
        for ref in references:
            if ref.getReferenceType().isCall():
                call_addr = ref.getFromAddress()
                call_context = self._analyze_single_call_context(call_addr)
                
                if call_context['type'] == 'dynamic':
                    context['dynamic_allocation'].append(call_context)
                    context['confidence_boost'] += 30
                elif call_context['type'] == 'stack':
                    context['stack_allocation'].append(call_context)
                    context['confidence_boost'] += 20
                elif call_context['type'] == 'global':
                    context['global_initialization'].append(call_context)
                    context['confidence_boost'] += 15
                    
        return context
        
    def get_constructor_signature_hints(self, func_addr):
        """
        Analyze function signature for constructor hints.
        
        Args:
            func_addr: Address of function to analyze
            
        Returns:
            dict: Signature analysis results
        """
        function = self.function_manager.getFunctionAt(func_addr)
        if function is None:
            return None
            
        signature = {
            'parameter_count': function.getParameterCount(),
            'return_type': str(function.getReturnType()),
            'calling_convention': str(function.getCallingConvention()),
            'is_constructor_like': False,
            'confidence': 0
        }
        
        # Constructors typically return void or the object type
        if signature['return_type'] in ['void', 'undefined']:
            signature['confidence'] += 10
            
        # Constructors typically have at least one parameter (this pointer)
        if signature['parameter_count'] >= 1:
            signature['confidence'] += 5
            
        # Check calling convention (thiscall is common for constructors)
        if 'this' in signature['calling_convention'].lower():
            signature['confidence'] += 15
            
        signature['is_constructor_like'] = signature['confidence'] >= 15
        return signature
        
    def _has_early_vtable_assignment(self, function):
        """Check if function assigns vtable pointer early."""
        try:
            # Get first few instructions
            instructions = self.listing.getInstructions(function.getBody(), True)
            instruction_count = 0
            
            for instruction in instructions:
                instruction_count += 1
                if instruction_count > 10:  # Only check first 10 instructions
                    break
                    
                # Look for MOV instructions that could be vtable assignments
                if instruction.getMnemonicString().upper() == "MOV":
                    # Check if this is writing to a memory location (potential vtable assignment)
                    if self._is_potential_vtable_assignment(instruction):
                        return True
                        
        except:
            pass
            
        return False
        
    def _analyze_this_pointer_usage(self, function):
        """Analyze this pointer usage patterns."""
        usage = {
            'score': 0,
            'register_usage': {},
            'offset_accesses': 0
        }
        
        try:
            instructions = self.listing.getInstructions(function.getBody(), True)
            
            # Track register usage (ECX is common for 'this' pointer in x86)
            registers = ['ecx', 'rcx', 'edx', 'rdx']  # Common 'this' pointer registers
            
            for instruction in instructions:
                inst_str = str(instruction).lower()
                
                for reg in registers:
                    if reg in inst_str:
                        usage['register_usage'][reg] = usage['register_usage'].get(reg, 0) + 1
                        
                # Look for offset accesses [reg+offset]
                if '[' in inst_str and '+' in inst_str:
                    usage['offset_accesses'] += 1
                    
            # Score based on patterns
            if usage['register_usage'].get('ecx', 0) >= 3:
                usage['score'] += 15
            if usage['register_usage'].get('rcx', 0) >= 3:
                usage['score'] += 15
            if usage['offset_accesses'] >= 2:
                usage['score'] += 10
                
        except:
            pass
            
        return usage
        
    def _analyze_member_initialization(self, function):
        """Analyze member variable initialization patterns."""
        init_analysis = {
            'score': 0,
            'offset_writes': 0,
            'immediate_values': 0,
            'zero_initializations': 0
        }
        
        try:
            instructions = self.listing.getInstructions(function.getBody(), True)
            
            for instruction in instructions:
                mnemonic = instruction.getMnemonicString().upper()
                inst_str = str(instruction).lower()
                
                # Look for MOV instructions writing to offsets
                if mnemonic == "MOV" and '[' in inst_str and '+' in inst_str:
                    init_analysis['offset_writes'] += 1
                    
                    # Check for immediate values
                    if any(char.isdigit() for char in inst_str.split(',')[-1]):
                        init_analysis['immediate_values'] += 1
                        
                    # Check for zero initialization
                    if ', 0' in inst_str or ', 0x0' in inst_str:
                        init_analysis['zero_initializations'] += 1
                        
            # Score based on patterns
            if init_analysis['offset_writes'] >= 2:
                init_analysis['score'] += 10
            if init_analysis['immediate_values'] >= 1:
                init_analysis['score'] += 5
            if init_analysis['zero_initializations'] >= 1:
                init_analysis['score'] += 5
                
        except:
            pass
            
        return init_analysis
        
    def _find_base_constructor_calls(self, function):
        """Find calls to other constructors (base class constructors)."""
        base_calls = []
        
        try:
            instructions = self.listing.getInstructions(function.getBody(), True)
            
            for instruction in instructions:
                if instruction.getFlowType().isCall():
                    flows = instruction.getFlows()
                    for flow_addr in flows:
                        called_function = self.function_manager.getFunctionAt(flow_addr)
                        if called_function is not None:
                            # Quick heuristic: if called function also sets vtables, might be constructor
                            if self._function_sets_vtables(called_function):
                                base_calls.append({
                                    'address': flow_addr,
                                    'function': called_function,
                                    'call_site': instruction.getAddress()
                                })
                                
        except:
            pass
            
        return base_calls
        
    def _analyze_function_prologue(self, function):
        """Analyze function prologue for constructor patterns."""
        prologue = {
            'is_constructor_like': False,
            'score': 0,
            'has_frame_setup': False,
            'preserves_registers': False
        }
        
        try:
            # Get first few instructions
            instructions = self.listing.getInstructions(function.getBody(), True)
            instruction_count = 0
            
            for instruction in instructions:
                instruction_count += 1
                if instruction_count > 5:  # Only check prologue
                    break
                    
                mnemonic = instruction.getMnemonicString().upper()
                
                # Look for standard prologue patterns
                if mnemonic in ["PUSH", "MOV"] and "ebp" in str(instruction).lower():
                    prologue['has_frame_setup'] = True
                    prologue['score'] += 5
                    
                if mnemonic == "PUSH" and any(reg in str(instruction).lower() 
                                            for reg in ["esi", "edi", "ebx"]):
                    prologue['preserves_registers'] = True
                    prologue['score'] += 3
                    
            prologue['is_constructor_like'] = prologue['score'] >= 5
            
        except:
            pass
            
        return prologue
        
    def _find_operator_new_functions(self):
        """Find operator new functions in the program."""
        new_functions = []
        
        function_iterator = self.function_manager.getFunctions(True)
        for function in function_iterator:
            func_name = function.getName().lower()
            
            # Look for various operator new patterns
            if any(pattern in func_name for pattern in [
                "operator new", "??2@", "_znw", "malloc"
            ]):
                new_functions.append(function)
                
        return new_functions
        
    def _analyze_single_call_context(self, call_addr):
        """Analyze the context of a single function call."""
        context = {
            'type': 'unknown',
            'confidence': 0,
            'details': {}
        }
        
        # Check if called after operator new
        if self._is_called_after_new(call_addr):
            context['type'] = 'dynamic'
            context['confidence'] = 30
            
        # Check if called with stack-allocated object
        elif self._is_stack_allocation_call(call_addr):
            context['type'] = 'stack'
            context['confidence'] = 20
            
        # Check if called in global context
        elif self._is_global_initialization_call(call_addr):
            context['type'] = 'global'
            context['confidence'] = 15
            
        return context
        
    def _is_potential_vtable_assignment(self, instruction):
        """Check if instruction could be a vtable assignment."""
        # This is a simplified check - real implementation would be more sophisticated
        inst_str = str(instruction).lower()
        return ('[' in inst_str and 
                'mov' in inst_str and 
                any(reg in inst_str for reg in ['ecx', 'eax', 'edx']))
        
    def _function_sets_vtables(self, function):
        """Quick check if function sets vtable pointers."""
        # Simplified implementation - could be enhanced
        try:
            instructions = self.listing.getInstructions(function.getBody(), True)
            
            for instruction in instructions:
                if (instruction.getMnemonicString().upper() == "MOV" and
                    '[' in str(instruction) and
                    self._is_potential_vtable_assignment(instruction)):
                    return True
                    
        except:
            pass
            
        return False
        
    def _is_called_after_new(self, call_addr):
        """Check if call occurs after operator new."""
        try:
            # Look backwards for operator new call
            current_addr = call_addr
            for i in range(20):
                current_addr = current_addr.previous()
                if current_addr is None:
                    break
                    
                instruction = self.listing.getInstructionAt(current_addr)
                if instruction is not None and instruction.getFlowType().isCall():
                    flows = instruction.getFlows()
                    for flow_addr in flows:
                        called_function = self.function_manager.getFunctionAt(flow_addr)
                        if called_function is not None:
                            func_name = called_function.getName().lower()
                            if any(pattern in func_name for pattern in ["new", "malloc"]):
                                return True
                                
        except:
            pass
            
        return False
        
    def _is_stack_allocation_call(self, call_addr):
        """Check if call is in stack allocation context."""
        try:
            # Look for LEA instructions loading stack addresses
            current_addr = call_addr
            for i in range(10):
                current_addr = current_addr.previous()
                if current_addr is None:
                    break
                    
                instruction = self.listing.getInstructionAt(current_addr)
                if instruction is not None:
                    if (instruction.getMnemonicString().upper() == "LEA" and
                        any(reg in str(instruction).lower() for reg in ["ebp", "esp", "rsp", "rbp"])):
                        return True
                        
        except:
            pass
            
        return False
        
    def _is_global_initialization_call(self, call_addr):
        """Check if call is in global initialization context."""
        # Check if call is outside of any function (global scope)
        calling_function = self.function_manager.getFunctionContaining(call_addr)
        return calling_function is None

