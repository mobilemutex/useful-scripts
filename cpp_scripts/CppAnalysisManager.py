# CppAnalysisManager.py - Main C++ Analysis Orchestration Script
# @author: mobilemutex
# @category: C++
# @keybinding: 
# @menupath: 
# @toolbar: 

"""
Main orchestration script for C++ reverse engineering analysis.
Coordinates vtable analysis, constructor identification, and class structure creation.
"""

import ghidra.app.script.GhidraScript as GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.data import *
from ghidra.program.model.listing import *
from ghidra.program.model.symbol import *
from ghidra.program.model.mem import *
from ghidra.util.exception import CancelledException
from java.lang import Exception as JavaException

# Import our utility modules (these would need to be in the same directory or Python path)
# from VtableUtils import VtableUtils
# from ConstructorUtils import ConstructorUtils
# from GhidraHelpers import GhidraHelpers

class CppAnalysisManager(GhidraScript):
    
    def __init__(self):
        super(CppAnalysisManager, self).__init__()
        self.analysis_state = {
            'vtables': [],
            'constructors': [],
            'classes': [],
            'analysis_complete': False
        }
        self.helpers = None
        
    def run(self):
        """Main execution method for the script."""
        try:
            self.initialize()
            
            # Show main menu
            while True:
                choice = self.show_main_menu()
                if choice is None or choice == "Exit":
                    break
                    
                self.handle_menu_choice(choice)
                
        except CancelledException:
            self.println("Script cancelled by user.")
        except Exception as e:
            self.popup("Error: {}".format(str(e)))
            
    def initialize(self):
        """Initialize the analysis manager."""
        # self.helpers = GhidraHelpers(currentProgram)
        self.println("C++ Analysis Manager initialized successfully.")
        self.println("This script coordinates vtable analysis, constructor identification, and class structure creation.")
        
    def show_main_menu(self):
        """Show the main menu and get user choice."""
        choices = [
            "Analyze Vtable",
            "Find Constructors", 
            "Create Class Structures",
            "Full Analysis Workflow",
            "View Analysis Results",
            "Export Results",
            "Clear Analysis Data",
            "Exit"
        ]
        
        choice = askChoice("C++ Analysis Manager", 
                          "Select an analysis option:", 
                          choices, 
                          "Full Analysis Workflow")
        return choice
        
    def handle_menu_choice(self, choice):
        """Handle the selected menu choice."""
        if choice == "Analyze Vtable":
            self.run_vtable_analysis()
        elif choice == "Find Constructors":
            self.run_constructor_analysis()
        elif choice == "Create Class Structures":
            self.run_class_structure_creation()
        elif choice == "Full Analysis Workflow":
            self.run_full_analysis_workflow()
        elif choice == "View Analysis Results":
            self.view_analysis_results()
        elif choice == "Export Results":
            self.export_analysis_results()
        elif choice == "Clear Analysis Data":
            self.clear_analysis_data()
            
    def run_vtable_analysis(self):
        """Run vtable analysis workflow."""
        self.println("\\n=== Vtable Analysis ===")
        
        # Get vtable addresses from user
        vtable_addresses = self.get_vtable_addresses_from_user()
        if not vtable_addresses:
            self.popup("No vtable addresses provided.")
            return
            
        # Analyze each vtable
        for vtable_addr in vtable_addresses:
            try:
                vtable_info = self.analyze_single_vtable(vtable_addr)
                if vtable_info:
                    self.analysis_state['vtables'].append(vtable_info)
                    self.println("Successfully analyzed vtable at {}".format(vtable_addr))
                else:
                    self.println("Failed to analyze vtable at {}".format(vtable_addr))
            except Exception as e:
                self.println("Error analyzing vtable at {}: {}".format(vtable_addr, str(e)))
                
        self.println("Vtable analysis complete. Found {} vtables.".format(len(self.analysis_state['vtables'])))
        
    def run_constructor_analysis(self):
        """Run constructor identification workflow."""
        self.println("\\n=== Constructor Analysis ===")
        
        if not self.analysis_state['vtables']:
            self.popup("No vtables analyzed yet. Please run vtable analysis first.")
            return
            
        # Find constructors for each vtable
        for vtable_info in self.analysis_state['vtables']:
            try:
                constructors = self.find_constructors_for_vtable(vtable_info)
                self.analysis_state['constructors'].extend(constructors)
                self.println("Found {} constructors for vtable {}".format(
                    len(constructors), vtable_info['address']))
            except Exception as e:
                self.println("Error finding constructors for vtable {}: {}".format(
                    vtable_info['address'], str(e)))
                
        self.println("Constructor analysis complete. Found {} constructors.".format(
            len(self.analysis_state['constructors'])))
        
    def run_class_structure_creation(self):
        """Run class structure creation workflow."""
        self.println("\\n=== Class Structure Creation ===")
        
        if not self.analysis_state['vtables'] or not self.analysis_state['constructors']:
            self.popup("Please run vtable and constructor analysis first.")
            return
            
        # Create class structures
        for vtable_info in self.analysis_state['vtables']:
            try:
                class_info = self.create_class_from_analysis(vtable_info)
                if class_info:
                    self.analysis_state['classes'].append(class_info)
                    self.println("Created class structure for {}".format(class_info['name']))
            except Exception as e:
                self.println("Error creating class structure: {}".format(str(e)))
                
        self.println("Class structure creation complete. Created {} classes.".format(
            len(self.analysis_state['classes'])))
        
    def run_full_analysis_workflow(self):
        """Run the complete analysis workflow."""
        self.println("\\n=== Full C++ Analysis Workflow ===")
        
        # Step 1: Vtable Analysis
        self.println("Step 1: Vtable Analysis")
        self.run_vtable_analysis()
        
        if not self.analysis_state['vtables']:
            self.popup("No vtables found. Cannot continue with analysis.")
            return
            
        # Step 2: Constructor Analysis
        self.println("\\nStep 2: Constructor Analysis")
        self.run_constructor_analysis()
        
        # Step 3: Class Structure Creation
        self.println("\\nStep 3: Class Structure Creation")
        self.run_class_structure_creation()
        
        # Step 4: Final Report
        self.println("\\nStep 4: Analysis Summary")
        self.analysis_state['analysis_complete'] = True
        self.generate_analysis_report()
        
    def get_vtable_addresses_from_user(self):
        """Get vtable addresses from user input."""
        addresses = []
        
        # Check current address first
        current_addr = currentAddress
        if current_addr is not None:
            use_current = askYesNo("Use Current Address", 
                                 "Use current address {} as vtable?".format(current_addr))
            if use_current:
                addresses.append(current_addr)
                return addresses
                
        # Manual input
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
        
    def analyze_single_vtable(self, vtable_addr):
        """Analyze a single vtable and return information."""
        # This would use VtableUtils to analyze the vtable
        # For now, simplified implementation
        
        vtable_info = {
            'address': vtable_addr,
            'functions': [],
            'size': 0,
            'name': "vtable_{}".format(vtable_addr).replace(":", "_")
        }
        
        try:
            # Extract function pointers (simplified)
            current_addr = vtable_addr
            pointer_size = currentProgram.getDefaultPointerSize()
            
            for i in range(50):  # Max 50 functions
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
                        vtable_info['functions'].append(func_addr)
                    else:
                        break
                        
                    current_addr = current_addr.add(pointer_size)
                    
                except:
                    break
                    
            vtable_info['size'] = len(vtable_info['functions']) * pointer_size
            
            # Create vtable structure
            self.create_vtable_structure(vtable_info)
            
            return vtable_info
            
        except Exception as e:
            self.println("Error analyzing vtable: {}".format(str(e)))
            return None
            
    def find_constructors_for_vtable(self, vtable_info):
        """Find constructors for a specific vtable."""
        constructors = []
        
        try:
            # Find references to the vtable
            reference_manager = currentProgram.getReferenceManager()
            references = reference_manager.getReferencesTo(vtable_info['address'])
            
            for ref in references:
                from_addr = ref.getFromAddress()
                function = currentProgram.getFunctionManager().getFunctionContaining(from_addr)
                
                if function is not None:
                    # Analyze function for constructor patterns
                    ctor_info = self.analyze_constructor_candidate(function, vtable_info)
                    if ctor_info and ctor_info['confidence'] >= 20:
                        constructors.append(ctor_info)
                        
        except Exception as e:
            self.println("Error finding constructors: {}".format(str(e)))
            
        return constructors
        
    def analyze_constructor_candidate(self, function, vtable_info):
        """Analyze a function to determine if it's a constructor."""
        # Simplified constructor analysis
        ctor_info = {
            'function': function,
            'address': function.getEntryPoint(),
            'name': function.getName(),
            'vtable_info': vtable_info,
            'confidence': 0,
            'patterns': []
        }
        
        # Check if vtable is set early in function
        if self.vtable_set_early(function, vtable_info['address']):
            ctor_info['confidence'] += 30
            ctor_info['patterns'].append('early_vtable_set')
            
        # Check for this pointer usage patterns
        if self.has_this_pointer_usage(function):
            ctor_info['confidence'] += 20
            ctor_info['patterns'].append('this_pointer_usage')
            
        # Check function name patterns
        func_name = function.getName().lower()
        if any(pattern in func_name for pattern in ['ctor', 'constructor', 'init']):
            ctor_info['confidence'] += 15
            ctor_info['patterns'].append('name_pattern')
            
        return ctor_info
        
    def create_class_from_analysis(self, vtable_info):
        """Create a class structure from analysis results."""
        class_name = "Class_{}".format(vtable_info['address']).replace(":", "_")
        
        # Find constructors for this vtable
        class_constructors = []
        for ctor in self.analysis_state['constructors']:
            if ctor['vtable_info']['address'] == vtable_info['address']:
                class_constructors.append(ctor)
                
        class_info = {
            'name': class_name,
            'vtable_info': vtable_info,
            'constructors': class_constructors,
            'virtual_functions': vtable_info['functions'],
            'size_estimate': self.estimate_class_size(vtable_info, class_constructors)
        }
        
        # Create class data type
        self.create_class_data_type(class_info)
        
        # Label functions
        self.label_class_functions(class_info)
        
        return class_info
        
    def create_vtable_structure(self, vtable_info):
        """Create vtable data structure."""
        try:
            struct_name = vtable_info['name']
            struct_dt = StructureDataType(struct_name, 0)
            
            # Add function pointers
            for i, func_addr in enumerate(vtable_info['functions']):
                field_name = "func_{}".format(i)
                struct_dt.add(PointerDataType.dataType, field_name, 
                            "Virtual function pointer to {}".format(func_addr))
                            
            # Add to data type manager
            data_type_manager = currentProgram.getDataTypeManager()
            final_struct = data_type_manager.addDataType(struct_dt, None)
            
            # Apply to memory
            createData(vtable_info['address'], final_struct)
            createLabel(vtable_info['address'], struct_name, True)
            
        except Exception as e:
            self.println("Error creating vtable structure: {}".format(str(e)))
            
    def create_class_data_type(self, class_info):
        """Create class data type."""
        try:
            class_name = class_info['name']
            class_struct = StructureDataType(class_name, 0)
            
            # Add vtable pointer
            class_struct.add(PointerDataType.dataType, "vftable", "Virtual function table pointer")
            
            # Add estimated member space
            if class_info['size_estimate'] > currentProgram.getDefaultPointerSize():
                remaining = class_info['size_estimate'] - currentProgram.getDefaultPointerSize()
                undefined_array = ArrayDataType(UndefinedDataType.dataType, remaining, 1)
                class_struct.add(undefined_array, "members", "Class member variables")
                
            # Add to data type manager
            data_type_manager = currentProgram.getDataTypeManager()
            data_type_manager.addDataType(class_struct, None)
            
        except Exception as e:
            self.println("Error creating class data type: {}".format(str(e)))
            
    def label_class_functions(self, class_info):
        """Label constructors and virtual functions."""
        class_name = class_info['name']
        
        # Label constructors
        for i, ctor in enumerate(class_info['constructors']):
            try:
                ctor_name = "{}::constructor_{}".format(class_name, i)
                ctor['function'].setName(ctor_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            except:
                pass
                
        # Label virtual functions
        for i, func_addr in enumerate(class_info['virtual_functions']):
            try:
                function = currentProgram.getFunctionManager().getFunctionAt(func_addr)
                if function is not None:
                    func_name = "{}::virtual_{}".format(class_name, i)
                    function.setName(func_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
            except:
                pass
                
    def view_analysis_results(self):
        """Display current analysis results."""
        self.println("\\n=== Analysis Results ===")
        self.println("Vtables analyzed: {}".format(len(self.analysis_state['vtables'])))
        self.println("Constructors found: {}".format(len(self.analysis_state['constructors'])))
        self.println("Classes created: {}".format(len(self.analysis_state['classes'])))
        
        if self.analysis_state['vtables']:
            self.println("\\nVtables:")
            for vtable in self.analysis_state['vtables']:
                self.println("  {} - {} functions".format(vtable['address'], len(vtable['functions'])))
                
        if self.analysis_state['constructors']:
            self.println("\\nConstructors:")
            for ctor in self.analysis_state['constructors']:
                self.println("  {} - confidence: {}".format(ctor['address'], ctor['confidence']))
                
        if self.analysis_state['classes']:
            self.println("\\nClasses:")
            for cls in self.analysis_state['classes']:
                self.println("  {} - {} constructors, {} virtual functions".format(
                    cls['name'], len(cls['constructors']), len(cls['virtual_functions'])))
                    
    def export_analysis_results(self):
        """Export analysis results to a file."""
        try:
            # Create analysis report
            report = self.generate_analysis_report_text()
            
            # Save to file (simplified - would need proper file dialog)
            filename = "cpp_analysis_results.txt"
            with open(filename, 'w') as f:
                f.write(report)
                
            self.println("Analysis results exported to: {}".format(filename))
            
        except Exception as e:
            self.popup("Error exporting results: {}".format(str(e)))
            
    def clear_analysis_data(self):
        """Clear all analysis data."""
        confirm = askYesNo("Clear Data", "Clear all analysis data?")
        if confirm:
            self.analysis_state = {
                'vtables': [],
                'constructors': [],
                'classes': [],
                'analysis_complete': False
            }
            self.println("Analysis data cleared.")
            
    def generate_analysis_report(self):
        """Generate and display analysis report."""
        report = self.generate_analysis_report_text()
        self.println(report)
        
    def generate_analysis_report_text(self):
        """Generate analysis report as text."""
        report = []
        report.append("=== C++ Analysis Report ===")
        report.append("Generated: {}".format(java.util.Date()))
        report.append("")
        
        report.append("Summary:")
        report.append("  Vtables analyzed: {}".format(len(self.analysis_state['vtables'])))
        report.append("  Constructors found: {}".format(len(self.analysis_state['constructors'])))
        report.append("  Classes created: {}".format(len(self.analysis_state['classes'])))
        report.append("")
        
        if self.analysis_state['classes']:
            report.append("Classes:")
            for cls in self.analysis_state['classes']:
                report.append("  Class: {}".format(cls['name']))
                report.append("    Vtable: {}".format(cls['vtable_info']['address']))
                report.append("    Constructors: {}".format(len(cls['constructors'])))
                report.append("    Virtual functions: {}".format(len(cls['virtual_functions'])))
                report.append("    Estimated size: {} bytes".format(cls['size_estimate']))
                report.append("")
                
        return "\\n".join(report)
        
    # Helper methods
    def is_valid_function_address(self, addr):
        """Check if address is a valid function."""
        try:
            memory = currentProgram.getMemory()
            if not memory.contains(addr):
                return False
            block = memory.getBlock(addr)
            return block is not None and block.isExecute()
        except:
            return False
            
    def vtable_set_early(self, function, vtable_addr):
        """Check if vtable is set early in function."""
        # Simplified check
        return True  # Would need proper implementation
        
    def has_this_pointer_usage(self, function):
        """Check for this pointer usage patterns."""
        # Simplified check
        return True  # Would need proper implementation
        
    def estimate_class_size(self, vtable_info, constructors):
        """Estimate class size."""
        # Simplified estimation
        return currentProgram.getDefaultPointerSize() + 16  # vtable + some members

# Create an instance and run if this script is executed directly
if __name__ == "__main__":
    manager = CppAnalysisManager()
    manager.run()

