# Ghidra C++ Reverse Engineering Scripts - Design Document

## Overview
This document outlines the design for a collection of Ghidra scripts to assist in reversing C++ binaries without RTTI information. The scripts will allow users to specify vtable addresses and automatically identify constructors and create class structures.

## Design Goals
1. **User-Guided Analysis:** Allow users to specify vtable addresses as starting points
2. **Constructor Identification:** Automatically identify constructors based on vtable usage patterns
3. **Class Structure Creation:** Generate Ghidra data types and structures for identified classes
4. **Modular Design:** Separate scripts for different aspects of analysis
5. **Interactive Workflow:** Support iterative analysis and refinement

## Script Architecture

### Core Scripts

#### 1. VtableAnalyzer.py
**Purpose:** Analyze user-specified vtable addresses and extract function information
**Functionality:**
- Validate vtable address and structure
- Extract function pointers from vtable
- Identify vtable size and layout
- Detect multiple inheritance patterns (vtable groups)
- Create vtable data structures in Ghidra

**Input:** Vtable address(es)
**Output:** Vtable structure information, function list

#### 2. ConstructorFinder.py
**Purpose:** Identify constructors based on vtable usage patterns
**Functionality:**
- Search for references to vtable addresses
- Analyze function patterns that set vtable pointers
- Identify constructor patterns (new + function call, stack allocation + function call)
- Distinguish constructors from other member functions
- Handle inheritance patterns (base class constructor calls)

**Input:** Vtable addresses, function addresses
**Output:** List of identified constructor functions

#### 3. ClassStructureBuilder.py
**Purpose:** Create class data structures and organize analysis results
**Functionality:**
- Create class data types in Ghidra
- Define vtable pointer members
- Organize constructors and member functions
- Create inheritance relationships
- Generate meaningful class and function names

**Input:** Constructor list, vtable information, class relationships
**Output:** Ghidra data types and structures

#### 4. CppAnalysisManager.py
**Purpose:** Main orchestration script that coordinates the analysis workflow
**Functionality:**
- Provide user interface for specifying vtables
- Coordinate execution of other scripts
- Manage analysis state and results
- Provide progress feedback and error handling
- Support iterative analysis refinement

### Utility Scripts

#### 5. VtableUtils.py
**Purpose:** Common utilities for vtable analysis
**Functions:**
- `validate_vtable_address(addr)` - Check if address contains valid vtable
- `extract_function_pointers(vtable_addr, size)` - Extract function addresses
- `detect_vtable_group(addr)` - Find related vtables for multiple inheritance
- `get_vtable_size(addr)` - Determine vtable size

#### 6. ConstructorUtils.py
**Purpose:** Common utilities for constructor identification
**Functions:**
- `find_vtable_references(vtable_addr)` - Find code that references vtable
- `analyze_function_pattern(func_addr)` - Check if function matches constructor pattern
- `find_new_operator_calls()` - Locate dynamic allocation patterns
- `identify_base_constructor_calls(func_addr)` - Find base class constructor calls

#### 7. GhidraHelpers.py
**Purpose:** Common Ghidra API utilities
**Functions:**
- `create_data_type(name, size)` - Create custom data types
- `set_function_name(addr, name)` - Set function names
- `create_structure(name, fields)` - Create structure data types
- `add_comment(addr, comment)` - Add analysis comments

## User Interface Design

### Main Analysis Workflow
1. **Vtable Specification:** User provides vtable address(es) via dialog or script parameter
2. **Vtable Analysis:** Automatic analysis of vtable structure and functions
3. **Constructor Search:** Automatic identification of constructor candidates
4. **Review and Refinement:** User reviews results and can refine analysis
5. **Structure Creation:** Generate final class structures and data types

### Input Methods
- **Interactive Dialog:** GUI dialog for specifying vtable addresses
- **Script Parameters:** Command-line style parameters for batch processing
- **Selection-Based:** Use current cursor position or selection as vtable address

### Output and Feedback
- **Progress Messages:** Real-time feedback during analysis
- **Results Summary:** Summary of identified classes, constructors, and functions
- **Error Handling:** Clear error messages and recovery suggestions
- **Analysis Report:** Detailed report of findings and confidence levels

## Technical Implementation Details

### Vtable Detection Algorithm
1. **Address Validation:** Check if address is in appropriate memory section (.rodata, .data)
2. **Pointer Validation:** Verify that vtable entries point to valid function addresses
3. **Pattern Recognition:** Look for consistent patterns in function pointer layout
4. **Size Detection:** Determine vtable size by finding end of function pointer sequence

### Constructor Identification Algorithm
1. **Reference Analysis:** Find all references to vtable address
2. **Context Analysis:** Analyze surrounding code for constructor patterns:
   - `new` operator followed by function call
   - Stack allocation followed by function call
   - Function that sets vtable pointer early in execution
3. **Pattern Matching:** Look for specific assembly patterns:
   - Vtable pointer assignment
   - Base class constructor calls
   - Member initialization
4. **Confidence Scoring:** Assign confidence scores to constructor candidates

### Class Structure Generation
1. **Data Type Creation:** Create Ghidra data types for each identified class
2. **Member Organization:** Organize vtable pointer and other members
3. **Function Association:** Associate constructors and member functions with classes
4. **Naming Convention:** Generate meaningful names based on analysis context
5. **Documentation:** Add comments and documentation to generated structures

## Error Handling and Edge Cases

### Common Error Scenarios
- **Invalid Vtable Address:** Address doesn't contain valid vtable data
- **Ambiguous Constructors:** Multiple functions could be constructors
- **Complex Inheritance:** Multiple inheritance with complex vtable layouts
- **Optimized Code:** Compiler optimizations that obscure patterns

### Mitigation Strategies
- **Validation Checks:** Extensive validation of input addresses and data
- **Confidence Scoring:** Provide confidence levels for all identifications
- **User Confirmation:** Allow user to confirm or reject identifications
- **Fallback Methods:** Alternative analysis methods when primary methods fail

## Integration with Existing Tools

### Ghidra Integration
- **Data Type Manager:** Integrate with Ghidra's data type system
- **Function Manager:** Use Ghidra's function analysis capabilities
- **Symbol Table:** Create meaningful symbols and names
- **Comments and Documentation:** Add analysis results as comments

### Compatibility Considerations
- **Compiler Variations:** Support for different C++ compilers (GCC, MSVC, Clang)
- **Architecture Support:** Focus on x86/x64, with extensibility for other architectures
- **Binary Formats:** Support for PE, ELF, and other common formats

## Future Enhancements

### Advanced Features
- **Machine Learning:** Use ML to improve constructor identification accuracy
- **Template Recognition:** Identify and handle C++ template instantiations
- **STL Detection:** Recognize and handle Standard Template Library usage
- **Cross-Reference Analysis:** Analyze relationships between multiple classes

### Performance Optimizations
- **Caching:** Cache analysis results for faster re-analysis
- **Parallel Processing:** Parallelize analysis where possible
- **Incremental Analysis:** Support for incremental updates as analysis progresses

## Testing Strategy

### Test Cases
- **Simple Classes:** Basic classes with virtual functions
- **Inheritance Hierarchies:** Single and multiple inheritance scenarios
- **Complex Vtables:** Large vtables with many functions
- **Optimized Binaries:** Binaries compiled with various optimization levels

### Validation Methods
- **Known Binaries:** Test against binaries with known class structures
- **Synthetic Tests:** Create test binaries with specific patterns
- **Comparison Testing:** Compare results with other tools (OOAnalyzer, IDA Pro)
- **User Feedback:** Collect feedback from real-world usage

