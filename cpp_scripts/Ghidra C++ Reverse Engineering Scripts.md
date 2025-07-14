# Ghidra C++ Reverse Engineering Scripts

**Author:** Manus AI  
**Version:** 1.0  
**Date:** July 2025

## Overview

This collection of Ghidra scripts provides comprehensive tools for reverse engineering C++ binaries that lack Runtime Type Information (RTTI). The scripts enable analysts to specify virtual function table (vtable) addresses manually and automatically identify constructors, create class structures, and organize the analysis results within Ghidra's framework.

The toolkit addresses a critical gap in C++ reverse engineering where traditional RTTI-based analysis tools fail. When C++ binaries are compiled without RTTI information or when RTTI has been stripped, analysts must rely on manual techniques and pattern recognition to understand class hierarchies and object-oriented structures. These scripts automate much of this process while providing the flexibility for user-guided analysis.

## Table of Contents

1. [Installation and Setup](#installation-and-setup)
2. [Script Collection Overview](#script-collection-overview)
3. [Quick Start Guide](#quick-start-guide)
4. [Detailed Usage Instructions](#detailed-usage-instructions)
5. [Advanced Features](#advanced-features)
6. [Troubleshooting](#troubleshooting)
7. [Technical Background](#technical-background)
8. [Best Practices](#best-practices)
9. [Limitations and Known Issues](#limitations-and-known-issues)
10. [Contributing](#contributing)
11. [References](#references)

## Installation and Setup

### Prerequisites

Before using these scripts, ensure you have the following:

- **Ghidra 10.0 or later**: The scripts are designed for modern Ghidra versions and utilize current API features
- **Java 11 or later**: Required for Ghidra operation
- **Python support in Ghidra**: Ensure Jython is properly configured
- **Target binary**: A C++ executable or library without RTTI information

### Installation Steps

1. **Download the Script Collection**: Obtain all script files from this repository
2. **Copy to Ghidra Scripts Directory**: Place all `.py` files in your Ghidra scripts directory, typically located at:
   - Windows: `%USERPROFILE%\\ghidra_scripts`
   - Linux/macOS: `~/ghidra_scripts`
3. **Refresh Script Manager**: In Ghidra, open the Script Manager (Window → Script Manager) and click the refresh button
4. **Verify Installation**: Confirm all scripts appear in the Script Manager under the "C++" category

### Required Files

The complete script collection includes:

- `CppAnalysisManager.py` - Main orchestration script
- `VtableAnalyzer.py` - Vtable structure analysis
- `ConstructorFinder.py` - Constructor identification
- `ClassStructureBuilder.py` - Class structure creation
- `VtableUtils.py` - Vtable utility functions
- `ConstructorUtils.py` - Constructor utility functions  
- `GhidraHelpers.py` - Common Ghidra API utilities

## Script Collection Overview

### Core Analysis Scripts

#### CppAnalysisManager.py
The main orchestration script that provides a unified interface for the entire analysis workflow. This script coordinates the execution of other components and manages the analysis state. It offers both interactive menu-driven operation and programmatic access to individual analysis phases.

Key features include:
- Interactive menu system for guided analysis
- Full workflow automation
- Analysis state management
- Results export and reporting
- Error handling and recovery

#### VtableAnalyzer.py  
Specialized script for analyzing virtual function tables in C++ binaries. This component handles the low-level details of vtable structure detection, function pointer extraction, and vtable validation.

Core capabilities:
- Vtable address validation and structure detection
- Function pointer extraction and validation
- Support for Itanium ABI vtable format
- Multiple inheritance pattern detection
- Automatic vtable size determination

#### ConstructorFinder.py
Advanced constructor identification engine that uses pattern matching and heuristic analysis to locate C++ constructors. The script analyzes function behavior, calling patterns, and assembly-level characteristics to identify constructor candidates.

Analysis techniques include:
- Vtable reference pattern analysis
- Early vtable assignment detection
- Dynamic allocation pattern recognition
- Base class constructor call identification
- Confidence scoring for constructor candidates

#### ClassStructureBuilder.py
Comprehensive class structure generation tool that creates meaningful Ghidra data types and organizes analysis results. This script transforms the raw analysis data into structured class definitions within Ghidra.

Structure creation features:
- Class data type generation
- Vtable structure definition
- Constructor and member function organization
- Inheritance relationship establishment
- Namespace creation and symbol management

### Utility Modules

#### VtableUtils.py
Comprehensive utility library for vtable-related operations. This module provides reusable functions for vtable validation, analysis, and manipulation that are used throughout the script collection.

#### ConstructorUtils.py  
Specialized utilities for constructor pattern detection and analysis. Contains the core algorithms for identifying constructor signatures and behavioral patterns.

#### GhidraHelpers.py
Common Ghidra API wrapper functions that simplify interaction with Ghidra's complex API. This module provides convenient interfaces for data type creation, symbol management, and memory operations.

## Quick Start Guide

### Basic Workflow

The typical analysis workflow follows these steps:

1. **Load Target Binary**: Open your C++ binary in Ghidra and complete initial auto-analysis
2. **Identify Vtable Addresses**: Locate potential vtable addresses through manual analysis or automated scanning
3. **Run Analysis**: Execute the scripts to analyze vtables, find constructors, and create class structures
4. **Review Results**: Examine the generated class structures and refine as needed
5. **Export Documentation**: Generate analysis reports for documentation purposes

### Simple Example

For a quick start with a single vtable:

1. Navigate to a suspected vtable address in Ghidra
2. Run `CppAnalysisManager.py` from the Script Manager
3. Select "Full Analysis Workflow" from the menu
4. Confirm the current address as a vtable when prompted
5. Review the generated class structure and constructor identifications

### Command-Line Style Usage

For automated analysis, you can also run individual scripts:

```python
# Analyze a specific vtable
vtable_addr = currentProgram.getAddressFactory().getAddress("0x12345678")
analyzer = VtableAnalyzer()
analyzer.analyze_vtable(vtable_addr)

# Find constructors for the vtable
finder = ConstructorFinder()
constructors = finder.find_constructors_for_vtable(vtable_addr)

# Create class structure
builder = ClassStructureBuilder()
class_info = builder.create_class_structure(vtable_addr, constructors)
```

## Detailed Usage Instructions

### Vtable Analysis

The vtable analysis process begins with identifying potential vtable addresses in the binary. Vtables in C++ binaries typically appear in read-only data sections and contain arrays of function pointers.

#### Manual Vtable Identification

Before running the automated analysis, you should manually identify potential vtable locations:

1. **Examine Data Sections**: Look in `.rodata`, `.data`, or similar sections for arrays of function pointers
2. **Follow References**: Use Ghidra's reference tracking to find code that references potential vtables
3. **Pattern Recognition**: Look for consistent patterns of function pointers that point to executable code
4. **Cross-Reference Analysis**: Examine functions that might set vtable pointers in constructors

#### Running Vtable Analysis

Once you have identified potential vtable addresses:

1. **Launch VtableAnalyzer**: Run the script from Ghidra's Script Manager
2. **Specify Addresses**: Provide vtable addresses either by:
   - Using the current cursor position
   - Entering addresses manually in hexadecimal format
   - Selecting from a list of candidates
3. **Review Results**: The script will:
   - Validate the vtable structure
   - Extract function pointers
   - Create vtable data types in Ghidra
   - Generate analysis reports

#### Vtable Structure Validation

The script performs several validation checks:

- **Address Alignment**: Ensures vtable addresses are properly aligned for the target architecture
- **Memory Accessibility**: Verifies addresses are in readable memory regions
- **Function Pointer Validation**: Confirms that vtable entries point to valid executable code
- **Structure Consistency**: Checks for consistent vtable layout patterns

### Constructor Identification

Constructor identification is one of the most challenging aspects of C++ reverse engineering. The ConstructorFinder script uses multiple heuristics and pattern matching techniques to identify constructor functions.

#### Analysis Techniques

The script employs several complementary approaches:

**Vtable Reference Analysis**: Constructors typically set vtable pointers early in their execution. The script analyzes all functions that reference identified vtables and examines their behavior patterns.

**Dynamic Allocation Patterns**: For dynamically allocated objects, constructors are often called immediately after `operator new`. The script identifies allocation patterns and traces subsequent function calls.

**Assembly Pattern Recognition**: Constructors exhibit characteristic assembly patterns, including:
- Early vtable pointer assignment
- This pointer manipulation
- Member variable initialization
- Base class constructor calls

**Calling Context Analysis**: The script examines how and where functions are called to determine if they match constructor usage patterns.

#### Confidence Scoring

Each constructor candidate receives a confidence score based on multiple factors:

- **High Confidence (30+ points)**: Strong indicators like early vtable assignment and dynamic allocation patterns
- **Medium Confidence (20-29 points)**: Moderate indicators such as this pointer usage and member initialization
- **Low Confidence (10-19 points)**: Weak indicators like naming patterns or basic structural characteristics

#### Manual Review and Refinement

While the automated analysis is comprehensive, manual review is often necessary:

1. **Examine High-Confidence Candidates**: Review functions with confidence scores above 30
2. **Validate Low-Confidence Results**: Manually analyze functions with scores between 10-20
3. **Cross-Reference with Vtables**: Ensure identified constructors correspond to the correct vtables
4. **Check for False Positives**: Verify that identified functions are actually constructors

### Class Structure Creation

The final phase involves creating meaningful class structures within Ghidra based on the analysis results.

#### Data Type Generation

The ClassStructureBuilder script creates several types of data structures:

**Class Data Types**: Primary class structures that include:
- Vtable pointer as the first member
- Estimated member variable space
- Proper size calculations based on constructor analysis

**Vtable Structures**: Detailed vtable layouts that include:
- Individual function pointer fields
- Meaningful field names based on function analysis
- Comments linking to actual function implementations

**Namespace Organization**: Logical grouping of related symbols:
- Class-specific namespaces for member functions
- Hierarchical organization for inheritance relationships
- Consistent naming conventions across the analysis

#### Inheritance Relationship Detection

The script attempts to identify inheritance relationships through:

**Constructor Call Analysis**: Examining constructor implementations for calls to other constructors, which often indicate base class relationships.

**Vtable Comparison**: Comparing vtable structures to identify shared function pointers that might indicate inheritance.

**Memory Layout Analysis**: Analyzing object memory layouts to detect embedded base class structures.

#### Symbol Management

Proper symbol management is crucial for maintaining organized analysis results:

1. **Function Naming**: Constructors and member functions receive meaningful names based on their class association
2. **Label Creation**: Important addresses receive descriptive labels for easy navigation
3. **Comment Addition**: Analysis results are documented through comprehensive comments
4. **Bookmark Management**: Key analysis points are marked with bookmarks for future reference

## Advanced Features

### Multiple Inheritance Support

C++ multiple inheritance creates complex vtable layouts that require specialized handling. The scripts include support for:

**Vtable Group Detection**: Identifying related vtables that belong to the same class hierarchy in multiple inheritance scenarios.

**Offset Calculation**: Computing proper offsets for base class vtables and this pointer adjustments.

**Complex Constructor Analysis**: Handling constructors that initialize multiple base classes and manage multiple vtable pointers.

### Template Recognition

While template instantiation analysis is limited without RTTI, the scripts provide basic support for:

**Pattern-Based Detection**: Identifying common template patterns through function naming and structure analysis.

**STL Container Recognition**: Basic recognition of Standard Template Library containers and their characteristic vtable patterns.

**Template Specialization Handling**: Managing multiple instantiations of the same template class.

### Compiler-Specific Adaptations

Different C++ compilers generate varying vtable layouts and constructor patterns:

**GCC Support**: Handles GCC-specific vtable layouts and constructor calling conventions.

**MSVC Compatibility**: Supports Microsoft Visual C++ vtable structures and exception handling patterns.

**Clang Integration**: Works with Clang-generated binaries and their optimization patterns.

### Batch Processing

For large-scale analysis, the scripts support batch processing modes:

**Multiple Binary Analysis**: Processing multiple related binaries with shared class hierarchies.

**Automated Scanning**: Systematic scanning of memory regions for vtable patterns.

**Report Generation**: Comprehensive reporting across multiple analysis sessions.

## Troubleshooting

### Common Issues and Solutions

#### Vtable Detection Problems

**Issue**: Script fails to detect valid vtables
**Solutions**:
- Verify address alignment for the target architecture
- Check that addresses are in readable memory sections
- Ensure the binary contains actual C++ code with virtual functions
- Try manual validation of suspected vtable addresses

**Issue**: False positive vtable detections
**Solutions**:
- Increase validation strictness in VtableUtils configuration
- Manually review detected vtables for consistency
- Cross-reference with disassembly to confirm function pointer arrays

#### Constructor Identification Issues

**Issue**: Low confidence scores for obvious constructors
**Solutions**:
- Review and adjust confidence scoring thresholds
- Add custom pattern recognition for specific compiler optimizations
- Manually validate constructor candidates through disassembly analysis

**Issue**: Missing constructor detections
**Solutions**:
- Expand search radius for vtable references
- Include additional calling pattern analysis
- Check for compiler-specific constructor optimizations

#### Class Structure Problems

**Issue**: Incorrect class size estimations
**Solutions**:
- Manually analyze constructor implementations for member initialization patterns
- Cross-reference with object allocation sizes
- Use debugging information if available to validate estimates

**Issue**: Inheritance relationships not detected
**Solutions**:
- Manually trace constructor call chains
- Compare vtable structures for shared function pointers
- Analyze object memory layouts for embedded structures

### Performance Optimization

For large binaries or complex analysis scenarios:

**Memory Management**: Monitor Ghidra memory usage during analysis and adjust batch sizes accordingly.

**Analysis Scope**: Limit analysis to specific memory regions or function sets when appropriate.

**Caching**: Enable result caching for repeated analysis operations.

**Parallel Processing**: Consider running multiple analysis sessions for independent class hierarchies.

### Debugging and Logging

The scripts include comprehensive logging capabilities:

**Verbose Mode**: Enable detailed logging for troubleshooting analysis issues.

**Debug Output**: Access internal analysis state and intermediate results.

**Error Reporting**: Comprehensive error messages with suggested solutions.

**Analysis Metrics**: Performance and accuracy metrics for analysis validation.

## Technical Background

### C++ Object Model Without RTTI

Understanding the C++ object model is crucial for effective reverse engineering. When RTTI is disabled or stripped, analysts must rely on structural patterns and behavioral analysis to understand class hierarchies.

#### Vtable Structure and Layout

Virtual function tables are the cornerstone of C++ polymorphism. In the Itanium ABI, which is used by GCC and Clang, vtables have a specific structure:

```
vtable layout:
[offset_to_top]     // Offset from vtable to top of object
[rtti_pointer]      // Pointer to RTTI info (0 if disabled)
[virtual_func_0]    // First virtual function
[virtual_func_1]    // Second virtual function
...
[virtual_func_n]    // Last virtual function
```

When RTTI is disabled, the `rtti_pointer` field is typically zero, which serves as an important validation criterion for vtable detection.

#### Constructor Behavior Patterns

C++ constructors exhibit predictable behavior patterns that can be detected through static analysis:

**Vtable Assignment**: Constructors must set the vtable pointer early in their execution, typically as one of the first operations after the function prologue.

**Member Initialization**: Constructors initialize member variables, often in a predictable order that corresponds to their declaration sequence.

**Base Class Construction**: In inheritance hierarchies, derived class constructors call base class constructors before initializing their own members.

**This Pointer Management**: Constructors receive the object address (this pointer) as their first parameter and use it throughout the initialization process.

### Assembly-Level Analysis Techniques

The scripts employ sophisticated assembly-level analysis to identify C++ patterns:

#### Pattern Matching Algorithms

**Instruction Sequence Analysis**: Identifying characteristic instruction sequences that indicate constructor behavior, such as vtable pointer assignments and member initialization loops.

**Register Usage Patterns**: Analyzing register usage to identify this pointer manipulation and member access patterns.

**Control Flow Analysis**: Examining function control flow to identify constructor-specific patterns like base class constructor calls and exception handling setup.

#### Heuristic Scoring Systems

The constructor identification system uses weighted heuristics to score potential constructor candidates:

**Primary Indicators (High Weight)**:
- Early vtable pointer assignment (30 points)
- Called immediately after operator new (35 points)
- Multiple offset-based memory writes (25 points)

**Secondary Indicators (Medium Weight)**:
- This pointer register usage patterns (20 points)
- Function name patterns containing "ctor" or "init" (15 points)
- Called in stack allocation contexts (20 points)

**Tertiary Indicators (Low Weight)**:
- Standard function prologue patterns (10 points)
- Specific calling conventions (10 points)
- Cross-references from global initialization (5 points)

### Algorithm Implementation Details

#### Vtable Validation Algorithm

The vtable validation process follows a multi-stage approach:

1. **Address Validation**: Verify that the provided address is within program memory and properly aligned
2. **Header Analysis**: Attempt to parse Itanium ABI header fields (offset_to_top, rtti_pointer)
3. **Function Pointer Extraction**: Read consecutive pointer-sized values and validate them as function addresses
4. **Consistency Checking**: Ensure all extracted function pointers point to executable memory regions
5. **Size Determination**: Calculate vtable size based on the number of valid function pointers

#### Constructor Detection Algorithm

Constructor detection employs a multi-pass analysis approach:

**Pass 1 - Reference Analysis**: Identify all functions that reference known vtable addresses and analyze their basic characteristics.

**Pass 2 - Pattern Matching**: Apply pattern matching algorithms to identify constructor-specific assembly patterns and behavioral characteristics.

**Pass 3 - Context Analysis**: Examine calling contexts to identify dynamic allocation patterns, stack allocation scenarios, and global initialization contexts.

**Pass 4 - Confidence Scoring**: Apply weighted scoring algorithms to rank constructor candidates based on the strength of detected patterns.

**Pass 5 - Validation**: Cross-validate results against known C++ object model constraints and compiler-specific patterns.

## Best Practices

### Preparation and Planning

Effective C++ reverse engineering requires careful preparation and systematic analysis:

**Binary Analysis Preparation**: Before running the scripts, complete Ghidra's automatic analysis and review the results. Pay particular attention to function identification, string analysis, and cross-reference generation.

**Memory Layout Understanding**: Familiarize yourself with the target binary's memory layout, including the locations of code sections, data sections, and any available debugging information.

**Compiler Identification**: Determine the compiler and compilation settings used to build the target binary, as this affects vtable layouts and constructor patterns.

### Systematic Analysis Approach

**Start with High-Confidence Targets**: Begin analysis with clearly identifiable vtables and work toward more ambiguous cases.

**Iterative Refinement**: Use the analysis results to inform subsequent analysis passes, refining vtable identifications and constructor detections based on discovered patterns.

**Cross-Validation**: Validate analysis results against multiple sources of evidence, including disassembly analysis, dynamic analysis results, and known C++ object model constraints.

### Documentation and Organization

**Maintain Analysis Notes**: Document your analysis process, including manual discoveries, script results, and validation steps.

**Organize Results**: Use Ghidra's organizational features (namespaces, bookmarks, comments) to maintain clear and navigable analysis results.

**Version Control**: Consider using version control for your Ghidra project files to track analysis progress and enable rollback if needed.

### Quality Assurance

**Manual Validation**: Always manually validate high-impact analysis results, particularly class structure definitions and inheritance relationships.

**Consistency Checking**: Ensure that analysis results are internally consistent and conform to C++ object model requirements.

**Peer Review**: When possible, have other analysts review your analysis results and methodology.

## Limitations and Known Issues

### Current Limitations

**Template Analysis**: The scripts provide limited support for C++ template analysis, as template instantiation patterns are difficult to detect without RTTI information.

**Exception Handling**: Analysis of C++ exception handling mechanisms is not fully implemented, though vtable-based exception handling patterns may be partially detected.

**Compiler Optimization**: Heavily optimized code may exhibit patterns that differ from the expected C++ object model, potentially leading to analysis errors.

**Architecture Support**: While the scripts are designed to be architecture-agnostic, they have been primarily tested on x86 and x64 platforms.

### Known Issues

**False Positive Constructors**: In some cases, regular member functions that set vtable pointers may be incorrectly identified as constructors.

**Multiple Inheritance Complexity**: Complex multiple inheritance hierarchies may not be fully analyzed, particularly when virtual inheritance is involved.

**Inline Function Handling**: Inlined constructors and member functions may not be properly detected or analyzed.

**Debug Information Conflicts**: When partial debug information is present, it may conflict with the script analysis results.

### Workarounds and Mitigation

**Manual Review**: Always manually review analysis results, particularly for critical class structures and inheritance relationships.

**Incremental Analysis**: Use incremental analysis approaches, validating results at each step before proceeding to more complex analysis.

**Cross-Reference with Dynamic Analysis**: When possible, validate static analysis results against dynamic analysis data from debuggers or runtime analysis tools.

**Community Feedback**: Report issues and contribute improvements to the script collection through community channels.

## Contributing

### Development Guidelines

Contributions to the script collection are welcome and encouraged. When contributing:

**Code Quality**: Follow Python coding standards and maintain consistency with existing script architecture.

**Documentation**: Provide comprehensive documentation for new features and modifications.

**Testing**: Test contributions against multiple target binaries and compiler configurations.

**Compatibility**: Ensure compatibility with current Ghidra versions and maintain backward compatibility when possible.

### Reporting Issues

When reporting issues:

**Provide Context**: Include information about the target binary, Ghidra version, and analysis context.

**Include Examples**: Provide specific examples of problematic analysis results or unexpected behavior.

**Suggest Solutions**: When possible, suggest potential solutions or workarounds for identified issues.

### Feature Requests

Feature requests should include:

**Use Case Description**: Clearly describe the use case and analysis scenario that would benefit from the requested feature.

**Technical Requirements**: Outline any specific technical requirements or constraints for the requested feature.

**Implementation Suggestions**: Provide suggestions for implementation approaches when possible.

## References

[1] Itanium C++ ABI Specification. https://itanium-cxx-abi.github.io/cxx-abi/abi.html

[2] Sabanal, P., & Yason, M. (2007). "Reversing C++". Black Hat DC 2007. https://www.blackhat.com/presentations/bh-dc-07/Sabanal_Yason/Paper/bh-dc-07-Sabanal_Yason-WP.pdf

[3] Schwalm, A. (2016). "Reversing C++ Virtual Functions: Part 1". https://alschwalm.com/blog/static/2016/12/17/reversing-c-virtual-functions/

[4] Schwalm, A. (2017). "Reversing C++ Virtual Functions: Part 2". https://alschwalm.com/blog/static/2017/01/24/reversing-c-virtual-functions-part-2-2/

[5] National Security Agency. (2019). "Ghidra Software Reverse Engineering Framework". https://ghidra-sre.org/

[6] Gennari, J. (2019). "Using OOAnalyzer to Reverse Engineer Object Oriented Code with Ghidra". Carnegie Mellon University Software Engineering Institute. https://insights.sei.cmu.edu/blog/using-ooanalyzer-to-reverse-engineer-object-oriented-code-with-ghidra/

[7] ISO/IEC 14882:2020. "Programming languages — C++". International Organization for Standardization.

[8] Stroustrup, B. (2013). "The C++ Programming Language, 4th Edition". Addison-Wesley Professional.

[9] Lippman, S. B., Lajoie, J., & Moo, B. E. (2012). "C++ Primer, 5th Edition". Addison-Wesley Professional.

[10] Meyers, S. (2014). "Effective Modern C++: 42 Specific Ways to Improve Your Use of C++11 and C++14". O'Reilly Media.

