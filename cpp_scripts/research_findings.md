# C++ Reverse Engineering Research Findings

## Vtable Structure and Layout

### Basic Vtable Concepts (from ALSchwalm's blog)

**Key Points:**
- Vtables are tables of function pointers created for each type having virtual functions
- Each instance gets a vptr (virtual pointer) that points to the correct vtable
- Vtable entries must be in the same order for related types
- Vtables are typically found in .rodata section as adjacent function offsets

**GCC Vtable Layout:**
```
| Offset | Pointer to  |
|--------|-------------|
|      0 | Destructor1 |
|      4 | Destructor2 |
|      8 | run         |
|     12 | walk        |
|     16 | move        |
```

**Important Details:**
- GCC inserts multiple destructors for different circumstances
- Abstract classes (with pure virtual methods) have NULL pointers for destructors in newer GCC versions
- Pure virtual functions are replaced with `___cxa_pure_virtual` entries
- Virtual function calls dereference vptr and add offset to access correct vtable entry

**Reverse Engineering Process:**
1. Locate vtables in .rodata by finding adjacent function offsets
2. Identify virtual function calls by looking for vptr dereference + offset patterns
3. Create structures for each class with vptr member
4. Create vtable structures with named function pointer members
5. Set appropriate types to get meaningful decompiler output

**Compilation Context:**
- Code compiled without RTTI (`-fno-rtti`)
- Binaries are stripped
- Focus on GCC behavior (implementation varies by compiler)



## Advanced Vtable Detection (from ALSchwalm's Part 2)

### Itanium C++ ABI Vtable Structure

**Complete Vtable Layout:**
```
| Offset to Top |
| RTTI Pointer  |
| Function Ptr 1|
| Function Ptr 2|
| ...           |
```

**Key Points:**
- RTTI pointer is 0 when RTTI is disabled
- Offset to Top indicates subobject positioning in multiple inheritance
- Virtual table groups consist of primary + secondary tables
- Groups have decreasing "Offset to Top" values

**Multiple Inheritance:**
- Objects with multiple parents have multiple vtables (vtable groups)
- Primary table for first parent, secondary tables for others
- Tables are adjacent in binary, ordered by parent declaration
- Offset to Top helps identify table relationships

### Programmatic Vtable Detection Algorithm

**Detection Criteria:**
1. Located in data segments (typically .rodata)
2. Contains consecutive function pointers
3. RTTI pointer is 0 (when RTTI disabled)
4. Only first element is referenced by code
5. Vtable groups have decreasing Offset to Top values

**Python Script Structure (IDA-based):**
```python
def get_table(ea):
    # Read offset_to_top and rtti_ptr
    # Validate rtti_ptr == 0
    # Count consecutive function pointers
    # Return (offset_to_top, end_ea) or None

def get_table_group_bounds(ea):
    # Find consecutive tables with decreasing offset_to_top
    # Return (start_ea, end_ea) for the group

def find_tablegroups(segname=".rodata"):
    # Scan segment for vtable groups
    # Return list of (start, end) address pairs
```

**Usage:**
- Run in IDA Python interpreter
- Combines with structure creation for analysis
- Enables automated vtable discovery in large binaries


## Constructor Identification Techniques (from Black Hat Paper)

### Types of Object Creation and Constructor Patterns

**1. Global Objects:**
- Memory allocated at compile-time in data segment
- Constructor called before main() during C++ startup
- Destructor called at program exit
- **Identification:** Look for function called with pointer to global variable as `this` pointer
- **Location:** Constructor calls between program entry point and main()

**2. Local Objects:**
- Memory allocated on stack
- Constructor called at point of declaration
- Destructor called at end of scope (block exit)
- **Identification:** Function called with `this` pointer to uninitialized stack variable
- **Pattern:** Destructor is last function called with same `this` pointer in same block

**Example Pattern:**
```assembly
.text:004010AD lea ecx, [ebp+var_8] ; var_8 is uninitialized
.text:004010B0 call sub_401000     ; constructor
.text:004010B5 mov edx, [ebp+var_8]
; ... object usage ...
.text:004010C6 lea ecx, [ebp+var_8]
.text:004010C9 call sub_401020     ; destructor
```

**3. Dynamically Allocated Objects:**
- Created via `new` operator
- Pattern: `new()` function call → constructor call
- `new()` takes object size as parameter, allocates heap memory
- Returned address passed to constructor as `this` pointer
- **Identification:** Look for `operator new()` calls followed by function calls
- Destruction via `delete` operator: destructor call → `free()` call

**Constructor Analysis for Class Relationships:**
- Constructors contain initialization code
- Call base class constructors
- Set up vtables
- **Single Inheritance Pattern:** Constructor calls another constructor with same `this` pointer
- High probability that called function is base class constructor if it's identified as constructor elsewhere


## Existing C++ Reverse Engineering Tools

### OOAnalyzer (CMU SEI)
**Description:** Automatically recovers C++-style classes from executables
**Approach:** 
- Uses constraint solving with XSB Prolog
- Generates and solves constraints to recover class information
- Recovers class definitions, virtual function call information, and class relationships
- Handles inheritance and composition

**Output:** JSON file with information on recovered C++ classes

**Integration:**
- Originally designed for IDA Pro via OOAnalyzer IDA Plugin
- New OOAnalyzer Ghidra Plugin available
- Part of Pharos Binary Analysis Framework

**Key Features:**
- Automated class recovery
- Virtual function table analysis
- Inheritance relationship detection
- No RTTI required

### Other Notable Tools:
**Binary Ninja:** Interactive decompiler with C++ analysis capabilities
**Cutter:** Free and open-source reverse engineering platform
**ReGenny:** Interactive structure reconstruction tool for C++ headers
**Ghidra C++ Class Analyzer:** Built-in Ghidra scripts for RTTI analysis and class reconstruction

### Ghidra Built-in Capabilities:
- RTTI analysis scripts (when RTTI is available)
- Class reconstruction scripts
- Virtual function table detection
- C++ decompilation support

**Gap Identified:** 
- Most tools focus on RTTI-enabled binaries
- Limited support for user-specified vtable addresses
- Manual constructor identification still challenging
- Need for interactive, user-guided analysis tools

