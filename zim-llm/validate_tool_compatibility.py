#!/usr/bin/env python3
"""
Validation script for Open-WebUI tool compatibility.
This script validates that the ZIM tools meet Open-WebUI requirements.
"""

import ast
import inspect
import sys
import re
from typing import get_type_hints

def validate_docstring():
    """Validate the tool docstring has required metadata."""
    print("📋 Validating tool docstring...")
    
    with open('zim_tools.py', 'r') as f:
        content = f.read()
    
    # Extract docstring
    tree = ast.parse(content)
    docstring = ast.get_docstring(tree)
    
    if not docstring:
        print("❌ No module docstring found")
        return False
    
    required_fields = {
        'title:': 'Tool title',
        'author:': 'Author information', 
        'description:': 'Tool description',
        'required_open_webui_version:': 'Required Open-WebUI version',
        'requirements:': 'Python dependencies',
        'version:': 'Tool version',
        'licence:': 'License information'
    }
    
    missing_fields = []
    for field, description in required_fields.items():
        if field not in docstring:
            missing_fields.append(f"{field} ({description})")
        else:
            print(f"✅ Found {field}")
    
    if missing_fields:
        print(f"❌ Missing required fields: {', '.join(missing_fields)}")
        return False
    
    print("✅ Docstring validation passed")
    return True

def validate_tools_class():
    """Validate the Tools class structure."""
    print("\n🔧 Validating Tools class structure...")
    
    try:
        from zim_tools import Tools
    except ImportError as e:
        print(f"❌ Failed to import Tools class: {e}")
        return False
    
    # Check if Tools class exists
    if not hasattr(Tools, '__init__'):
        print("❌ Tools class missing __init__ method")
        return False
    
    print("✅ Tools class found")
    
    # Check for Valves subclass
    if not hasattr(Tools, 'Valves'):
        print("❌ Tools class missing Valves subclass")
        return False
    
    print("✅ Valves subclass found")
    
    # Validate Valves inherits from BaseModel
    try:
        from pydantic import BaseModel
        if not issubclass(Tools.Valves, BaseModel):
            print("❌ Valves class does not inherit from BaseModel")
            return False
        print("✅ Valves inherits from BaseModel")
    except ImportError:
        print("⚠️ Cannot validate BaseModel inheritance (pydantic not available)")
    
    return True

def validate_tool_methods():
    """Validate tool methods have proper signatures and type hints."""
    print("\n⚙️ Validating tool methods...")
    
    try:
        from zim_tools import Tools
    except ImportError as e:
        print(f"❌ Failed to import Tools class: {e}")
        return False
    
    tools_instance = Tools()
    
    # Expected tool methods
    expected_methods = [
        'list_zim_files',
        'search_zim',
        'read_zim_article', 
        'search_and_collect_zim'
    ]
    
    for method_name in expected_methods:
        if not hasattr(tools_instance, method_name):
            print(f"❌ Missing method: {method_name}")
            return False
        
        method = getattr(tools_instance, method_name)
        
        # Check if method is callable
        if not callable(method):
            print(f"❌ {method_name} is not callable")
            return False
        
        # Check method signature
        sig = inspect.signature(method)
        
        # Validate type hints
        try:
            hints = get_type_hints(method)
            if 'return' not in hints:
                print(f"⚠️ {method_name} missing return type hint")
            else:
                print(f"✅ {method_name} has return type hint: {hints['return']}")
        except Exception as e:
            print(f"⚠️ Could not get type hints for {method_name}: {e}")
        
        # Check for async
        if not inspect.iscoroutinefunction(method):
            print(f"⚠️ {method_name} is not async (may not support event emitters)")
        else:
            print(f"✅ {method_name} is async")
        
        print(f"✅ Method {method_name} validated")
    
    return True

def validate_valve_configuration():
    """Validate valve configuration options."""
    print("\n⚙️ Validating valve configuration...")
    
    try:
        from zim_tools import Tools
    except ImportError as e:
        print(f"❌ Failed to import Tools class: {e}")
        return False
    
    tools = Tools()
    valves = tools.valves
    
    # Check expected valve fields
    expected_valves = {
        'zim_directory': str,
        'max_search_results': int,
        'enable_citations': bool,
        'enable_status_updates': bool
    }
    
    for valve_name, expected_type in expected_valves.items():
        if not hasattr(valves, valve_name):
            print(f"❌ Missing valve: {valve_name}")
            return False
        
        valve_value = getattr(valves, valve_name)
        if not isinstance(valve_value, expected_type):
            print(f"❌ Valve {valve_name} has wrong type: {type(valve_value)} (expected {expected_type})")
            return False
        
        print(f"✅ Valve {valve_name}: {valve_value} ({expected_type.__name__})")
    
    return True

def validate_error_handling():
    """Validate error handling capabilities."""
    print("\n🛡️ Validating error handling...")
    
    try:
        from zim_tools import Tools
    except ImportError as e:
        print(f"❌ Failed to import Tools class: {e}")
        return False
    
    tools = Tools()
    
    # Test dependency checking
    if hasattr(tools, '_dependencies_available'):
        print(f"✅ Dependency checking available: {tools._dependencies_available}")
    else:
        print("❌ Missing dependency checking")
        return False
    
    # Test helper methods
    helper_methods = ['_find_zim_files', '_get_zim_info']
    for method_name in helper_methods:
        if not hasattr(tools, method_name):
            print(f"❌ Missing helper method: {method_name}")
            return False
        print(f"✅ Helper method {method_name} found")
    
    return True

def validate_open_webui_compatibility():
    """Validate Open-WebUI specific compatibility features."""
    print("\n🌐 Validating Open-WebUI compatibility...")
    
    # Check for event emitter support
    with open('zim_tools.py', 'r') as f:
        content = f.read()
    
    # Check for __event_emitter__ parameter
    if '__event_emitter__' not in content:
        print("❌ Missing __event_emitter__ parameter support")
        return False
    print("✅ Event emitter support found")
    
    # Check for citation events
    if '"type": "citation"' not in content:
        print("❌ Missing citation event support")
        return False
    print("✅ Citation event support found")
    
    # Check for status events
    if '"type": "status"' not in content:
        print("❌ Missing status event support")
        return False
    print("✅ Status event support found")
    
    # Check for proper async/await usage
    if 'await __event_emitter__' not in content:
        print("❌ Missing proper async event emitter usage")
        return False
    print("✅ Proper async event emitter usage found")
    
    return True

def validate_dependencies():
    """Validate dependency handling."""
    print("\n📦 Validating dependency handling...")
    
    with open('zim_tools.py', 'r') as f:
        content = f.read()
    
    # Check for proper import handling
    if 'try:' not in content or 'except ImportError:' not in content:
        print("❌ Missing proper import error handling")
        return False
    print("✅ Import error handling found")
    
    # Check for libzim imports
    required_imports = ['libzim.reader', 'libzim.search', 'strip_tags']
    for imp in required_imports:
        if imp not in content:
            print(f"❌ Missing import: {imp}")
            return False
        print(f"✅ Import found: {imp}")
    
    # Check for fallback implementations
    if 'def strip_tags(content):' not in content:
        print("❌ Missing fallback strip_tags implementation")
        return False
    print("✅ Fallback strip_tags implementation found")
    
    return True

def generate_compatibility_report():
    """Generate a comprehensive compatibility report."""
    print("\n📊 Generating compatibility report...")
    
    tests = [
        ("Docstring Validation", validate_docstring),
        ("Tools Class Structure", validate_tools_class),
        ("Tool Methods", validate_tool_methods),
        ("Valve Configuration", validate_valve_configuration),
        ("Error Handling", validate_error_handling),
        ("Open-WebUI Compatibility", validate_open_webui_compatibility),
        ("Dependency Handling", validate_dependencies)
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results[test_name] = False
    
    # Generate report
    print("\n" + "="*50)
    print("COMPATIBILITY REPORT")
    print("="*50)
    
    passed = 0
    total = len(tests)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<30} {status}")
        if result:
            passed += 1
    
    print("-"*50)
    print(f"TOTAL: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 All compatibility tests passed!")
        print("The ZIM tools are ready for Open-WebUI integration.")
    else:
        print(f"\n⚠️ {total-passed} tests failed.")
        print("Please address the issues before deploying to Open-WebUI.")
    
    return passed == total

def main():
    """Main validation function."""
    print("🔍 ZIM Tools Open-WebUI Compatibility Validation")
    print("="*60)
    
    # Check if zim_tools.py exists
    try:
        with open('zim_tools.py', 'r') as f:
            pass
        print("✅ zim_tools.py found")
    except FileNotFoundError:
        print("❌ zim_tools.py not found in current directory")
        sys.exit(1)
    
    # Run validation
    success = generate_compatibility_report()
    
    if success:
        print("\n🚀 Next steps:")
        print("1. Copy zim_tools.py to your Open-WebUI instance")
        print("2. Install dependencies (libzim, strip-tags)")
        print("3. Download ZIM files to your chosen directory")
        print("4. Configure the tool in Open-WebUI settings")
        print("5. Enable the tool for your models")
        print("6. Test with real ZIM files using the testing guide")
    else:
        print("\n🔧 Please fix the validation issues before proceeding.")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

