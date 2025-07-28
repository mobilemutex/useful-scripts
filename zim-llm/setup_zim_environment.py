#!/usr/bin/env python3
"""
Setup script for ZIM Tools environment.
This script helps set up the environment for testing ZIM tools.
"""

import os
import sys
import subprocess
import urllib.request
from pathlib import Path

def install_dependencies():
    """Install required dependencies for ZIM tools."""
    print("📦 Installing dependencies...")
    
    dependencies = [
        "libzim>=3.5",
        "strip-tags>=0.6",
        "pydantic"
    ]
    
    for dep in dependencies:
        print(f"   Installing {dep}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep])
            print(f"   ✅ {dep} installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Failed to install {dep}: {e}")
            return False
    
    return True

def download_sample_zim():
    """Download a small sample ZIM file for testing."""
    print("\n📥 Downloading sample ZIM file...")
    
    # Small test ZIM file (TED talks, usually around 100MB)
    zim_url = "https://download.kiwix.org/zim/ted/ted_en_science_2023-08.zim"
    zim_filename = "ted_en_science_2023-08.zim"
    
    if os.path.exists(zim_filename):
        print(f"   ✅ {zim_filename} already exists")
        return True
    
    try:
        print(f"   Downloading {zim_filename} from {zim_url}")
        print("   This may take a few minutes...")
        
        def progress_hook(block_num, block_size, total_size):
            downloaded = block_num * block_size
            if total_size > 0:
                percent = min(100, (downloaded * 100) // total_size)
                print(f"\r   Progress: {percent}% ({downloaded // (1024*1024)} MB / {total_size // (1024*1024)} MB)", end="")
        
        urllib.request.urlretrieve(zim_url, zim_filename, progress_hook)
        print(f"\n   ✅ Downloaded {zim_filename}")
        return True
        
    except Exception as e:
        print(f"\n   ❌ Failed to download ZIM file: {e}")
        print("   You can manually download ZIM files from: https://download.kiwix.org/zim/")
        return False

def create_test_script():
    """Create a comprehensive test script with real ZIM file."""
    print("\n📝 Creating comprehensive test script...")
    
    test_script = '''#!/usr/bin/env python3
"""
Comprehensive test script for ZIM Tools with real ZIM files.
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock

# Import our ZIM tools
from zim_tools import Tools

async def test_with_real_zim():
    """Test ZIM tools with real ZIM files."""
    print("🧪 Testing ZIM Tools with real ZIM files...")
    
    tools = Tools()
    event_emitter = AsyncMock()
    
    # Test 1: List available ZIM files
    print("\\n📁 Listing available ZIM files...")
    result = await tools.list_zim_files(__event_emitter__=event_emitter)
    print(result)
    
    # Find ZIM files for testing
    zim_files = tools._find_zim_files()
    if not zim_files:
        print("❌ No ZIM files found. Please download some ZIM files first.")
        return
    
    # Use the first ZIM file for testing
    test_zim = zim_files[0]
    print(f"\\n🎯 Using {os.path.basename(test_zim)} for testing...")
    
    # Test 2: Search the ZIM file
    print("\\n🔍 Testing search functionality...")
    search_result = await tools.search_zim(test_zim, "science", __event_emitter__=event_emitter)
    print(search_result)
    
    # Test 3: Search and collect content
    print("\\n🔍📖 Testing search and collect functionality...")
    collect_result = await tools.search_and_collect_zim(test_zim, "technology", __event_emitter__=event_emitter)
    print(collect_result[:500] + "..." if len(collect_result) > 500 else collect_result)
    
    print("\\n✅ Real ZIM file testing completed!")

if __name__ == "__main__":
    asyncio.run(test_with_real_zim())
'''
    
    with open("test_real_zim.py", "w") as f:
        f.write(test_script)
    
    print("   ✅ Created test_real_zim.py")

def create_usage_examples():
    """Create usage examples for the ZIM tools."""
    print("\n📚 Creating usage examples...")
    
    examples = '''# ZIM Tools Usage Examples

## Basic Usage in Open-WebUI

1. **Install the tool:**
   - Copy `zim_tools.py` to your Open-WebUI instance
   - The tool will automatically install dependencies when saved

2. **Configure the tool:**
   - Go to Workspace > Tools in Open-WebUI
   - Find "ZIM Archive Tools" and configure:
     - `zim_directory`: Directory containing your ZIM files
     - `max_search_results`: Maximum results to return (default: 3)
     - `enable_citations`: Enable citation events (default: True)

3. **Enable for models:**
   - Go to Workspace > Models
   - Edit your model and enable "ZIM Archive Tools"

## Example Conversations

### Discovering Available Resources
**User:** "What offline resources do you have access to?"
**LLM:** *calls `list_zim_files()`*
**Response:** Shows available Wikipedia, Stack Exchange, DevDocs, etc.

### Searching for Information
**User:** "Can you find information about machine learning from the available offline resources?"
**LLM:** *calls `search_and_collect_zim()` with appropriate ZIM file*
**Response:** Returns relevant articles with proper citations

### Specific Topic Research
**User:** "I need information about Docker containers from the DevDocs archive"
**LLM:** *calls `search_and_collect_zim("devdocs_en_docker_2025-04.zim", "containers")`*
**Response:** Returns Docker container documentation with citations

## ZIM File Sources

Download ZIM files from:
- **Kiwix Downloads:** https://download.kiwix.org/zim/
- **Wikipedia:** Various language editions and date ranges
- **Stack Exchange:** Programming Q&A sites
- **DevDocs:** Developer documentation
- **Project Gutenberg:** Classic literature
- **TED Talks:** Educational videos and transcripts

## Popular ZIM Files for Development

1. **Wikipedia (English, no pictures):** `wikipedia_en_all_nopic_YYYY-MM.zim`
2. **Stack Overflow:** `stackoverflow.com_en_all_YYYY-MM.zim`
3. **DevDocs (various technologies):** `devdocs_en_*_YYYY-MM.zim`
4. **Ask Ubuntu:** `askubuntu.com_en_all_YYYY-MM.zim`

## Configuration Tips

- Place ZIM files in a dedicated directory (e.g., `/data/zim/`)
- Set `KIWIX_HOME` environment variable to your ZIM directory
- Start with smaller ZIM files for testing
- Use descriptive filenames to help the LLM choose appropriate resources
'''
    
    with open("USAGE_EXAMPLES.md", "w") as f:
        f.write(examples)
    
    print("   ✅ Created USAGE_EXAMPLES.md")

def main():
    """Main setup function."""
    print("🚀 ZIM Tools Environment Setup")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version.split()[0]} detected")
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Failed to install dependencies")
        sys.exit(1)
    
    # Create test scripts and examples
    create_test_script()
    create_usage_examples()
    
    # Optionally download sample ZIM
    print("\n❓ Would you like to download a sample ZIM file for testing?")
    print("   This will download a ~100MB TED talks archive.")
    response = input("   Download sample ZIM? (y/N): ").lower().strip()
    
    if response in ['y', 'yes']:
        download_sample_zim()
    else:
        print("   Skipping sample download. You can manually download ZIM files from:")
        print("   https://download.kiwix.org/zim/")
    
    print("\n🎉 Setup completed!")
    print("\nNext steps:")
    print("1. Copy zim_tools.py to your Open-WebUI instance")
    print("2. Download ZIM files to your chosen directory")
    print("3. Configure the tool in Open-WebUI")
    print("4. Enable the tool for your models")
    print("5. Start chatting with offline knowledge!")

if __name__ == "__main__":
    main()

