# ZIM Tools for Open-WebUI

Convert offline Kiwix ZIM archives (Wikipedia, Stack Exchange, DevDocs, etc.) into an instant knowledge source for LLMs in Open-WebUI.

## Overview

This project provides Open-WebUI compatible tools that enable Large Language Models to search and read content from offline ZIM archives. Based on the [llm-tools-kiwix](https://github.com/mozanunal/llm-tools-kiwix) project, these tools bring the power of offline knowledge bases directly into your Open-WebUI chat interface.

## Key Features

- **🔍 Intelligent Search**: Search across multiple ZIM archives with relevance ranking
- **📚 Content Retrieval**: Read and extract clean text content from ZIM articles
- **📖 Multiple Archives**: Support for Wikipedia, Stack Exchange, DevDocs, and more
- **🎯 Smart Discovery**: Automatic detection of available ZIM files
- **📊 Real-time Feedback**: Progress updates and status indicators during operations
- **📝 Citation Support**: Proper attribution with source references
- **⚙️ Configurable**: Customizable search limits and behavior settings
- **🛡️ Error Handling**: Graceful handling of missing files and network issues

## Supported ZIM Archives

- **Wikipedia**: All language editions (with or without images)
- **Stack Exchange**: Stack Overflow, Ask Ubuntu, Server Fault, etc.
- **DevDocs**: Documentation for programming languages and frameworks
- **Project Gutenberg**: Classic literature and texts
- **TED Talks**: Educational video transcripts
- **Wiktionary**: Dictionary and language resources
- **And many more**: Any ZIM archive from [Kiwix Downloads](https://download.kiwix.org/zim/)

## Quick Start

### 1. Installation

1. **Copy the tool file** to your Open-WebUI instance:
   ```bash
   # Copy zim_tools.py to your Open-WebUI tools directory
   cp zim_tools.py /path/to/open-webui/tools/
   ```

2. **Install in Open-WebUI**:
   - Go to **Workspace > Tools** in Open-WebUI
   - Click **+ Add Tool**
   - Paste the contents of `zim_tools.py`
   - Click **Save**

### 2. Download ZIM Files

Download ZIM archives from [Kiwix Downloads](https://download.kiwix.org/zim/):

```bash
# Create ZIM directory
mkdir -p /data/zim
cd /data/zim

# Download sample archives (examples)
wget https://download.kiwix.org/zim/wikipedia/wikipedia_en_simple_all_nopic_2023-10.zim
wget https://download.kiwix.org/zim/stackoverflow.com/stackoverflow.com_en_all_2024-10.zim
```

### 3. Configuration

1. **Configure tool settings**:
   - Go to **Workspace > Tools** in Open-WebUI
   - Find "ZIM Archive Tools" and click the settings icon
   - Set `zim_directory` to your ZIM files location (e.g., `/data/zim`)
   - Adjust other settings as needed

2. **Enable for models**:
   - Go to **Workspace > Models**
   - Select your model and click the edit icon
   - Enable "ZIM Archive Tools" in the Tools section
   - Save changes

### 4. Usage

Start chatting with your LLM and ask questions that can benefit from offline knowledge:

```
"What offline resources do you have access to?"
"Search for information about machine learning algorithms"
"Find documentation about Docker containers from DevDocs"
"What can you tell me about quantum physics from Wikipedia?"
```

## Tool Functions

### `list_zim_files()`
Discovers and lists all available ZIM archive files with metadata including article counts and file sizes.

### `search_zim(zim_file_path, search_query)`
Performs full-text search within a specific ZIM archive and returns article paths and metadata.

### `read_zim_article(zim_file_path, article_path)`
Reads and returns the plain text content of a specific article from a ZIM archive.

### `search_and_collect_zim(zim_file_path, search_query)`
**Primary function** that combines search and content retrieval, returning formatted content from the most relevant articles.

## Configuration Options

### Valves (Settings)

- **`zim_directory`** (string, default: `"./"`)
  - Directory to search for ZIM files
  - Also checks `KIWIX_HOME` environment variable

- **`max_search_results`** (integer, default: `3`)
  - Maximum number of search results to return
  - Prevents overwhelming responses with too many results

- **`enable_citations`** (boolean, default: `true`)
  - Enable citation events for proper source attribution
  - Provides references for academic and research use

- **`enable_status_updates`** (boolean, default: `true`)
  - Enable real-time status updates during operations
  - Shows search progress and content retrieval status

## Example Conversations

### Discovering Resources
**User**: "What offline knowledge bases do you have access to?"

**LLM**: *calls `list_zim_files()`*

**Response**: 
```
Found 3 ZIM archive files:

1. wikipedia_en_simple_all_nopic_2023-10.zim
   Path: /data/zim/wikipedia_en_simple_all_nopic_2023-10.zim
   Articles: 205,328, Media: 0
   Size: 245.7 MB

2. stackoverflow.com_en_all_2024-10.zim
   Path: /data/zim/stackoverflow.com_en_all_2024-10.zim
   Articles: 23,456,789, Media: 0
   Size: 52,341.2 MB

3. devdocs_en_python_2025-04.zim
   Path: /data/zim/devdocs_en_python_2025-04.zim
   Articles: 12,543, Media: 0
   Size: 89.3 MB
```

### Research Query
**User**: "I need information about neural networks and deep learning"

**LLM**: *calls `search_and_collect_zim("wikipedia_en_simple_all_nopic_2023-10.zim", "neural networks deep learning")`*

**Response**: Returns relevant Wikipedia articles about neural networks with proper citations and source attribution.

### Technical Documentation
**User**: "How do I use Python decorators?"

**LLM**: *calls `search_and_collect_zim("devdocs_en_python_2025-04.zim", "decorators")`*

**Response**: Returns Python documentation about decorators with code examples and explanations.

## Dependencies

The tool automatically handles dependency installation through Open-WebUI. Required packages:

- `libzim>=3.5` - Core ZIM file reading library
- `strip-tags>=0.6` - HTML tag removal for clean text
- `pydantic` - Configuration validation (usually pre-installed)

## Troubleshooting

### Common Issues

#### "libzim not available" Error
**Solution**: The tool will automatically install dependencies when saved in Open-WebUI. If manual installation is needed:
```bash
pip install libzim>=3.5 strip-tags>=0.6
```

#### "No ZIM files found"
**Solution**: 
1. Check the `zim_directory` setting in tool configuration
2. Ensure ZIM files are in the correct directory
3. Set the `KIWIX_HOME` environment variable if needed

#### Search Returns No Results
**Solution**:
1. Try different search terms
2. Verify the ZIM file contains the expected content
3. Check ZIM file integrity

#### Performance Issues
**Solution**:
1. Use smaller ZIM files for testing
2. Reduce `max_search_results` setting
3. Ensure sufficient disk space and memory

### Debug Mode

Enable detailed logging by modifying the tool configuration:
```python
# In tool settings, enable verbose status updates
enable_status_updates: true
```

## File Structure

```
zim-tools-openwebui/
├── zim_tools.py                    # Main tool file
├── README.md                       # This documentation
├── INSTALLATION.md                 # Detailed installation guide
├── USAGE_EXAMPLES.md              # Usage examples and patterns
├── testing_guide.md               # Comprehensive testing guide
├── setup_zim_environment.py       # Environment setup script
├── validate_tool_compatibility.py # Compatibility validation
└── test_zim_tools.py              # Basic functionality tests
```

## Contributing

This project is based on [llm-tools-kiwix](https://github.com/mozanunal/llm-tools-kiwix) by mozanunal. Contributions and improvements are welcome.

## License

MIT License - see the original [llm-tools-kiwix](https://github.com/mozanunal/llm-tools-kiwix) project for details.

## Support

For issues and questions:
1. Check the troubleshooting section above
2. Review the testing guide for validation steps
3. Ensure your Open-WebUI version is compatible (0.4.0+)
4. Verify ZIM file integrity and format

## Acknowledgments

- **mozanunal** for the original [llm-tools-kiwix](https://github.com/mozanunal/llm-tools-kiwix) project
- **Kiwix Project** for the ZIM format and archive ecosystem
- **Open-WebUI Team** for the extensible LLM interface platform

