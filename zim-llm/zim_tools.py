"""
title: ZIM Archive Tools
author: 
description: Search and read content from offline ZIM archives (Wikipedia, Stack Exchange, DevDocs, etc.)
required_open_webui_version: 0.4.0
requirements: libzim>=3.5, strip-tags>=0.6
version: 1.0.0
licence: MIT
"""

import os
from glob import glob
from pathlib import Path
from typing import List, Tuple, Optional
from datetime import datetime
from pydantic import BaseModel, Field

# Import libzim modules for ZIM file operations
try:
    from libzim.reader import Archive
    from libzim.search import Query, Searcher
except ImportError:
    Archive = None
    Query = None
    Searcher = None

# Import strip_tags for HTML content cleaning
try:
    from strip_tags import strip_tags
except ImportError:
    def strip_tags(content):
        """Fallback HTML tag stripper if strip_tags is not available"""
        import re
        return re.sub(r'<[^>]+>', '', content)


class Tools:
    def __init__(self):
        """Initialize the ZIM Tools."""
        self.valves = self.Valves()
        self.citation = False  # We handle custom citations
        
        # Check if required dependencies are available
        if Archive is None or Query is None or Searcher is None:
            self._dependencies_available = False
        else:
            self._dependencies_available = True

    class Valves(BaseModel):
        zim_directory: str = Field(
            default="./",
            description="Directory to search for ZIM files (can also use KIWIX_HOME env var)"
        )
        max_search_results: int = Field(
            default=3,
            description="Maximum number of search results to return"
        )
        enable_citations: bool = Field(
            default=True,
            description="Enable citation events for search results"
        )
        enable_status_updates: bool = Field(
            default=True,
            description="Enable status update events during operations"
        )

    def _find_zim_files(self, root_dir: str = None) -> List[str]:
        """
        Find ZIM archive files in a specified directory.
        
        Args:
            root_dir: Directory to search. Defaults to valve setting or current directory.
            
        Returns:
            List of paths to .zim files found.
        """
        if root_dir is None:
            root_dir = self.valves.zim_directory
            
        zim_files = []
        
        # Search in the specified root directory
        zim_files.extend(glob(f"{root_dir}/*.zim"))
        
        # Also search in KIWIX_HOME if set
        kiwix_home_env = os.environ.get("KIWIX_HOME")
        if kiwix_home_env and kiwix_home_env != root_dir:
            zim_files.extend(glob(f"{kiwix_home_env}/*.zim"))
        
        # Remove duplicates and return sorted list
        return sorted(list(set(zim_files)))

    def _get_zim_info(self, zim_file_path: str) -> dict:
        """
        Get basic information about a ZIM file.
        
        Args:
            zim_file_path: Path to the ZIM file
            
        Returns:
            Dictionary with ZIM file information
        """
        try:
            if not self._dependencies_available:
                return {"error": "libzim not available"}
                
            archive = Archive(zim_file_path)
            return {
                "path": zim_file_path,
                "filename": os.path.basename(zim_file_path),
                "article_count": archive.article_count,
                "media_count": archive.media_count,
                "size_mb": round(os.path.getsize(zim_file_path) / (1024 * 1024), 2)
            }
        except Exception as e:
            return {
                "path": zim_file_path,
                "filename": os.path.basename(zim_file_path),
                "error": str(e)
            }

    async def list_zim_files(self, __event_emitter__=None) -> str:
        """
        List all available ZIM archive files with their information.
        
        Returns:
            Formatted string listing all discovered ZIM files with metadata.
        """
        if not self._dependencies_available:
            return "Error: libzim library is not available. Please install it with: pip install libzim>=3.5"
        
        if __event_emitter__ and self.valves.enable_status_updates:
            await __event_emitter__({
                "type": "status",
                "data": {"description": "Discovering ZIM files...", "done": False}
            })
        
        zim_files = self._find_zim_files()
        
        if not zim_files:
            return f"No ZIM files found in directory '{self.valves.zim_directory}' or KIWIX_HOME environment variable."
        
        if __event_emitter__ and self.valves.enable_status_updates:
            await __event_emitter__({
                "type": "status", 
                "data": {"description": f"Found {len(zim_files)} ZIM files, gathering information...", "done": False}
            })
        
        result_lines = [f"Found {len(zim_files)} ZIM archive files:\n"]
        
        for i, zim_file in enumerate(zim_files, 1):
            info = self._get_zim_info(zim_file)
            if "error" in info:
                result_lines.append(f"{i}. {info['filename']} - Error: {info['error']}")
            else:
                result_lines.append(
                    f"{i}. {info['filename']}\n"
                    f"   Path: {info['path']}\n"
                    f"   Articles: {info['article_count']:,}, Media: {info['media_count']:,}\n"
                    f"   Size: {info['size_mb']} MB"
                )
        
        if __event_emitter__ and self.valves.enable_status_updates:
            await __event_emitter__({
                "type": "status",
                "data": {"description": "ZIM file discovery complete", "done": True}
            })
        
        return "\n\n".join(result_lines)

    async def search_zim(self, zim_file_path: str, search_query: str, __event_emitter__=None) -> str:
        """
        Search for articles in a ZIM archive file.
        
        Args:
            zim_file_path: Path to the ZIM archive file
            search_query: Search query string
            
        Returns:
            Search results with article paths and metadata
        """
        if not self._dependencies_available:
            return "Error: libzim library is not available. Please install it with: pip install libzim>=3.5"
        
        if __event_emitter__ and self.valves.enable_status_updates:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Searching '{search_query}' in {os.path.basename(zim_file_path)}...", "done": False}
            })
        
        try:
            archive = Archive(zim_file_path)
            query = Query().set_query(search_query)
            searcher = Searcher(archive)
            search = searcher.search(query)
            search_count = search.getEstimatedMatches()
            
            if search_count == 0:
                return f"No results found for '{search_query}' in {os.path.basename(zim_file_path)}."
            
            # Limit results to prevent overwhelming responses
            results_limit = min(search_count, self.valves.max_search_results)
            search_results_objects = list(search.getResults(0, results_limit))
            
            # Extract article paths from search results
            article_paths = [result.get_path() for result in search_results_objects]
            
            if __event_emitter__ and self.valves.enable_status_updates:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": f"Found {search_count} matches, returning top {len(article_paths)}", "done": True}
                })
            
            result_lines = [
                f"Search results for '{search_query}' in {os.path.basename(zim_file_path)}:",
                f"Total matches: {search_count}, showing top {len(article_paths)} results:\n"
            ]
            
            for i, path in enumerate(article_paths, 1):
                result_lines.append(f"{i}. {path}")
            
            return "\n".join(result_lines)
            
        except FileNotFoundError:
            return f"Error: ZIM file not found at '{zim_file_path}'. Please check the path."
        except Exception as e:
            return f"Error searching ZIM file: {str(e)}"

    async def read_zim_article(self, zim_file_path: str, article_path: str, __event_emitter__=None) -> str:
        """
        Read the content of a specific article from a ZIM archive.
        
        Args:
            zim_file_path: Path to the ZIM archive file
            article_path: Path to the article within the ZIM file
            
        Returns:
            Plain text content of the article
        """
        if not self._dependencies_available:
            return "Error: libzim library is not available. Please install it with: pip install libzim>=3.5"
        
        if __event_emitter__ and self.valves.enable_status_updates:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Reading article: {article_path}", "done": False}
            })
        
        try:
            archive = Archive(zim_file_path)
            entry = archive.get_entry_by_path(article_path)
            html_content = bytes(entry.get_item().content).decode("UTF-8")
            plain_text = strip_tags(html_content, minify=True, remove_blank_lines=True)
            
            if __event_emitter__ and self.valves.enable_citations:
                await __event_emitter__({
                    "type": "citation",
                    "data": {
                        "document": [plain_text],
                        "metadata": [{
                            "date_accessed": datetime.now().isoformat(),
                            "source": f"{os.path.basename(zim_file_path)}:{article_path}",
                            "zim_file": zim_file_path,
                            "article_path": article_path
                        }],
                        "source": {
                            "name": f"{os.path.basename(zim_file_path)} - {article_path}",
                            "url": f"zim://{zim_file_path}#{article_path}"
                        }
                    }
                })
            
            if __event_emitter__ and self.valves.enable_status_updates:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": "Article content retrieved", "done": True}
                })
            
            return plain_text.strip()
            
        except FileNotFoundError:
            return f"Error: ZIM file not found at '{zim_file_path}'"
        except Exception as e:
            return f"Error reading article '{article_path}' from ZIM file '{zim_file_path}': {str(e)}"

    async def search_and_collect_zim(self, zim_file_path: str, search_query: str, __event_emitter__=None) -> str:
        """
        Search a ZIM archive and return the content of matching articles.
        This is the primary function that combines search and content retrieval.
        
        Args:
            zim_file_path: Path to the ZIM archive file
            search_query: Search query string
            
        Returns:
            Combined content from matching articles with citations
        """
        if not self._dependencies_available:
            return "Error: libzim library is not available. Please install it with: pip install libzim>=3.5"
        
        if __event_emitter__ and self.valves.enable_status_updates:
            await __event_emitter__({
                "type": "status",
                "data": {"description": f"Searching and collecting content for '{search_query}'...", "done": False}
            })
        
        try:
            # First, perform the search
            archive = Archive(zim_file_path)
            query = Query().set_query(search_query)
            searcher = Searcher(archive)
            search = searcher.search(query)
            search_count = search.getEstimatedMatches()
            
            if search_count == 0:
                return f"No results found for '{search_query}' in {os.path.basename(zim_file_path)}."
            
            # Get limited results
            results_limit = min(search_count, self.valves.max_search_results)
            search_results_objects = list(search.getResults(0, results_limit))
            article_paths = [result.get_path() for result in search_results_objects]
            
            if __event_emitter__ and self.valves.enable_status_updates:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": f"Found {search_count} matches, retrieving content from top {len(article_paths)} articles...", "done": False}
                })
            
            # Collect content from each article
            output_parts = [
                f"Search results for '{search_query}' in {os.path.basename(zim_file_path)}:",
                f"Found {search_count} total matches, showing content from top {len(article_paths)} articles:\n"
            ]
            
            for i, article_path in enumerate(article_paths, 1):
                if __event_emitter__ and self.valves.enable_status_updates:
                    await __event_emitter__({
                        "type": "status",
                        "data": {"description": f"Reading article {i} of {len(article_paths)}: {article_path}", "done": False}
                    })
                
                try:
                    entry = archive.get_entry_by_path(article_path)
                    html_content = bytes(entry.get_item().content).decode("UTF-8")
                    plain_text = strip_tags(html_content, minify=True, remove_blank_lines=True)
                    
                    output_parts.append(f"## Article {i}: {article_path}")
                    output_parts.append(plain_text.strip())
                    
                    # Emit citation for this article
                    if __event_emitter__ and self.valves.enable_citations:
                        await __event_emitter__({
                            "type": "citation",
                            "data": {
                                "document": [plain_text],
                                "metadata": [{
                                    "date_accessed": datetime.now().isoformat(),
                                    "source": f"{os.path.basename(zim_file_path)}:{article_path}",
                                    "zim_file": zim_file_path,
                                    "article_path": article_path,
                                    "search_query": search_query
                                }],
                                "source": {
                                    "name": f"{os.path.basename(zim_file_path)} - {article_path}",
                                    "url": f"zim://{zim_file_path}#{article_path}"
                                }
                            }
                        })
                    
                except Exception as e:
                    output_parts.append(f"## Article {i}: {article_path}")
                    output_parts.append(f"Error reading article: {str(e)}")
            
            if __event_emitter__ and self.valves.enable_status_updates:
                await __event_emitter__({
                    "type": "status",
                    "data": {"description": f"Content collection complete - retrieved {len(article_paths)} articles", "done": True}
                })
            
            return "\n\n".join(output_parts)
            
        except FileNotFoundError:
            return f"Error: ZIM file not found at '{zim_file_path}'. Please check the path."
        except Exception as e:
            return f"An unexpected error occurred while searching and collecting content: {str(e)}"

