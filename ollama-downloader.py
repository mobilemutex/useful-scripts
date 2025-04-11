#!/usr/bin/env python3
import os
import requests
import json
import hashlib
import argparse
from pathlib import Path
import time

def download_file(url, destination, headers=None):
    """Download a file from a URL with progress reporting."""
    if headers is None:
        headers = {}
    
    response = requests.get(url, stream=True, headers=headers)
    response.raise_for_status()
    
    total_size = int(response.headers.get('content-length', 0))
    block_size = 8192
    downloaded = 0
    start_time = time.time()
    
    with open(destination, 'wb') as file:
        for chunk in response.iter_content(chunk_size=block_size):
            if chunk:
                file.write(chunk)
                downloaded += len(chunk)
                
                # Update progress
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    elapsed_time = time.time() - start_time
                    if elapsed_time > 0:
                        speed = downloaded / (1024 * 1024 * elapsed_time)  # MB/s
                        print(f"\rDownloading: {percent:.2f}% of {total_size / (1024 * 1024):.2f} MB at {speed:.2f} MB/s", end='')
    
    print()  # New line after download completes

def verify_sha256(file_path, expected_hash):
    """Verify the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    computed_hash = sha256_hash.hexdigest()
    return computed_hash == expected_hash

def get_model_manifest(model_name, model_tag="latest"):
    """Get the model manifest from the Ollama registry."""
    registry_url = "https://registry.ollama.ai/v2"
    manifest_url = f"{registry_url}/library/{model_name}/manifests/{model_tag}"
    
    headers = {
        "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json"
    }
    
    try:
        response = requests.get(manifest_url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching manifest: {e}")
        return None

def download_model(model_name, model_tag="latest", output_dir=None, force=False):
    """
    Download an Ollama model and its blobs.
    
    Args:
        model_name: Name of the model to download (e.g., 'llama3')
        model_tag: Tag of the model to download (default: 'latest')
        output_dir: Directory to save the model files to (default: ~/.ollama/models)
        force: Whether to force re-download of existing files (default: False)
    """
    if output_dir is None:
        # Default to ~/.ollama structure
        home = Path.home()
        output_dir = home / ".ollama" / "models"
    else:
        output_dir = Path(output_dir)
    
    # Create directories
    blobs_dir = output_dir / "blobs"
    manifest_dir = output_dir / "manifests" / "registry.ollama.ai" / "library" / model_name
    if model_tag != "latest":
        manifest_dir = manifest_dir / model_tag
    else:
        manifest_dir = manifest_dir / "latest"
    
    os.makedirs(blobs_dir, exist_ok=True)
    os.makedirs(manifest_dir, exist_ok=True)
    
    print(f"Fetching manifest for {model_name}:{model_tag}")
    manifest = get_model_manifest(model_name, model_tag)
    if not manifest:
        print("Failed to fetch manifest. Exiting.")
        return
    
    # Save manifest
    manifest_path = manifest_dir / "manifest"
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Manifest saved to {manifest_path}")
    
    # Download blobs based on the manifest
    registry_url = "https://registry.ollama.ai/v2"
    
    # Handle both config and layers
    blobs_to_download = []
    
    # Add config if present
    if 'config' in manifest and 'digest' in manifest['config']:
        blobs_to_download.append(manifest['config']['digest'])
    
    # Add layers
    if 'layers' in manifest:
        for layer in manifest['layers']:
            if 'digest' in layer:
                blobs_to_download.append(layer['digest'])
    
    print(f"Found {len(blobs_to_download)} blobs to download")
    
    # Calculate total size if available
    total_size = 0
    for layer in manifest.get('layers', []):
        if 'size' in layer:
            total_size += layer['size']
    
    if total_size > 0:
        print(f"Total download size: {total_size / (1024 * 1024):.2f} MB")
    
    for i, digest in enumerate(blobs_to_download):
        if not digest.startswith('sha256:'):
            print(f"Warning: Blob {i} has unexpected digest format: {digest}")
            continue
        
        # Extract hash from digest
        blob_hash = digest.split(':')[1]
        blob_path = blobs_dir / f"sha256-{blob_hash}"
        
        # Skip if blob already exists and is valid (unless force is True)
        if not force and blob_path.exists():
            print(f"Checking existing blob {blob_hash}...")
            if verify_sha256(blob_path, blob_hash):
                print(f"Blob {blob_hash} already exists and is valid")
                continue
            else:
                print(f"Blob {blob_hash} exists but is invalid. Re-downloading...")
        
        # Construct URL for the blob
        blob_url = f"{registry_url}/library/{model_name}/blobs/{digest}"
        
        print(f"Downloading blob {i+1}/{len(blobs_to_download)}: {blob_hash}")
        
        # Add retry mechanism
        max_retries = 3
        retry_delay = 5  # seconds
        
        for retry in range(max_retries):
            try:
                download_file(blob_url, blob_path)
                
                # Verify downloaded blob
                if verify_sha256(blob_path, blob_hash):
                    print(f"Blob {blob_hash} verified successfully")
                    break
                else:
                    print(f"Warning: Blob {blob_hash} failed verification")
                    if retry < max_retries - 1:
                        print(f"Retrying in {retry_delay} seconds... (Attempt {retry + 2}/{max_retries})")
                        time.sleep(retry_delay)
            except Exception as e:
                print(f"Error downloading blob {blob_hash}: {e}")
                if retry < max_retries - 1:
                    print(f"Retrying in {retry_delay} seconds... (Attempt {retry + 2}/{max_retries})")
                    time.sleep(retry_delay)
    
    print(f"Model {model_name}:{model_tag} download complete")
    print(f"Files are saved to:")
    print(f"  - Blobs: {blobs_dir}")
    print(f"  - Manifest: {manifest_path}")
    print()
    print("To use this model with Ollama, ensure these files are in the correct Ollama directories.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download Ollama models directly without using the Ollama binary")
    parser.add_argument("model", help="Model name (e.g., 'llama3')")
    parser.add_argument("--tag", default="latest", help="Model tag (default: 'latest')")
    parser.add_argument("--output", help="Output directory (default: ~/.ollama/models)")
    parser.add_argument("--force", action="store_true", help="Force re-download of existing files")
    
    args = parser.parse_args()
    
    download_model(args.model, args.tag, args.output, args.force)
