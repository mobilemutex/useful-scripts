#!/bin/bash

# Script to load Docker images from tar.gz files, retag them with a local registry URL, and push them

# Display usage information
display_usage() {
    echo "Usage: $0 <folder_path> <registry_url>"
    echo
    echo "<folder_path>    Path to the folder containing Docker image tar.gz files"
    echo "<registry_url>   URL of the local registry to push images to (e.g., localhost:5000)"
    echo
    echo "Example: $0 ./docker-images localhost:5000"
}

# Check if required arguments are provided
if [ $# -lt 2 ]; then
    display_usage
    exit 1
fi

FOLDER_PATH=$1
REGISTRY_URL=$2

# Check if folder exists
if [ ! -d "$FOLDER_PATH" ]; then
    echo "Error: Folder '$FOLDER_PATH' does not exist"
    exit 1
fi

# Find all tar.gz files in the specified folder
echo "Looking for Docker image archives in $FOLDER_PATH..."
files=$(find "$FOLDER_PATH" -name "*.tar.gz")

# Check if any files were found
if [ -z "$files" ]; then
    echo "No .tar.gz files found in $FOLDER_PATH"
    exit 1
fi

# Process each file
for file in $files; do
    echo "Processing $file..."
    
    # Load the Docker image
    echo "Loading image from $file..."
    LOAD_OUTPUT=$(gunzip -c "$file" | docker load)
    echo "Load output: $LOAD_OUTPUT"
    
    # Extract the repository and tag from the output
    IMAGE_INFO=""
    
    # Pattern 1: "Loaded image: name:tag"
    if [[ $LOAD_OUTPUT =~ Loaded\ image:\ ([^[:space:]]+) ]]; then
        IMAGE_INFO="${BASH_REMATCH[1]}"
    # Pattern 2: Try to extract image ID if present
    elif [[ $LOAD_OUTPUT =~ sha256:([a-f0-9]+) ]]; then
        SHA256="${BASH_REMATCH[1]}"
        # Get image info using the SHA256
        IMAGE_INFO=$(docker images --format "{{.Repository}}:{{.Tag}}" --filter "id=sha256:$SHA256" | head -n 1)
    fi
    
    # Check if we got a valid image info
    if [ -z "$IMAGE_INFO" ]; then
        echo "Warning: Could not extract image information from $file. Please tag it manually."
        continue
    fi
    
    # Split the image info into name and tag
    if [[ $IMAGE_INFO == *":"* ]]; then
        # Image has a tag
        IMAGE_NAME=$(echo "$IMAGE_INFO" | cut -d':' -f1)
        IMAGE_TAG=$(echo "$IMAGE_INFO" | cut -d':' -f2)
    else
        # Image has no tag, use 'latest'
        IMAGE_NAME=$IMAGE_INFO
        IMAGE_TAG="latest"
    fi
    
    echo "Loaded image: $IMAGE_NAME:$IMAGE_TAG"
    
    # Create the new tag with the registry URL
    NEW_TAG="$REGISTRY_URL/$IMAGE_NAME:$IMAGE_TAG"
    echo "Retagging image as: $NEW_TAG"
    docker tag "$IMAGE_NAME:$IMAGE_TAG" "$NEW_TAG"
    
    # Push the image to the registry
    echo "Pushing image to registry: $NEW_TAG"
    docker push "$NEW_TAG"
    
    echo "Completed processing $file"
    echo "-----------------------------------"
done

echo "All Docker images have been processed."
