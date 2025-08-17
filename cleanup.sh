#!/bin/bash

# Stop and remove containers
echo "Stopping containers..."
docker stop encrypter decrypter1 decrypter2 decrypter3 2>/dev/null || true
docker rm encrypter decrypter1 decrypter2 decrypter3 2>/dev/null || true

# Clean up shared directory
rm -rf ./mta_shared
rm -rf ./logs

echo "Cleanup complete!"