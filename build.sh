#!/bin/bash

# Build Docker images
echo "Building encrypter image..."
docker build -t mta-encrypter -f Dockerfile.encrypter .

echo "Building decrypter image..."
docker build -t mta-decrypter -f Dockerfile.decrypter .

echo "Build complete!"

# cleanup.sh
#!/bin/bash

# Stop and remove containers
echo "Stopping containers..."
docker stop encrypter decrypter1 decrypter2 decrypter3 2>/dev/null || true
docker rm encrypter decrypter1 decrypter2 decrypter3 2>/dev/null || true

# Clean up shared directory
rm -rf ./mta_shared
rm -rf ./logs

echo "Cleanup complete!"
