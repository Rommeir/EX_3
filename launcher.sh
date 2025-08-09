#!/bin/bash

# Create shared directory and config
mkdir -p ./mta_shared
echo "8 8" > ./mta_shared/config.txt

# Clean up any existing containers
docker stop encrypter decrypter1 decrypter2 decrypter3 2>/dev/null || true
docker rm encrypter decrypter1 decrypter2 decrypter3 2>/dev/null || true

# Build images
echo "Building encrypter image..."
docker build -t mta-encrypter -f Dockerfile.encrypter .

echo "Building decrypter image..."
docker build -t mta-decrypter -f Dockerfile.decrypter .

# Run encrypter container
echo "Starting encrypter..."
docker run -d \
  --name encrypter \
  -v $(pwd)/mta_shared:/mnt/mta \
  -v $(pwd)/logs:/var/log \
  mta-encrypter

# Wait a bit for encrypter to start
sleep 2

# Run decrypter containers
echo "Starting decrypters..."
for i in {1..3}; do
  docker run -d \
    --name decrypter$i \
    -v $(pwd)/mta_shared:/mnt/mta \
    -v $(pwd)/logs:/var/log \
    mta-decrypter $i
done

echo "All containers started!"
echo "Monitor logs with:"
echo "  docker logs -f encrypter"
echo "  docker logs -f decrypter1"
echo "  docker logs -f decrypter2"
echo "  docker logs -f decrypter3"
echo ""
echo "Or check log files in ./logs/"
echo ""
echo "Stop all containers with:"
echo "  docker stop encrypter decrypter1 decrypter2 decrypter3"
