#!/bin/bash
set -e

# Run any initialization steps here (e.g., dynamic config generation or permissions setup)
echo "Starting initialization script..."

# Execute CMD passed from Dockerfile (supervisord)
exec "$@"
