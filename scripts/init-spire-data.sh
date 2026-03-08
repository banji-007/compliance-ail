#!/bin/bash

# Initialize SPIRE data directories with proper permissions
mkdir -p /opt/spire/data
chmod 755 /opt/spire/data

# Create empty database file if it doesn't exist
if [ ! -f /opt/spire/data/server.db ]; then
    touch /opt/spire/data/server.db
    chmod 644 /opt/spire/data/server.db
fi

echo "SPIRE data directory initialized"
