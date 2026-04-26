#!/bin/bash

# Deployment configuration
REMOTE_HOST="192.168.31.251"
REMOTE_USER="pi2" 
REMOTE_PASSWORD="12345678"
REMOTE_DIR="~/pyBumbleMesh"

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    echo "sshpass could not be found. Please install it (e.g., brew install sshpass)"
    exit 1
fi

echo "Deploying to $REMOTE_USER@$REMOTE_HOST..."

# Sync files using sshpass
# -e 'ssh -o StrictHostKeyChecking=no' handles the fingerprint prompt
sshpass -p "$REMOTE_PASSWORD" rsync -avz -e 'ssh -o StrictHostKeyChecking=no' \
    --exclude '.venv' \
    --exclude '.git' \
    --exclude 'bluez-5.86' \
    --exclude '__pycache__' \
    ./ $REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR

# Setup environment on the Pi using sshpass
sshpass -p "$REMOTE_PASSWORD" ssh -o StrictHostKeyChecking=no $REMOTE_USER@$REMOTE_HOST << EOF
    cd $REMOTE_DIR
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
    fi
    source .venv/bin/activate
    pip install -r requirements.txt
    pip install -e .
    echo "Deployment complete."
EOF
