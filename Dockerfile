FROM ubuntu:22.04

ARG GEMINI_API_KEY=""
ENV GEMINI_API_KEY=$GEMINI_API_KEY

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.foundry/bin:/root/.cargo/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    build-essential \
    libssl-dev \
    pkg-config \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup

# Install Aderyn (Rust-based)
RUN curl --proto '=https' --tlsv1.2 -LsSf https://github.com/cyfrin/aderyn/releases/latest/download/aderyn-installer.sh | bash

# Upgrade pip
RUN python3 -m pip install --upgrade pip setuptools wheel

# Install Python security tools
RUN pip3 install solc-select slither-analyzer
RUN pip3 install mythril
RUN pip3 install halmos

# Install audit dependencies
RUN pip3 install pyyaml requests

# Install Solhint (Node-based)
RUN npm install -g solhint

# Install default Solidity version
RUN solc-select install 0.8.20 && solc-select use 0.8.20

# Copy the audit module
COPY audit/ /app/audit/

# Copy entrypoint script
COPY entrypoint.py /app/entrypoint.py

# Copy legacy orchestrator (for backwards compatibility)
COPY orchestrator.py /usr/local/bin/orchestrator.py

# Set working directory
WORKDIR /target

# Default entrypoint runs the new modular scanner
ENTRYPOINT ["python3", "/app/entrypoint.py"]
