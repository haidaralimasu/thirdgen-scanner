FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.foundry/bin:/root/.cargo/bin:$PATH"

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


RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup

RUN curl --proto '=https' --tlsv1.2 -LsSf https://github.com/cyfrin/aderyn/releases/latest/download/aderyn-installer.sh | bash

RUN python3 -m pip install --upgrade pip

# 4. INSTALL PYTHON TOOLS
# We install them separately to avoid dependency conflicts (Backtracking)
RUN python3 -m pip install --upgrade pip setuptools wheel

# Install Slither & Utilities first
RUN pip3 install solc-select slither-analyzer

# Install Mythril (The Sniper) - Standalone to prevent numpy conflicts
RUN pip3 install mythril

RUN wget https://github.com/crytic/echidna/releases/download/v2.2.3/echidna-test-2.2.3-Ubuntu-22.04.tar.gz \
    && tar -xvf echidna-test-2.2.3-Ubuntu-22.04.tar.gz \
    && mv echidna-test /usr/local/bin/echidna \
    && chmod +x /usr/local/bin/echidna \
    && rm echidna-test-2.2.3-Ubuntu-22.04.tar.gz

# Install Halmos (Formal Verification)
RUN pip3 install halmos

RUN npm install -g solhint

RUN solc-select install 0.8.20 && solc-select use 0.8.20

COPY orchestrator.py /usr/local/bin/orchestrator.py

WORKDIR /target
ENTRYPOINT ["python3", "/usr/local/bin/orchestrator.py"]