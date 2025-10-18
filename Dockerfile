# Simple Dockerfile for Seccomp Sandbox Project
FROM ubuntu:22.04

# Install required packages
RUN apt-get update && apt-get install -y \
    gcc \
    make \
    strace \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Build the project
RUN make all

# Default command
CMD ["/bin/bash"]
