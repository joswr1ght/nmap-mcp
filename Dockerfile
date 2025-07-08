# Minimal Dockerfile for nmap-mcp server
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Set working directory
WORKDIR /app

# Copy project files
COPY nmap_mcp.py .
COPY pyproject.toml .
COPY LICENSE .
COPY README.md .

# Install Python dependencies (create lockfile and install)
RUN uv sync

# Expose default SSE port
EXPOSE 3001

# Default command runs in foreground mode for container use
# Bind to 0.0.0.0 so the container can accept connections from outside
CMD ["uv", "run", "nmap_mcp.py", "--sse", "--host", "0.0.0.0", "--port", "3001"]
