# Nmap MCP Server

A Model Context Protocol (MCP) server that provides Nmap scanning capabilities for AI assistants and other MCP clients.

## Features

- **TCP Connect Port Scans**: Perform TCP connect scans on specified targets
- **Version Detection**: Use `-sV` to detect service versions
- **Script Scanning**: Run Nmap scripts with `-sC` or custom scripts
- **Script Search**: Search available Nmap scripts by name, category, or keyword
- **Multiple Scan Types**: Support for TCP connect, SYN, and UDP scans
- **Flexible Port Specification**: Support for port ranges, lists, top-N ports, and all ports
- **Timing Control**: Configurable timing templates (T0-T5)
- **Multiple Targets**: Scan multiple hosts or IP ranges in a single operation
- **Scan History**: Persistent storage and retrieval of scan results
- **SSE Support**: Server-Sent Events for web-based MCP clients
- **JSON Output**: Structured JSON responses for easy parsing

## Requirements

- Python 3.10+
- Nmap installed on the system
- uv package manager (recommended)

## Installation

### Using uv (Recommended)

```bash
# Clone the repository
git clone <repository-url>
cd nmap-mcp

# Run directly with uv (will install dependencies automatically)
uv run nmap_mcp.py
```

### Using pip

```bash
# Install dependencies
pip install mcp asyncio-sse python-nmap

# Run the server
python nmap_mcp.py
```

### Using Docker

```bash
# Build the container
docker build -t nmap-mcp .

# Run in SSE mode for web clients
docker run -p 3001:3001 nmap-mcp

# Run in stdio mode (for direct MCP client connection)
docker run -i nmap-mcp uv run nmap_mcp.py
```

## Usage

### Command Line Options

```bash
python nmap_mcp.py [options]

Options:
  -d, --daemon        Run in daemon mode (only available with --sse)
  --sse              Enable SSE mode for web clients
  --port PORT        Port for SSE server (default: 3001)
  --host HOST        Host for SSE server (default: localhost)
```

### Available Tools

#### 1. `tcp_scan`
Perform TCP port scans on one or more targets.

**Parameters:**
- `targets` (required): List of IP addresses, hostnames, or CIDR ranges
- `ports` (required): Port specification (e.g., "80,443", "1-1000", "all", "top-1000")
- `scan_type`: Type of scan ("connect", "syn", "udp") - default: "connect"
- `timing`: Nmap timing template ("T0" to "T5") - default: "T3"
- `skip_ping`: Skip host discovery (boolean) - default: false
- `verbose`: Enable verbose output (boolean) - default: false

**Example:**
```json
{
  "targets": ["192.168.1.1", "google.com"],
  "ports": "top-1000",
  "scan_type": "syn",
  "timing": "T4"
}
```

#### 2. `version_scan`
Perform version detection scan on specified ports.

**Parameters:**
- `targets` (required): List of targets to scan
- `ports` (required): Port specification
- `timing`: Timing template - default: "T3"
- `skip_ping`: Skip host discovery - default: false
- `verbose`: Enable verbose output - default: false

**Example:**
```json
{
  "targets": ["192.168.1.1"],
  "ports": "22,80,443",
  "timing": "T3"
}
```

#### 3. `script_scan`
Perform Nmap script scan with default or custom scripts.

**Parameters:**
- `targets` (required): List of targets to scan
- `ports` (required): Port specification
- `scripts` (required): Script specification ("default" for -sC, or specific script names)
- `timing`: Timing template - default: "T3"
- `skip_ping`: Skip host discovery - default: false
- `verbose`: Enable verbose output - default: false

**Example:**
```json
{
  "targets": ["192.168.1.1"],
  "ports": "80,443",
  "scripts": "http-enum,http-headers"
}
```

#### 4. `search_scripts`
Search available Nmap scripts by name, category, or keyword.

**Parameters:**
- `query` (required): Search query for script name, category, or keyword
- `category`: Filter by script category (optional)

**Example:**
```json
{
  "query": "http",
  "category": "discovery"
}
```

#### 5. `get_scan_history`
Retrieve scan history with optional filtering.

**Parameters:**
- `limit`: Maximum number of scans to return - default: 10
- `target_filter`: Filter scans by target (partial match)

**Example:**
```json
{
  "limit": 5,
  "target_filter": "192.168.1"
}
```

## Scan History

Scan results are automatically stored in memory and can be persisted to `scan_history.json` when the server shuts down gracefully. History includes:

- Scan ID and timestamp
- Scan type and parameters
- Complete Nmap command executed
- Raw and parsed output
- Execution time and status

## Development

### Running Tests

```bash
# Install development dependencies
uv sync --extra dev

# Run tests
uv run pytest
```

### Code Formatting

```bash
# Format code
uv run black nmap_mcp.py
uv run isort nmap_mcp.py

# Type checking
uv run mypy nmap_mcp.py
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Troubleshooting

### "Nmap is not available on this system"

Make sure Nmap is installed and accessible in your PATH:

```bash
# On Ubuntu/Debian
sudo apt-get install nmap

# On macOS
brew install nmap

# On Red Hat/CentOS
sudo yum install nmap
```

### Permission Issues

Some Nmap scan types (like SYN scans) require root privileges:

```bash
# Run with sudo if needed
sudo uv run nmap_mcp.py
```

### Port Access Issues

If running in SSE mode and can't access the web interface:

1. Check that the port (default 3001) is not blocked by firewall
2. Ensure the host binding is correct (use "0.0.0.0" for external access)
3. Verify no other service is using the same port

## Claude Desktop Configuration

To use the nmap-mcp server with Claude Desktop, you need to add it to your MCP configuration file.

### Step 1: Locate Configuration File

The Claude Desktop configuration file is located at:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### Step 2: Add Server Configuration

Edit the configuration file to include the nmap-mcp server:

```json
{
  "mcpServers": {
    "nmap-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/nmap-mcp",
        "nmap_mcp.py"
      ],
      "env": {
        "UV_PROJECT_ENVIRONMENT": "/path/to/nmap-mcp/.venv"
      }
    }
  }
}
```

**Important**: Replace `/path/to/nmap-mcp` with the actual path to your nmap-mcp installation directory.

### Step 3: Alternative Configuration (Python)

If you prefer to use Python directly instead of uv:

```json
{
  "mcpServers": {
    "nmap-mcp": {
      "command": "python",
      "args": [
        "/path/to/nmap-mcp/nmap_mcp.py"
      ],
      "env": {
        "PYTHONPATH": "/path/to/nmap-mcp"
      }
    }
  }
}
```

### Step 4: Restart Claude Desktop

After saving the configuration file, restart Claude Desktop for the changes to take effect.

### Step 5: Verify Connection

Once Claude Desktop restarts, you should be able to use nmap scanning capabilities in your conversations. You can test by asking Claude to:

- "Scan the top 100 ports on scanme.nmap.org"
- "Search for HTTP-related Nmap scripts"
- "Show me the scan history"

### Configuration Examples

#### For Development (Local Installation)
```json
{
  "mcpServers": {
    "nmap-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/Users/username/Dev/nmap-mcp",
        "nmap_mcp.py"
      ]
    }
  }
}
```

#### For System Installation
```json
{
  "mcpServers": {
    "nmap-mcp": {
      "command": "nmap-mcp",
      "args": []
    }
  }
}
```

#### With Custom Timing (Faster Scans)
```json
{
  "mcpServers": {
    "nmap-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/nmap-mcp",
        "nmap_mcp.py"
      ],
      "env": {
        "NMAP_DEFAULT_TIMING": "T4"
      }
    }
  }
}
```

### Troubleshooting Claude Desktop Integration

#### Server Not Found
- Verify the path to nmap-mcp directory is correct
- Ensure uv is installed and accessible in your PATH
- Check that nmap_mcp.py has execute permissions

#### Permission Denied
- Make sure Claude Desktop has permission to execute the server
- For SYN scans, you may need to run Claude Desktop with elevated privileges
- Consider using TCP connect scans which don't require root access

#### Connection Timeout
- Check that Nmap is installed and accessible
- Verify network connectivity for target scanning
- Try running the server manually to test functionality:
  ```bash
  cd /path/to/nmap-mcp
  uv run nmap_mcp.py
  ```

#### Configuration Validation
You can validate your configuration by checking the Claude Desktop logs or testing the server independently:

```bash
# Test server startup
cd /path/to/nmap-mcp
python test_setup.py

# Test MCP communication
python example_client.py
```
