nmap-mcp will use [Nmap](https://nmap.org) to scan and enumerate one or more systems identified by IP addresses or hostnames.

Features:

+ Support for TCP connect port scans
+ Support to use the Nmap top 1000 most common ports, or any top N ports using `--top-ports`
+ Support to scan explicitly identified ports by range or list
+ Support to scan all ports
+ Support to perform a version scan using `-sV`
+ Support to perform a script scan using `-sC`
+ Support to perform a script scan using a specified script with `--script`
+ Support to enumerate a list of available scripts with `--script-help all`
+ As an MCP server, Nmap-mcp supports SSE to provide search tools to MCP clients
+ Run in the foreground or as a daemon
+ nmap-mcp is a single file for ease of deployment
+ Uses uv for Python package management and running the server with inline metadata for `uv run` without additional package configuration
+ Defines a `pyproject.toml` file for uv packaging
+ Minimal Dockerfile to simply deployment as an MCP server
