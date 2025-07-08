#!/usr/bin/env python3
"""
Nmap MCP Server

A Model Context Protocol server that provides Nmap scanning capabilities.

/// script
requires-python = ">=3.10"
dependencies = [
    "mcp",
    "sse-starlette",
    "python-nmap",
    "starlette",
    "uvicorn",
]
///
"""

import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union
import argparse
import signal

from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListResourcesRequest,
    ListResourcesResult,
    ListToolsRequest,
    ListToolsResult,
    ReadResourceRequest,
    ReadResourceResult,
    Resource,
    TextContent,
    Tool,
)

try:
    from starlette.applications import Starlette
    from starlette.responses import Response
    from sse_starlette.sse import EventSourceResponse
    import uvicorn
    SSE_AVAILABLE = True
except ImportError:
    SSE_AVAILABLE = False

# Global scan history storage
scan_history: List[Dict[str, Any]] = []

# Global server instance for signal handling
server_instance = None

logger = logging.getLogger(__name__)


class NmapMCPServer:
    def __init__(self):
        self.server = Server("nmap-mcp")
        self.scan_counter = 0

        # Register handlers
        self.server.list_tools = self.list_tools
        self.server.call_tool = self.call_tool
        self.server.list_resources = self.list_resources
        self.server.read_resource = self.read_resource

    async def list_tools(self) -> ListToolsResult:
        """List available Nmap tools."""
        tools = [
            Tool(
                name="tcp_scan",
                description="Perform TCP port scans on one or more targets",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of IP addresses, hostnames, or CIDR ranges to scan"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Port specification (e.g., '80,443', '1-1000', 'all', or 'top-N' where N is number)"
                        },
                        "scan_type": {
                            "type": "string",
                            "enum": ["connect", "syn", "udp"],
                            "default": "connect",
                            "description": "Type of TCP scan to perform"
                        },
                        "timing": {
                            "type": "string",
                            "enum": ["T0", "T1", "T2", "T3", "T4", "T5"],
                            "default": "T3",
                            "description": "Nmap timing template"
                        },
                        "skip_ping": {
                            "type": "boolean",
                            "default": False,
                            "description": "Skip host discovery (use -Pn)"
                        },
                        "verbose": {
                            "type": "boolean",
                            "default": False,
                            "description": "Enable verbose output"
                        }
                    },
                    "required": ["targets", "ports"]
                }
            ),
            Tool(
                name="version_scan",
                description="Perform version detection scan on specified ports",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of IP addresses, hostnames, or CIDR ranges to scan"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Port specification (e.g., '80,443', '1-1000', 'top-1000')"
                        },
                        "timing": {
                            "type": "string",
                            "enum": ["T0", "T1", "T2", "T3", "T4", "T5"],
                            "default": "T3",
                            "description": "Nmap timing template"
                        },
                        "skip_ping": {
                            "type": "boolean",
                            "default": False,
                            "description": "Skip host discovery (use -Pn)"
                        },
                        "verbose": {
                            "type": "boolean",
                            "default": False,
                            "description": "Enable verbose output"
                        }
                    },
                    "required": ["targets", "ports"]
                }
            ),
            Tool(
                name="script_scan",
                description="Perform Nmap script scan with default or custom scripts",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of IP addresses, hostnames, or CIDR ranges to scan"
                        },
                        "ports": {
                            "type": "string",
                            "description": "Port specification (e.g., '80,443', '1-1000', 'top-1000')"
                        },
                        "scripts": {
                            "type": "string",
                            "description": "Script specification ('default' for -sC, or specific script names)"
                        },
                        "timing": {
                            "type": "string",
                            "enum": ["T0", "T1", "T2", "T3", "T4", "T5"],
                            "default": "T3",
                            "description": "Nmap timing template"
                        },
                        "skip_ping": {
                            "type": "boolean",
                            "default": False,
                            "description": "Skip host discovery (use -Pn)"
                        },
                        "verbose": {
                            "type": "boolean",
                            "default": False,
                            "description": "Enable verbose output"
                        }
                    },
                    "required": ["targets", "ports", "scripts"]
                }
            ),
            Tool(
                name="search_scripts",
                description="Search available Nmap scripts by name, category, or keyword",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query for script name, category, or keyword"
                        },
                        "category": {
                            "type": "string",
                            "description": "Filter by script category (auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln)"
                        }
                    },
                    "required": ["query"]
                }
            ),
            Tool(
                name="get_scan_history",
                description="Retrieve scan history with optional filtering",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "default": 10,
                            "description": "Maximum number of scans to return"
                        },
                        "target_filter": {
                            "type": "string",
                            "description": "Filter scans by target (partial match)"
                        }
                    }
                }
            )
        ]
        return ListToolsResult(tools=tools)

    async def call_tool(self, request: CallToolRequest) -> CallToolResult:
        """Handle tool calls."""
        try:
            if request.name == "tcp_scan":
                return await self._tcp_scan(request.arguments)
            elif request.name == "version_scan":
                return await self._version_scan(request.arguments)
            elif request.name == "script_scan":
                return await self._script_scan(request.arguments)
            elif request.name == "search_scripts":
                return await self._search_scripts(request.arguments)
            elif request.name == "get_scan_history":
                return await self._get_scan_history(request.arguments)
            else:
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Unknown tool: {request.name}")]
                )
        except Exception as e:
            logger.error(f"Error in tool {request.name}: {e}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Error: {str(e)}")]
            )

    async def _check_nmap_availability(self) -> bool:
        """Check if nmap is available on the system."""
        try:
            result = subprocess.run(["nmap", "--version"],
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _build_nmap_command(self, targets: List[str], ports: str,
                           scan_type: str = "connect", timing: str = "T3",
                           skip_ping: bool = False, verbose: bool = False,
                           version_scan: bool = False, scripts: Optional[str] = None) -> List[str]:
        """Build nmap command with specified options."""
        cmd = ["nmap"]

        # Scan type
        if scan_type == "syn":
            cmd.append("-sS")
        elif scan_type == "udp":
            cmd.append("-sU")
        else:  # connect
            cmd.append("-sT")

        # Version detection
        if version_scan:
            cmd.append("-sV")

        # Scripts
        if scripts:
            if scripts.lower() == "default":
                cmd.append("-sC")
            else:
                cmd.extend(["--script", scripts])

        # Timing
        cmd.append(f"-{timing}")

        # Skip ping
        if skip_ping:
            cmd.append("-Pn")

        # Verbose
        if verbose:
            cmd.append("-v")

        # Port specification
        if ports.lower() == "all":
            cmd.append("-p-")
        elif ports.lower().startswith("top-"):
            try:
                top_n = int(ports[4:])
                cmd.extend(["--top-ports", str(top_n)])
            except ValueError:
                cmd.extend(["--top-ports", "1000"])
        else:
            cmd.extend(["-p", ports])

        # Output format
        cmd.extend(["-oX", "-"])  # XML output to stdout

        # Targets
        cmd.extend(targets)

        return cmd

    async def _execute_nmap(self, cmd: List[str]) -> Dict[str, Any]:
        """Execute nmap command and parse results."""
        if not await self._check_nmap_availability():
            raise Exception("Nmap is not available on this system. Please install nmap to continue.")

        start_time = time.time()

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise Exception(f"Nmap failed with return code {process.returncode}: {stderr.decode()}")

            # Parse XML output (simplified parsing)
            result = {
                "command": " ".join(cmd),
                "return_code": process.returncode,
                "execution_time": time.time() - start_time,
                "timestamp": datetime.now().isoformat(),
                "raw_output": stdout.decode(),
                "error_output": stderr.decode() if stderr else None,
                "parsed_results": self._parse_nmap_xml(stdout.decode())
            }

            return result

        except asyncio.TimeoutError:
            raise Exception("Nmap scan timed out")
        except Exception as e:
            raise Exception(f"Failed to execute nmap: {str(e)}")

    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """Parse nmap XML output (simplified parsing)."""
        # This is a simplified parser - in production you'd want to use proper XML parsing
        import re

        parsed = {
            "hosts": [],
            "scan_stats": {}
        }

        # Extract basic host information
        host_pattern = r'<host.*?</host>'
        hosts = re.findall(host_pattern, xml_output, re.DOTALL)

        for host_xml in hosts:
            host_info = {"addresses": [], "ports": [], "hostnames": []}

            # Extract IP addresses
            ip_pattern = r'<address addr="([^"]+)" addrtype="([^"]+)"'
            addresses = re.findall(ip_pattern, host_xml)
            host_info["addresses"] = [{"addr": addr, "type": addr_type} for addr, addr_type in addresses]

            # Extract ports
            port_pattern = r'<port protocol="([^"]+)" portid="([^"]+)".*?<state state="([^"]+)"'
            ports = re.findall(port_pattern, host_xml, re.DOTALL)
            host_info["ports"] = [{"protocol": prot, "port": port, "state": state}
                                for prot, port, state in ports]

            parsed["hosts"].append(host_info)

        return parsed

    async def _tcp_scan(self, args: Dict[str, Any]) -> CallToolResult:
        """Perform TCP scan."""
        targets = args["targets"]
        ports = args["ports"]
        scan_type = args.get("scan_type", "connect")
        timing = args.get("timing", "T3")
        skip_ping = args.get("skip_ping", False)
        verbose = args.get("verbose", False)

        cmd = self._build_nmap_command(
            targets, ports, scan_type, timing, skip_ping, verbose
        )

        result = await self._execute_nmap(cmd)

        # Store in history
        self.scan_counter += 1
        scan_record = {
            "scan_id": self.scan_counter,
            "scan_type": "tcp_scan",
            "targets": targets,
            "ports": ports,
            "options": {
                "scan_type": scan_type,
                "timing": timing,
                "skip_ping": skip_ping,
                "verbose": verbose
            },
            "result": result
        }
        scan_history.append(scan_record)

        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )

    async def _version_scan(self, args: Dict[str, Any]) -> CallToolResult:
        """Perform version detection scan."""
        targets = args["targets"]
        ports = args["ports"]
        timing = args.get("timing", "T3")
        skip_ping = args.get("skip_ping", False)
        verbose = args.get("verbose", False)

        cmd = self._build_nmap_command(
            targets, ports, "connect", timing, skip_ping, verbose, version_scan=True
        )

        result = await self._execute_nmap(cmd)

        # Store in history
        self.scan_counter += 1
        scan_record = {
            "scan_id": self.scan_counter,
            "scan_type": "version_scan",
            "targets": targets,
            "ports": ports,
            "options": {
                "timing": timing,
                "skip_ping": skip_ping,
                "verbose": verbose
            },
            "result": result
        }
        scan_history.append(scan_record)

        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )

    async def _script_scan(self, args: Dict[str, Any]) -> CallToolResult:
        """Perform script scan."""
        targets = args["targets"]
        ports = args["ports"]
        scripts = args["scripts"]
        timing = args.get("timing", "T3")
        skip_ping = args.get("skip_ping", False)
        verbose = args.get("verbose", False)

        cmd = self._build_nmap_command(
            targets, ports, "connect", timing, skip_ping, verbose, scripts=scripts
        )

        result = await self._execute_nmap(cmd)

        # Store in history
        self.scan_counter += 1
        scan_record = {
            "scan_id": self.scan_counter,
            "scan_type": "script_scan",
            "targets": targets,
            "ports": ports,
            "scripts": scripts,
            "options": {
                "timing": timing,
                "skip_ping": skip_ping,
                "verbose": verbose
            },
            "result": result
        }
        scan_history.append(scan_record)

        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )

    async def _search_scripts(self, args: Dict[str, Any]) -> CallToolResult:
        """Search available Nmap scripts."""
        query = args["query"]
        category = args.get("category")

        try:
            # Get script help
            cmd = ["nmap", "--script-help", "all"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise Exception(f"Failed to get script help: {stderr.decode()}")

            script_help = stdout.decode()

            # Parse and filter scripts
            scripts = self._parse_script_help(script_help, query, category)

            result = {
                "query": query,
                "category_filter": category,
                "total_found": len(scripts),
                "scripts": scripts
            }

            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, indent=2))]
            )

        except Exception as e:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Error searching scripts: {str(e)}")]
            )

    def _parse_script_help(self, script_help: str, query: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Parse nmap script help output and filter by query/category."""
        scripts = []
        current_script = None

        lines = script_help.split('\n')

        for line in lines:
            line = line.strip()

            # New script entry
            if line and not line.startswith(' ') and not line.startswith('\t'):
                if current_script:
                    scripts.append(current_script)

                current_script = {
                    "name": line,
                    "description": "",
                    "categories": []
                }
            elif current_script and line:
                # Description or categories
                if line.startswith('Categories:'):
                    cats = line.replace('Categories:', '').strip().split()
                    current_script["categories"] = cats
                else:
                    current_script["description"] += line + " "

        if current_script:
            scripts.append(current_script)

        # Filter scripts
        filtered_scripts = []
        query_lower = query.lower()

        for script in scripts:
            match = False

            # Check name match
            if query_lower in script["name"].lower():
                match = True

            # Check description match
            if query_lower in script["description"].lower():
                match = True

            # Check category match
            if category:
                if category.lower() in [cat.lower() for cat in script["categories"]]:
                    match = True
            else:
                # Check if query matches any category
                for cat in script["categories"]:
                    if query_lower in cat.lower():
                        match = True
                        break

            if match:
                filtered_scripts.append(script)

        return filtered_scripts

    async def _get_scan_history(self, args: Dict[str, Any]) -> CallToolResult:
        """Get scan history with optional filtering."""
        limit = args.get("limit", 10)
        target_filter = args.get("target_filter")

        filtered_history = scan_history

        if target_filter:
            filtered_history = [
                scan for scan in scan_history
                if any(target_filter.lower() in target.lower() for target in scan["targets"])
            ]

        # Get most recent scans
        recent_scans = filtered_history[-limit:] if limit else filtered_history

        result = {
            "total_scans": len(scan_history),
            "filtered_count": len(filtered_history),
            "returned_count": len(recent_scans),
            "scans": recent_scans
        }

        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )

    async def list_resources(self) -> ListResourcesResult:
        """List available resources."""
        resources = [
            Resource(
                uri="scan://history",
                name="Scan History",
                mimeType="application/json",
                description="Complete scan history"
            )
        ]
        return ListResourcesResult(resources=resources)

    async def read_resource(self, request: ReadResourceRequest) -> ReadResourceResult:
        """Read a resource."""
        if request.uri == "scan://history":
            content = json.dumps(scan_history, indent=2)
            return ReadResourceResult(
                contents=[TextContent(type="text", text=content)]
            )
        else:
            raise ValueError(f"Unknown resource: {request.uri}")


async def create_sse_server(nmap_server: 'NmapMCPServer', host: str, port: int):
    """Create a simple SSE server for web-based MCP clients."""
    if not SSE_AVAILABLE:
        raise Exception("SSE dependencies not available. Install starlette and sse-starlette.")

    app = Starlette()

    async def sse_endpoint(request):
        async def event_generator():
            # Send MCP initialization response
            yield {
                "event": "message",
                "data": json.dumps({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {},
                            "resources": {}
                        },
                        "serverInfo": {
                            "name": "nmap-mcp",
                            "version": "1.0.0"
                        }
                    }
                })
            }

            # Send tools list
            tools = await nmap_server.list_tools()
            yield {
                "event": "message",
                "data": json.dumps({
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                    "params": {}
                })
            }

            # Keep connection alive with minimal heartbeat
            while True:
                await asyncio.sleep(30)  # Reduced frequency
                yield {
                    "event": "ping",
                    "data": ""
                }

        return EventSourceResponse(event_generator())

    # Add MCP JSON-RPC endpoint for handling requests
    async def mcp_rpc_endpoint(request):
        try:
            body = await request.json()

            # Handle different MCP methods
            if body.get("method") == "tools/list":
                tools = await nmap_server.list_tools()
                response = {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "result": {
                        "tools": [
                            {
                                "name": tool.name,
                                "description": tool.description,
                                "inputSchema": tool.inputSchema
                            }
                            for tool in tools.tools
                        ]
                    }
                }
            elif body.get("method") == "tools/call":
                params = body.get("params", {})
                request_obj = CallToolRequest(
                    name=params.get("name"),
                    arguments=params.get("arguments", {})
                )
                result = await nmap_server.call_tool(request_obj)
                response = {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "result": {
                        "content": [
                            {
                                "type": content.type,
                                "text": content.text
                            }
                            for content in result.content
                        ]
                    }
                }
            elif body.get("method") == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {},
                            "resources": {}
                        },
                        "serverInfo": {
                            "name": "nmap-mcp",
                            "version": "1.0.0"
                        }
                    }
                }
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": body.get("id"),
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {body.get('method')}"
                    }
                }

            return Response(
                json.dumps(response),
                media_type="application/json"
            )

        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": body.get("id") if 'body' in locals() else None,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
            return Response(
                json.dumps(error_response),
                media_type="application/json",
                status_code=500
            )

    app.add_route("/sse", sse_endpoint)
    app.add_route("/mcp", mcp_rpc_endpoint, methods=["POST"])

    # Add a simple info endpoint
    async def info_endpoint(request):
        tools = await nmap_server.list_tools()
        return Response(
            json.dumps({
                "server": "nmap-mcp",
                "version": "1.0.0",
                "available_tools": [tool.name for tool in tools.tools]
            }),
            media_type="application/json"
        )

    app.add_route("/info", info_endpoint)

    return app


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    logger.info(f"Received signal {signum}, shutting down...")

    # Save scan history before shutdown
    try:
        with open("scan_history.json", "w") as f:
            json.dump(scan_history, f, indent=2)
        logger.info("Scan history saved to scan_history.json")
    except Exception as e:
        logger.error(f"Failed to save scan history: {e}")

    # Force exit immediately
    os._exit(0)


async def main():
    global server_instance

    parser = argparse.ArgumentParser(description="Nmap MCP Server")
    parser.add_argument("-f", "--foreground", action="store_true",
                       help="Run in foreground mode (default is daemon)")
    parser.add_argument("--sse", action="store_true",
                       help="Enable SSE mode for web clients")
    parser.add_argument("--port", type=int, default=3001,
                       help="Port for SSE server (default: 3001)")
    parser.add_argument("--host", default="localhost",
                       help="Host for SSE server (default: localhost)")

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Load scan history if exists
    try:
        if os.path.exists("scan_history.json"):
            with open("scan_history.json", "r") as f:
                scan_history.extend(json.load(f))
            logger.info(f"Loaded {len(scan_history)} scans from history")
    except Exception as e:
        logger.warning(f"Failed to load scan history: {e}")

    # Create server instance
    nmap_server = NmapMCPServer()
    server_instance = nmap_server

    if args.sse:
        # Run SSE server
        if not SSE_AVAILABLE:
            logger.error("SSE mode requires starlette and sse-starlette packages")
            sys.exit(1)

        logger.info(f"Starting Nmap MCP Server in SSE mode on {args.host}:{args.port}")
        app = await create_sse_server(nmap_server, args.host, args.port)

        config = uvicorn.Config(
            app,
            host=args.host,
            port=args.port,
            log_level="info"
        )
        server = uvicorn.Server(config)
        await server.serve()
    else:
        # Run stdio server
        logger.info("Starting Nmap MCP Server in stdio mode")
        if not args.foreground:
            logger.info("Running in daemon mode (use -f for foreground)")

        try:
            async with stdio_server() as (read_stream, write_stream):
                await nmap_server.server.run(
                    read_stream, write_stream, InitializationOptions(
                        server_name="nmap-mcp",
                        server_version="1.0.0",
                        capabilities=nmap_server.server.get_capabilities(
                            notification_options=None,
                            experimental_capabilities=None,
                        ),
                    )
                )
        except asyncio.CancelledError:
            logger.info("Server shutdown completed")
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise


if __name__ == "__main__":
    asyncio.run(main())
