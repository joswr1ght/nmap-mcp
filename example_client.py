#!/usr/bin/env python3
"""
Example MCP client for nmap-mcp server.

This demonstrates how to connect to and use the nmap-mcp server.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add the current directory to the Python path to import nmap_mcp
sys.path.insert(0, str(Path(__file__).parent))

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("MCP client libraries not installed. Install with: uv add mcp")
    sys.exit(1)


async def demonstrate_tcp_scan():
    """Demonstrate TCP scanning capabilities."""
    print("=== TCP Scan Demo ===")

    server_params = StdioServerParameters(
        command="uv",
        args=["run", "nmap_mcp.py", "-f"]
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                print("Performing TCP scan on scanme.nmap.org...")

                result = await session.call_tool(
                    "tcp_scan",
                    {
                        "targets": ["scanme.nmap.org"],
                        "ports": "top-10",
                        "scan_type": "connect",
                        "timing": "T3"
                    }
                )

                scan_result = json.loads(result.content[0].text)
                print(f"Scan completed in {scan_result['execution_time']:.2f} seconds")
                print(f"Command executed: {scan_result['command']}")
                print(f"Hosts found: {len(scan_result['parsed_results']['hosts'])}")

                return True

    except Exception as e:
        print(f"Error during TCP scan demo: {e}")
        return False


async def demonstrate_script_search():
    """Demonstrate script search capabilities."""
    print("\n=== Script Search Demo ===")

    server_params = StdioServerParameters(
        command="uv",
        args=["run", "nmap_mcp.py", "-f"]
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                print("Searching for HTTP-related scripts...")

                result = await session.call_tool(
                    "search_scripts",
                    {
                        "query": "http",
                        "category": "discovery"
                    }
                )

                search_result = json.loads(result.content[0].text)
                print(f"Found {search_result['total_found']} HTTP discovery scripts")

                # Show first few results
                for i, script in enumerate(search_result['scripts'][:3]):
                    print(f"{i+1}. {script['name']}")
                    print(f"   Categories: {', '.join(script['categories'])}")
                    print(f"   Description: {script['description'][:100]}...")
                    print()

                return True

    except Exception as e:
        print(f"Error during script search demo: {e}")
        return False


async def demonstrate_scan_history():
    """Demonstrate scan history capabilities."""
    print("\n=== Scan History Demo ===")

    server_params = StdioServerParameters(
        command="uv",
        args=["run", "nmap_mcp.py", "-f"]
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                print("Retrieving scan history...")

                result = await session.call_tool(
                    "get_scan_history",
                    {
                        "limit": 5
                    }
                )

                history_result = json.loads(result.content[0].text)
                print(f"Total scans in history: {history_result['total_scans']}")
                print(f"Showing last {history_result['returned_count']} scans:")

                for scan in history_result['scans']:
                    timestamp = scan['result']['timestamp']
                    targets = ', '.join(scan['targets'])
                    scan_type = scan['scan_type']
                    print(f"- {timestamp}: {scan_type} on {targets}")

                return True

    except Exception as e:
        print(f"Error during scan history demo: {e}")
        return False


async def main():
    """Run demonstration of nmap-mcp capabilities."""
    print("nmap-mcp Client Demo")
    print("===================")

    print("\nThis demo will:")
    print("1. Perform a sample TCP scan")
    print("2. Search for Nmap scripts")
    print("3. Show scan history")
    print("\nNote: Make sure the nmap-mcp server dependencies are installed.")
    print("Run: uv sync --frozen\n")

    # Check if we should proceed
    try:
        response = input("Continue with demo? (y/N): ").strip().lower()
        if response not in ('y', 'yes'):
            print("Demo cancelled.")
            return 0
    except KeyboardInterrupt:
        print("\nDemo cancelled.")
        return 0

    demos = [
        demonstrate_tcp_scan,
        demonstrate_script_search,
        demonstrate_scan_history,
    ]

    results = []
    for demo in demos:
        try:
            result = await demo()
            results.append(result)
        except Exception as e:
            print(f"Demo {demo.__name__} failed: {e}")
            results.append(False)

    passed = sum(results)
    total = len(results)

    print(f"\n=== Demo Results ===")
    print(f"{passed}/{total} demos completed successfully")

    if passed == total:
        print("🎉 All demos completed successfully!")
        return 0
    else:
        print("❌ Some demos failed. Check the error messages above.")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nDemo interrupted by user.")
        sys.exit(0)
