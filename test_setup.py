#!/usr/bin/env python3
"""
Simple test script to validate nmap-mcp functionality.
"""

import asyncio
import json
import subprocess
import sys
from pathlib import Path

async def test_nmap_availability():
    """Test if nmap is available."""
    try:
        result = subprocess.run(["nmap", "--version"],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ Nmap is available")
            return True
        else:
            print("✗ Nmap is not working properly")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("✗ Nmap is not installed or not in PATH")
        return False

async def test_mcp_server_import():
    """Test if the MCP server can be imported."""
    try:
        # Test import using uv run
        result = subprocess.run(["uv", "run", "python", "-c", "import nmap_mcp; print('Import successful')"],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ nmap_mcp module imports successfully")
            return True
        else:
            print(f"✗ Failed to import nmap_mcp: {result.stderr}")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"✗ Failed to test import: {e}")
        return False

async def test_uv_run():
    """Test if the server can be run with uv."""
    try:
        # Test help flag
        result = subprocess.run(["uv", "run", "nmap_mcp.py", "--help"],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ Server can be run with uv")
            return True
        else:
            print(f"✗ Failed to run with uv: {result.stderr}")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"✗ uv command failed: {e}")
        return False

async def main():
    """Run all tests."""
    print("Running nmap-mcp validation tests...\n")

    tests = [
        test_nmap_availability,
        test_mcp_server_import,
        test_uv_run,
    ]

    results = []
    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
            results.append(False)
        print()

    passed = sum(results)
    total = len(results)

    print(f"Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! The nmap-mcp server is ready to use.")
        return 0
    else:
        print("❌ Some tests failed. Please check the requirements and installation.")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
