"""
Simulated File Tool
===================
Mock implementation of file read/write operations.
Does NOT perform any real file system actions.
"""

from typing import Any


def read_file(path: str) -> dict[str, Any]:
    """
    Simulate reading a file.

    Args:
        path: Path to the file to read.

    Returns:
        A simulated success response with mock content.
    """
    return {
        "status": "success",
        "message": f"File read from {path}",
        "content": f"[Simulated content of {path}]",
    }


def write_file(path: str, content: str) -> dict[str, Any]:
    """
    Simulate writing to a file.

    Args:
        path: Path to the file to write.
        content: Content to write to the file.

    Returns:
        A simulated success response.
    """
    return {
        "status": "success",
        "message": f"File written to {path}",
        "details": {
            "path": path,
            "bytes_written": len(content),
        },
    }
