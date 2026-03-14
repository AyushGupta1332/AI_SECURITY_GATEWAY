"""
Simulated Database Tool
=======================
Mock implementation of a database query tool.
Does NOT perform any real database operations.
"""

from typing import Any


def query_database(query: str) -> dict[str, Any]:
    """
    Simulate executing a database query.

    Args:
        query: The SQL query string to execute.

    Returns:
        A simulated success response with mock rows.
    """
    return {
        "status": "success",
        "message": "Query executed successfully",
        "details": {
            "query": query,
            "rows_returned": 3,
            "data": [
                {"id": 1, "name": "Sample Record 1"},
                {"id": 2, "name": "Sample Record 2"},
                {"id": 3, "name": "Sample Record 3"},
            ],
        },
    }
