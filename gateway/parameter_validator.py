"""
Parameter Validator
===================
Validates tool parameters against policy constraints.
Independent from policy loading — receives constraints as input.
"""

import re
from typing import Any


# System directories that write_file must never target
BLOCKED_SYSTEM_DIRECTORIES: list[str] = ["/etc", "/usr", "/bin"]

# SQL keywords that indicate destructive operations
DESTRUCTIVE_SQL_KEYWORDS: list[str] = ["DROP", "DELETE", "ALTER", "TRUNCATE"]


class ParameterValidator:
    """
    Validates parameters for each tool type against
    the constraints defined in the policy configuration.
    """

    def validate(
        self,
        tool_name: str,
        parameters: dict[str, Any],
        constraints: dict[str, Any],
    ) -> tuple[bool, str]:
        """
        Validate parameters for a given tool.

        Args:
            tool_name: The name of the tool being called.
            parameters: The parameters supplied in the request.
            constraints: The constraints from the policy for this tool/agent.

        Returns:
            A tuple of (is_valid, reason).
        """
        validator_map = {
            "read_file": self._validate_read_file,
            "write_file": self._validate_write_file,
            "send_email": self._validate_send_email,
            "query_database": self._validate_query_database,
        }

        validator = validator_map.get(tool_name)
        if validator is None:
            return False, f"No validator defined for tool: {tool_name}"

        return validator(parameters, constraints)

    def _validate_read_file(
        self, parameters: dict[str, Any], constraints: dict[str, Any]
    ) -> tuple[bool, str]:
        """Validate read_file: path must respect path_prefix constraint."""
        path: str = parameters.get("path", "")
        path_prefix: str = constraints.get("path_prefix", "")

        if not path:
            return False, "Parameter 'path' is required"

        if path_prefix and not path.startswith(path_prefix):
            return False, (
                f"Path '{path}' violates path_prefix constraint. "
                f"Must start with '{path_prefix}'"
            )

        return True, "Path validated successfully"

    def _validate_write_file(
        self, parameters: dict[str, Any], constraints: dict[str, Any]
    ) -> tuple[bool, str]:
        """
        Validate write_file:
        - Must not target system directories (/etc, /usr, /bin).
        - Must respect path_prefix constraint if defined.
        """
        path: str = parameters.get("path", "")
        content: str = parameters.get("content", "")

        if not path:
            return False, "Parameter 'path' is required"

        if not content:
            return False, "Parameter 'content' is required"

        # Check for blocked system directories
        for blocked_dir in BLOCKED_SYSTEM_DIRECTORIES:
            if path.startswith(blocked_dir):
                return False, (
                    f"Write access to system directory '{blocked_dir}' is blocked"
                )

        # Check path_prefix constraint if defined
        path_prefix: str = constraints.get("path_prefix", "")
        if path_prefix and not path.startswith(path_prefix):
            return False, (
                f"Path '{path}' violates path_prefix constraint. "
                f"Must start with '{path_prefix}'"
            )

        return True, "Write parameters validated successfully"

    def _validate_send_email(
        self, parameters: dict[str, Any], constraints: dict[str, Any]
    ) -> tuple[bool, str]:
        """Validate send_email: 'to' domain must be in allowed_domains."""
        to_address: str = parameters.get("to", "")
        subject: str = parameters.get("subject", "")
        body: str = parameters.get("body", "")

        if not to_address:
            return False, "Parameter 'to' is required"

        if not subject:
            return False, "Parameter 'subject' is required"

        if not body:
            return False, "Parameter 'body' is required"

        # Extract domain from email address
        allowed_domains: list[str] = constraints.get("allowed_domains", [])
        if allowed_domains:
            match = re.match(r"^[^@]+@(.+)$", to_address)
            if not match:
                return False, f"Invalid email address format: '{to_address}'"

            domain = match.group(1).lower()
            allowed_lower = [d.lower() for d in allowed_domains]

            if domain not in allowed_lower:
                return False, (
                    f"Email domain '{domain}' is not in allowed domains: "
                    f"{allowed_domains}"
                )

        return True, "Domain validated successfully"

    def _validate_query_database(
        self, parameters: dict[str, Any], constraints: dict[str, Any]
    ) -> tuple[bool, str]:
        """
        Validate query_database:
        - Block destructive SQL keywords (DROP, DELETE, ALTER, TRUNCATE).
        - Enforce read_only constraint if set.
        """
        query: str = parameters.get("query", "")

        if not query:
            return False, "Parameter 'query' is required"

        query_upper = query.upper()

        # Check for destructive SQL keywords
        read_only: bool = constraints.get("read_only", True)
        if read_only:
            for keyword in DESTRUCTIVE_SQL_KEYWORDS:
                if re.search(rf"\b{keyword}\b", query_upper):
                    return False, (
                        f"Destructive SQL keyword '{keyword}' detected. "
                        f"Query blocked under read_only constraint."
                    )

            # Also block INSERT and UPDATE under read_only
            for keyword in ["INSERT", "UPDATE"]:
                if re.search(rf"\b{keyword}\b", query_upper):
                    return False, (
                        f"Write operation '{keyword}' blocked under read_only constraint."
                    )

        else:
            # Even non-read-only agents cannot use DROP, ALTER, TRUNCATE
            for keyword in ["DROP", "ALTER", "TRUNCATE"]:
                if re.search(rf"\b{keyword}\b", query_upper):
                    return False, (
                        f"Destructive SQL keyword '{keyword}' is always blocked."
                    )

        return True, "Query validated successfully"
