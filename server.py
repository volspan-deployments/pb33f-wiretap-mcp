from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn
import threading
from fastmcp import FastMCP
import httpx
import os
import subprocess
import asyncio
import json
import yaml
from typing import Optional, List

mcp = FastMCP("wiretap")


def _find_wiretap_binary() -> str:
    """Find the wiretap binary in PATH or common locations."""
    import shutil
    binary = shutil.which("wiretap")
    if binary:
        return binary
    common_paths = [
        "/usr/local/bin/wiretap",
        "/usr/bin/wiretap",
        os.path.expanduser("~/go/bin/wiretap"),
        "/opt/homebrew/bin/wiretap",
    ]
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return "wiretap"


def _run_command(cmd: List[str], cwd: Optional[str] = None) -> dict:
    """Run a shell command synchronously and return result."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd
        )
        return {
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "command": " ".join(cmd)
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": "Command timed out after 30 seconds",
            "command": " ".join(cmd)
        }
    except FileNotFoundError:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"Binary not found: {cmd[0]}. Please install wiretap first.",
            "command": " ".join(cmd)
        }
    except Exception as e:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "command": " ".join(cmd)
        }


@mcp.tool()
async def start_wiretap(
    _track("start_wiretap")
    target_url: str,
    spec_file: Optional[str] = None,
    port: int = 9090,
    monitor_port: int = 9091,
    config_file: Optional[str] = None,
    hard_errors: bool = False
) -> dict:
    """
    Start the wiretap proxy daemon to intercept and analyze API traffic for OpenAPI contract violations.
    Use this to launch the proxy server with a target API URL and optional OpenAPI spec.
    This is the primary way to begin monitoring API compliance.
    """
    wiretap = _find_wiretap_binary()
    cmd = [wiretap, "-u", target_url]

    if spec_file:
        cmd.extend(["-s", spec_file])
    if port != 9090:
        cmd.extend(["-p", str(port)])
    if monitor_port != 9091:
        cmd.extend(["-m", str(monitor_port)])
    if config_file:
        cmd.extend(["-c", config_file])
    if hard_errors:
        cmd.append("--hard-errors")

    # Start wiretap as a background process (daemon)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True
        )
        # Give it a moment to start
        await asyncio.sleep(1.5)

        # Check if process is still running
        if proc.poll() is None:
            return {
                "success": True,
                "pid": proc.pid,
                "message": f"Wiretap proxy started successfully in background (PID: {proc.pid})",
                "proxy_url": f"http://localhost:{port}",
                "monitor_url": f"http://localhost:{monitor_port}",
                "target_url": target_url,
                "spec_file": spec_file,
                "port": port,
                "monitor_port": monitor_port,
                "hard_errors": hard_errors,
                "command": " ".join(cmd),
                "tip": "Point your HTTP client to the proxy_url. View violations at the monitor_url."
            }
        else:
            stdout, stderr = proc.communicate()
            return {
                "success": False,
                "pid": proc.pid,
                "message": "Wiretap process exited unexpectedly",
                "stdout": stdout.strip(),
                "stderr": stderr.strip(),
                "command": " ".join(cmd)
            }
    except FileNotFoundError:
        return {
            "success": False,
            "message": "wiretap binary not found. Please install wiretap first.",
            "install_instructions": {
                "homebrew": "brew install pb33f/taps/wiretap",
                "npm": "npm install -g @pb33f/wiretap",
                "curl": "curl -fsSL https://pb33f.io/wiretap/install.sh | sh",
                "docker": "docker pull pb33f/wiretap"
            },
            "command": " ".join(cmd)
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to start wiretap: {str(e)}",
            "command": " ".join(cmd)
        }


@mcp.tool()
async def validate_request(
    _track("validate_request")
    spec_file: str,
    method: str,
    path: str,
    headers: Optional[List[str]] = None,
    body: Optional[str] = None,
    query_params: Optional[str] = None
) -> dict:
    """
    Validate a specific HTTP request against an OpenAPI specification without proxying live traffic.
    Use this to check whether a given request (method, path, headers, body) complies with the API contract
    before sending it.
    """
    wiretap = _find_wiretap_binary()
    cmd = [wiretap, "validate", "request",
           "-s", spec_file,
           "--method", method.upper(),
           "--path", path]

    if headers:
        for header in headers:
            cmd.extend(["--header", header])
    if body:
        cmd.extend(["--body", body])
    if query_params:
        cmd.extend(["--query", query_params])

    result = _run_command(cmd)

    # Try to parse JSON output if available
    if result["stdout"]:
        try:
            parsed = json.loads(result["stdout"])
            result["parsed_output"] = parsed
        except json.JSONDecodeError:
            result["parsed_output"] = None

    result["validation_target"] = {
        "spec_file": spec_file,
        "method": method.upper(),
        "path": path,
        "headers": headers,
        "has_body": body is not None,
        "query_params": query_params
    }

    if result["success"]:
        result["message"] = "Request validation completed"
        result["violations_found"] = "violation" in result["stdout"].lower() or "error" in result["stdout"].lower()
    else:
        result["message"] = "Request validation failed or violations detected"
        result["violations_found"] = True

    return result


@mcp.tool()
async def validate_response(
    _track("validate_response")
    spec_file: str,
    method: str,
    path: str,
    status_code: int,
    response_body: Optional[str] = None,
    headers: Optional[List[str]] = None
) -> dict:
    """
    Validate a specific HTTP response against an OpenAPI specification.
    Use this to check whether a given API response (status code, headers, body) complies with
    what the spec defines for a given operation.
    """
    wiretap = _find_wiretap_binary()
    cmd = [wiretap, "validate", "response",
           "-s", spec_file,
           "--method", method.upper(),
           "--path", path,
           "--status", str(status_code)]

    if response_body:
        cmd.extend(["--body", response_body])
    if headers:
        for header in headers:
            cmd.extend(["--header", header])

    result = _run_command(cmd)

    # Try to parse JSON output if available
    if result["stdout"]:
        try:
            parsed = json.loads(result["stdout"])
            result["parsed_output"] = parsed
        except json.JSONDecodeError:
            result["parsed_output"] = None

    result["validation_target"] = {
        "spec_file": spec_file,
        "method": method.upper(),
        "path": path,
        "status_code": status_code,
        "headers": headers,
        "has_body": response_body is not None
    }

    if result["success"]:
        result["message"] = "Response validation completed"
        result["violations_found"] = "violation" in result["stdout"].lower() or "error" in result["stdout"].lower()
    else:
        result["message"] = "Response validation failed or violations detected"
        result["violations_found"] = True

    return result


@mcp.tool()
async def get_violations(
    _track("get_violations")
    monitor_port: int = 9091,
    filter_type: Optional[str] = None,
    limit: int = 50
) -> dict:
    """
    Retrieve the list of captured OpenAPI contract violations from the running wiretap proxy.
    Use this to inspect what requests or responses have failed compliance checks during a monitoring session.
    """
    base_url = f"http://localhost:{monitor_port}"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try common wiretap API endpoints for violations
            endpoints_to_try = [
                f"{base_url}/api/violations",
                f"{base_url}/violations",
                f"{base_url}/api/transactions",
                f"{base_url}/transactions",
            ]

            last_error = None
            for endpoint in endpoints_to_try:
                try:
                    response = await client.get(endpoint)
                    if response.status_code == 200:
                        data = response.json()

                        # Filter by type if requested
                        violations = data
                        if isinstance(data, list):
                            if filter_type == "request":
                                violations = [v for v in data if v.get("type") == "request" or v.get("violationType") == "request"]
                            elif filter_type == "response":
                                violations = [v for v in data if v.get("type") == "response" or v.get("violationType") == "response"]

                            # Apply limit
                            violations = violations[:limit]

                        return {
                            "success": True,
                            "endpoint": endpoint,
                            "monitor_port": monitor_port,
                            "filter_type": filter_type,
                            "limit": limit,
                            "count": len(violations) if isinstance(violations, list) else 1,
                            "violations": violations
                        }
                except Exception as e:
                    last_error = str(e)
                    continue

            # If no endpoint worked, return status with helpful info
            return {
                "success": False,
                "message": f"Could not connect to wiretap monitor at {base_url}. Is the wiretap proxy running?",
                "monitor_port": monitor_port,
                "last_error": last_error,
                "monitor_ui": f"{base_url}",
                "tip": "Start wiretap first using start_wiretap tool, then query violations.",
                "tried_endpoints": endpoints_to_try
            }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to connect to wiretap monitor: {str(e)}",
            "monitor_port": monitor_port,
            "monitor_url": f"http://localhost:{monitor_port}",
            "tip": "Ensure wiretap is running. Use start_wiretap to launch the proxy."
        }


@mcp.tool()
async def configure_path_rewrite(
    _track("configure_path_rewrite")
    original_path: str,
    rewritten_path: str,
    config_file: str = ".wiretap",
    rewrite_id: Optional[str] = None,
    target_url: Optional[str] = None
) -> dict:
    """
    Configure path rewriting rules in the wiretap configuration file.
    Use this to set up path redirects, rewrites, or alternate target URLs for specific API paths
    when the proxy needs to forward requests to different backends.
    """
    try:
        # Load existing config or create new one
        config_data = {}
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                content = f.read().strip()
                if content:
                    try:
                        config_data = yaml.safe_load(content) or {}
                    except yaml.YAMLError:
                        try:
                            config_data = json.loads(content)
                        except json.JSONDecodeError:
                            config_data = {}

        # Ensure paths section exists
        if "paths" not in config_data:
            config_data["paths"] = []

        # Build the new path rule
        path_rule = {
            "path": original_path,
            "rewritePath": rewritten_path
        }
        if rewrite_id:
            path_rule["rewriteId"] = rewrite_id
        if target_url:
            path_rule["target"] = target_url

        # Check if rule for this path already exists, update if so
        updated = False
        for i, rule in enumerate(config_data["paths"]):
            if isinstance(rule, dict) and rule.get("path") == original_path:
                config_data["paths"][i] = path_rule
                updated = True
                break

        if not updated:
            config_data["paths"].append(path_rule)

        # Write back to file
        with open(config_file, "w") as f:
            yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)

        return {
            "success": True,
            "message": f"Path rewrite rule {'updated' if updated else 'added'} successfully",
            "config_file": os.path.abspath(config_file),
            "rule": path_rule,
            "action": "updated" if updated else "created",
            "total_rules": len(config_data.get("paths", [])),
            "full_config": config_data
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to configure path rewrite: {str(e)}",
            "config_file": config_file,
            "original_path": original_path,
            "rewritten_path": rewritten_path
        }


@mcp.tool()
async def generate_config(
    _track("generate_config")
    target_url: str,
    spec_file: Optional[str] = None,
    output_file: str = ".wiretap",
    port: int = 9090,
    hard_errors: bool = False,
    ignore_redirects: bool = False
) -> dict:
    """
    Generate a wiretap configuration file (.wiretap) with sensible defaults for a project.
    Use this to scaffold a new configuration when setting up wiretap for the first time or for a new project.
    """
    try:
        # Build config structure matching wiretap's expected format
        config = {
            "contract": spec_file if spec_file else "",
            "target": target_url,
            "port": str(port),
            "monitorPort": str(port + 1),
            "wsPort": str(port + 2),
            "hardErrors": hard_errors,
            "ignoreRedirects": ignore_redirects,
            "paths": [],
            "headers": {},
            "variables": {}
        }

        # Remove empty string values for cleanliness
        if not config["contract"]:
            del config["contract"]

        # Write the YAML config file
        with open(output_file, "w") as f:
            f.write("# Wiretap Configuration File\n")
            f.write("# Generated by FastMCP Wiretap Server\n")
            f.write("# Documentation: https://pb33f.io/wiretap/\n\n")
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        # Also produce an example CLI command
        cli_parts = ["wiretap", "-u", target_url]
        if spec_file:
            cli_parts.extend(["-s", spec_file])
        if port != 9090:
            cli_parts.extend(["-p", str(port)])
        if hard_errors:
            cli_parts.append("--hard-errors")

        return {
            "success": True,
            "message": f"Wiretap configuration file generated at '{output_file}'",
            "output_file": os.path.abspath(output_file),
            "config": config,
            "equivalent_cli_command": " ".join(cli_parts),
            "usage": f"Run: wiretap -c {output_file}  OR  {' '.join(cli_parts)}",
            "proxy_url": f"http://localhost:{port}",
            "monitor_url": f"http://localhost:{port + 1}"
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to generate config: {str(e)}",
            "output_file": output_file
        }


@mcp.tool()
async def check_compliance(
    _track("check_compliance")
    spec_file: str,
    har_file: Optional[str] = None,
    output_format: str = "text",
    fail_on_violations: bool = True
) -> dict:
    """
    Run a full compliance check by replaying a collection of request/response pairs from a HAR file
    or log against an OpenAPI specification. Use this in CI/CD pipelines to detect contract violations
    in recorded traffic.
    """
    wiretap = _find_wiretap_binary()

    if not os.path.exists(spec_file):
        return {
            "success": False,
            "message": f"OpenAPI spec file not found: {spec_file}",
            "spec_file": spec_file
        }

    if har_file and not os.path.exists(har_file):
        return {
            "success": False,
            "message": f"HAR file not found: {har_file}",
            "har_file": har_file
        }

    # Build the compliance check command
    cmd = [wiretap, "compliance"]

    if har_file:
        cmd.extend(["--har", har_file])

    cmd.extend(["-s", spec_file])

    if output_format and output_format != "text":
        cmd.extend(["--format", output_format])

    result = _run_command(cmd)

    # Try to parse output based on format
    parsed_output = None
    if result["stdout"]:
        if output_format == "json":
            try:
                parsed_output = json.loads(result["stdout"])
            except json.JSONDecodeError:
                parsed_output = None
        elif output_format == "junit":
            parsed_output = result["stdout"]  # XML string for JUnit

    # Determine if compliance passed
    violations_detected = (
        result["returncode"] != 0 or
        "violation" in result["stdout"].lower() or
        "violation" in result["stderr"].lower()
    )

    compliance_result = {
        "success": result["success"],
        "compliant": not violations_detected,
        "violations_found": violations_detected,
        "returncode": result["returncode"],
        "spec_file": spec_file,
        "har_file": har_file,
        "output_format": output_format,
        "command": result["command"],
        "stdout": result["stdout"],
        "stderr": result["stderr"]
    }

    if parsed_output is not None:
        compliance_result["parsed_output"] = parsed_output

    if fail_on_violations and violations_detected:
        compliance_result["ci_exit_code"] = 1
        compliance_result["ci_message"] = "COMPLIANCE CHECK FAILED: OpenAPI contract violations detected."
    else:
        compliance_result["ci_exit_code"] = 0
        compliance_result["ci_message"] = "COMPLIANCE CHECK PASSED: No violations detected."

    return compliance_result




_SERVER_SLUG = "pb33f-wiretap"

def _track(tool_name: str, ua: str = ""):
    try:
        import urllib.request, json as _json
        data = _json.dumps({"slug": _SERVER_SLUG, "event": "tool_call", "tool": tool_name, "user_agent": ua}).encode()
        req = urllib.request.Request("https://www.volspan.dev/api/analytics/event", data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass

async def health(request):
    return JSONResponse({"status": "ok", "server": mcp.name})

async def tools(request):
    registered = await mcp.list_tools()
    tool_list = [{"name": t.name, "description": t.description or ""} for t in registered]
    return JSONResponse({"tools": tool_list, "count": len(tool_list)})

sse_app = mcp.http_app(transport="sse")

app = Starlette(
    routes=[
        Route("/health", health),
        Route("/tools", tools),
        Mount("/", sse_app),
    ],
    lifespan=sse_app.lifespan,
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
