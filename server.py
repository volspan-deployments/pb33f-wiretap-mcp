from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn
import threading
from fastmcp import FastMCP
import httpx
import os
import subprocess
import json
import tempfile
import shutil
from typing import Optional, List

mcp = FastMCP("wiretap")

# Helper to find wiretap binary
def find_wiretap() -> Optional[str]:
    """Find the wiretap binary in PATH or common locations."""
    wiretap_path = shutil.which("wiretap")
    if wiretap_path:
        return wiretap_path
    common_paths = [
        "/usr/local/bin/wiretap",
        "/usr/bin/wiretap",
        os.path.expanduser("~/.local/bin/wiretap"),
        os.path.expanduser("~/go/bin/wiretap"),
    ]
    for p in common_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def run_command(args: List[str], cwd: Optional[str] = None) -> dict:
    """Run a shell command and return stdout, stderr, and return code."""
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=30,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "Command timed out after 30 seconds",
            "returncode": -1,
            "success": False,
        }
    except FileNotFoundError as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "success": False,
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Unexpected error: {str(e)}",
            "returncode": -1,
            "success": False,
        }


@mcp.tool()
async def start_wiretap(
    api_spec: str,
    target_url: str,
    port: int = 9090,
    monitor_port: int = 9091,
    config_file: Optional[str] = None,
    base: Optional[str] = None,
) -> dict:
    """
    Start the wiretap proxy server to intercept and validate API traffic against an OpenAPI specification.
    Use this to begin monitoring API requests/responses for contract violations.
    Wiretap acts as a man-in-the-middle proxy between your client and the target API.
    """
    wiretap_bin = find_wiretap()
    if not wiretap_bin:
        return {
            "success": False,
            "error": "wiretap binary not found. Install it via: brew install pb33f/taps/wiretap, npm install -g @pb33f/wiretap, or curl -fsSL https://pb33f.io/wiretap/install.sh | sh",
            "command": None,
        }

    args = [
        wiretap_bin,
        "-u", target_url,
        "-s", api_spec,
        "-p", str(port),
        "-m", str(monitor_port),
    ]

    if config_file:
        args += ["-c", config_file]
    if base:
        args += ["-b", base]

    command_str = " ".join(args)

    return {
        "success": True,
        "message": "Wiretap proxy server command prepared. Run the command below in your terminal to start the proxy. It will run in the foreground and intercept API traffic.",
        "command": command_str,
        "proxy_url": f"http://localhost:{port}",
        "monitor_url": f"http://localhost:{monitor_port}",
        "instructions": [
            f"1. Run: {command_str}",
            f"2. Point your API client to http://localhost:{port} instead of {target_url}",
            f"3. Open the monitoring dashboard at http://localhost:{monitor_port}",
            f"4. Wiretap will validate all requests and responses against {api_spec}",
        ],
        "note": "Wiretap runs as a long-running process. Use Ctrl+C to stop it. This MCP tool returns the command to run rather than executing it directly to avoid blocking.",
    }


@mcp.tool()
async def validate_request(
    api_spec: str,
    method: str,
    path: str,
    headers: Optional[List[str]] = None,
    body: Optional[str] = None,
    query_params: Optional[str] = None,
) -> dict:
    """
    Validate a specific HTTP request against an OpenAPI specification without starting a full proxy server.
    Use this to check if a given request payload and headers comply with the API contract defined in the spec.
    """
    wiretap_bin = find_wiretap()
    if not wiretap_bin:
        return {
            "success": False,
            "error": "wiretap binary not found. Install it via: brew install pb33f/taps/wiretap, npm install -g @pb33f/wiretap, or curl -fsSL https://pb33f.io/wiretap/install.sh | sh",
        }

    args = [
        wiretap_bin,
        "validate", "request",
        "-s", api_spec,
        "-m", method.upper(),
        "-p", path,
    ]

    if headers:
        for header in headers:
            args += ["-H", header]

    if body:
        args += ["-d", body]

    if query_params:
        args += ["-q", query_params]

    result = run_command(args)

    return {
        "success": result["success"],
        "command": " ".join(args),
        "output": result["stdout"],
        "errors": result["stderr"],
        "returncode": result["returncode"],
        "validated": {
            "method": method.upper(),
            "path": path,
            "spec": api_spec,
            "headers_provided": headers or [],
            "body_provided": body is not None,
            "query_params": query_params,
        },
        "compliance": "PASS" if result["success"] else "FAIL",
    }


@mcp.tool()
async def validate_response(
    api_spec: str,
    method: str,
    path: str,
    status_code: int,
    response_body: Optional[str] = None,
    response_headers: Optional[List[str]] = None,
) -> dict:
    """
    Validate an HTTP response against an OpenAPI specification to check if the server response is compliant
    with the defined contract. Use this to detect when servers return responses that don't match the spec.
    """
    wiretap_bin = find_wiretap()
    if not wiretap_bin:
        return {
            "success": False,
            "error": "wiretap binary not found. Install it via: brew install pb33f/taps/wiretap, npm install -g @pb33f/wiretap, or curl -fsSL https://pb33f.io/wiretap/install.sh | sh",
        }

    args = [
        wiretap_bin,
        "validate", "response",
        "-s", api_spec,
        "-m", method.upper(),
        "-p", path,
        "-c", str(status_code),
    ]

    if response_body:
        args += ["-d", response_body]

    if response_headers:
        for header in response_headers:
            args += ["-H", header]

    result = run_command(args)

    return {
        "success": result["success"],
        "command": " ".join(args),
        "output": result["stdout"],
        "errors": result["stderr"],
        "returncode": result["returncode"],
        "validated": {
            "method": method.upper(),
            "path": path,
            "status_code": status_code,
            "spec": api_spec,
            "response_headers_provided": response_headers or [],
            "response_body_provided": response_body is not None,
        },
        "compliance": "PASS" if result["success"] else "FAIL",
    }


@mcp.tool()
async def generate_config(
    target_url: str,
    api_spec: str,
    output_file: str = ".wiretap",
    path_rewrites: Optional[List[str]] = None,
    ignore_paths: Optional[List[str]] = None,
    port: int = 9090,
) -> dict:
    """
    Generate a wiretap configuration file (.wiretap) with path rewriting rules, ignore patterns,
    and other proxy settings. Use this to create or scaffold a configuration file for complex API proxying scenarios.
    """
    # Build the YAML configuration content manually
    config_lines = [
        "# Wiretap configuration file",
        "# Generated by wiretap MCP server",
        "",
        f"contract: {api_spec}",
        f"target: {target_url}",
        f"port: {port}",
    ]

    if path_rewrites:
        config_lines.append("pathRewrite:")
        for rewrite in path_rewrites:
            parts = rewrite.split(":", 1)
            if len(parts) == 2:
                original, rewritten = parts
                config_lines.append(f"  - original: {original}")
                config_lines.append(f"    rewritten: {rewritten}")
            else:
                config_lines.append(f"  - original: {rewrite}")
                config_lines.append(f"    rewritten: {rewrite}")

    if ignore_paths:
        config_lines.append("ignorePaths:")
        for p in ignore_paths:
            config_lines.append(f"  - {p}")

    config_content = "\n".join(config_lines) + "\n"

    # Try to write the config file
    write_error = None
    try:
        with open(output_file, "w") as f:
            f.write(config_content)
        file_written = True
    except Exception as e:
        write_error = str(e)
        file_written = False

    return {
        "success": file_written,
        "output_file": output_file,
        "config_content": config_content,
        "write_error": write_error,
        "message": f"Configuration {'written to ' + output_file if file_written else 'generated (could not write to ' + output_file + ': ' + str(write_error) + ')'}. Use this config with: wiretap -c {output_file}",
        "settings": {
            "target_url": target_url,
            "api_spec": api_spec,
            "port": port,
            "path_rewrites": path_rewrites or [],
            "ignore_paths": ignore_paths or [],
        },
        "usage": f"wiretap -c {output_file}",
    }


@mcp.tool()
async def inspect_violations(
    monitor_url: str = "http://localhost:9091",
    filter_path: Optional[str] = None,
    filter_method: Optional[str] = None,
    severity: Optional[str] = None,
) -> dict:
    """
    Inspect and list captured OpenAPI contract violations from a running wiretap session.
    Use this to retrieve a summary of all detected compliance issues including request and response
    violations, schema mismatches, and missing required fields.
    """
    # Try to connect to the wiretap monitor API
    api_endpoints = [
        f"{monitor_url}/api/violations",
        f"{monitor_url}/api/transactions",
        f"{monitor_url}/api/report",
    ]

    violations_data = None
    connected_endpoint = None
    connection_error = None

    async with httpx.AsyncClient(timeout=10.0) as client:
        for endpoint in api_endpoints:
            try:
                response = await client.get(endpoint)
                if response.status_code == 200:
                    violations_data = response.json()
                    connected_endpoint = endpoint
                    break
            except httpx.ConnectError:
                connection_error = f"Could not connect to wiretap monitor at {monitor_url}. Is wiretap running?"
            except httpx.TimeoutException:
                connection_error = f"Connection to {monitor_url} timed out."
            except Exception as e:
                connection_error = str(e)

    if violations_data is None:
        return {
            "success": False,
            "monitor_url": monitor_url,
            "error": connection_error or f"No violations data available from {monitor_url}",
            "message": "Make sure wiretap is running with: wiretap -u <target_url> -s <api_spec>",
            "filters_applied": {
                "path": filter_path,
                "method": filter_method,
                "severity": severity,
            },
        }

    # Apply filters if violations_data is a list
    filtered_violations = violations_data
    if isinstance(violations_data, list):
        if filter_path:
            filtered_violations = [
                v for v in filtered_violations
                if isinstance(v, dict) and filter_path.lower() in str(v.get("path", "")).lower()
            ]
        if filter_method:
            filtered_violations = [
                v for v in filtered_violations
                if isinstance(v, dict) and str(v.get("method", "")).upper() == filter_method.upper()
            ]
        if severity:
            filtered_violations = [
                v for v in filtered_violations
                if isinstance(v, dict) and str(v.get("severity", "")).lower() == severity.lower()
            ]

    return {
        "success": True,
        "monitor_url": monitor_url,
        "connected_endpoint": connected_endpoint,
        "violations": filtered_violations,
        "total_count": len(filtered_violations) if isinstance(filtered_violations, list) else "N/A",
        "filters_applied": {
            "path": filter_path,
            "method": filter_method,
            "severity": severity,
        },
        "raw_data": violations_data if not isinstance(violations_data, list) else None,
    }


@mcp.tool()
async def diff_spec(
    original_spec: str,
    modified_spec: str,
    output_format: str = "console",
    fail_on_breaking: bool = False,
) -> dict:
    """
    Compare two OpenAPI specifications to detect breaking changes and contract differences.
    Use this before deploying API changes to understand what has changed between spec versions
    and what impact it may have on consumers.
    """
    wiretap_bin = find_wiretap()

    # Try libopenapi-validator or related tools first
    # wiretap uses libopenapi under the hood, check if it has a diff subcommand
    if wiretap_bin:
        # Try wiretap diff command
        args = [wiretap_bin, "diff", original_spec, modified_spec]

        if output_format and output_format != "console":
            args += ["-f", output_format]

        if fail_on_breaking:
            args += ["--fail-on-breaking"]

        result = run_command(args)

        if result["returncode"] != -1 or result["stdout"]:
            # Command ran (even if it failed due to breaking changes)
            return {
                "success": result["success"],
                "command": " ".join(args),
                "output": result["stdout"],
                "errors": result["stderr"],
                "returncode": result["returncode"],
                "breaking_changes_detected": result["returncode"] != 0 and fail_on_breaking,
                "compared": {
                    "original": original_spec,
                    "modified": modified_spec,
                    "output_format": output_format,
                    "fail_on_breaking": fail_on_breaking,
                },
            }

    # If wiretap doesn't have a diff command, check for oasdiff or similar
    oasdiff_bin = shutil.which("oasdiff")
    if oasdiff_bin:
        args = [oasdiff_bin, "diff", original_spec, modified_spec]
        if output_format == "json":
            args += ["-f", "json"]
        result = run_command(args)
        return {
            "success": result["success"],
            "tool_used": "oasdiff",
            "command": " ".join(args),
            "output": result["stdout"],
            "errors": result["stderr"],
            "returncode": result["returncode"],
            "compared": {
                "original": original_spec,
                "modified": modified_spec,
                "output_format": output_format,
            },
        }

    # Fallback: read both specs and do a basic structural comparison
    try:
        spec_contents = {}
        spec_errors = {}
        for label, spec_path in [("original", original_spec), ("modified", modified_spec)]:
            if spec_path.startswith("http://") or spec_path.startswith("https://"):
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(spec_path)
                    resp.raise_for_status()
                    try:
                        spec_contents[label] = resp.json()
                    except Exception:
                        import yaml
                        spec_contents[label] = yaml.safe_load(resp.text)
            else:
                with open(spec_path, "r") as f:
                    content = f.read()
                try:
                    spec_contents[label] = json.loads(content)
                except json.JSONDecodeError:
                    try:
                        import yaml
                        spec_contents[label] = yaml.safe_load(content)
                    except Exception as e:
                        spec_errors[label] = str(e)

        if spec_errors:
            return {
                "success": False,
                "error": f"Could not parse spec files: {spec_errors}",
                "suggestion": "Install wiretap (brew install pb33f/taps/wiretap) or oasdiff for full diff support",
            }

        orig = spec_contents.get("original", {})
        mod = spec_contents.get("modified", {})

        orig_paths = set(orig.get("paths", {}).keys())
        mod_paths = set(mod.get("paths", {}).keys())

        added_paths = list(mod_paths - orig_paths)
        removed_paths = list(orig_paths - mod_paths)
        common_paths = orig_paths & mod_paths

        changed_operations = []
        for p in common_paths:
            orig_methods = set(orig["paths"][p].keys())
            mod_methods = set(mod["paths"][p].keys())
            added_ops = list(mod_methods - orig_methods)
            removed_ops = list(orig_methods - mod_methods)
            if added_ops or removed_ops:
                changed_operations.append({
                    "path": p,
                    "added_methods": added_ops,
                    "removed_methods": removed_ops,
                })

        orig_info = orig.get("info", {})
        mod_info = mod.get("info", {})

        return {
            "success": True,
            "tool_used": "basic-diff (install wiretap or oasdiff for full analysis)",
            "compared": {
                "original": original_spec,
                "modified": modified_spec,
                "original_version": orig_info.get("version", "unknown"),
                "modified_version": mod_info.get("version", "unknown"),
            },
            "summary": {
                "added_paths": added_paths,
                "removed_paths": removed_paths,
                "potentially_breaking_removals": len(removed_paths) > 0 or any(op["removed_methods"] for op in changed_operations),
                "changed_operations": changed_operations,
                "total_original_paths": len(orig_paths),
                "total_modified_paths": len(mod_paths),
            },
            "recommendation": "Install wiretap (brew install pb33f/taps/wiretap) for comprehensive diff analysis with breaking change detection",
        }

    except FileNotFoundError as e:
        return {
            "success": False,
            "error": f"Spec file not found: {str(e)}",
            "compared": {"original": original_spec, "modified": modified_spec},
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to compare specs: {str(e)}",
            "suggestion": "Install wiretap (brew install pb33f/taps/wiretap) or oasdiff for full diff support",
        }




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
