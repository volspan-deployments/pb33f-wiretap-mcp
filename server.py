from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn
import threading
from fastmcp import FastMCP
import httpx
import os
import json
import subprocess
import shutil
import tempfile
from typing import Optional, List

mcp = FastMCP("wiretap")


def find_wiretap_binary() -> Optional[str]:
    """Find the wiretap binary in common locations."""
    # Check PATH first
    binary = shutil.which("wiretap")
    if binary:
        return binary
    
    # Check common npm global install locations
    common_paths = [
        os.path.expanduser("~/.npm-global/bin/wiretap"),
        os.path.expanduser("~/node_modules/.bin/wiretap"),
        "/usr/local/bin/wiretap",
        "/usr/bin/wiretap",
        "/opt/homebrew/bin/wiretap",
    ]
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    
    return None


@mcp.tool()
async def start_wiretap(
    api_spec: str,
    target_url: str,
    port: int = 9090,
    ui_port: int = 9091,
    config_file: Optional[str] = None,
    base: Optional[str] = None,
    static_dir: Optional[str] = None,
) -> dict:
    """
    Start the wiretap proxy server to intercept and validate API traffic against an OpenAPI specification.
    Use this to launch the daemon that listens for HTTP requests, proxies them to the target API,
    and checks for contract violations. This is the primary entry point for running wiretap.
    """
    binary = find_wiretap_binary()
    if not binary:
        return {
            "success": False,
            "error": "wiretap binary not found. Install it via: npm install -g @pb33f/wiretap or brew install pb33f/taps/wiretap",
            "install_instructions": {
                "npm": "npm install -g @pb33f/wiretap",
                "yarn": "yarn global add @pb33f/wiretap",
                "homebrew": "brew install pb33f/taps/wiretap",
                "curl": "curl -fsSL https://pb33f.io/wiretap/install.sh | sh",
                "docker": "docker pull pb33f/wiretap"
            }
        }

    cmd = [
        binary,
        "-u", target_url,
        "-s", api_spec,
        "-p", str(port),
        "-m", str(ui_port),
    ]

    if config_file:
        cmd.extend(["-c", config_file])
    if base:
        cmd.extend(["-b", base])
    if static_dir:
        cmd.extend(["--static", static_dir])

    command_str = " ".join(cmd)

    return {
        "success": True,
        "message": "wiretap command prepared. Run this command in your terminal to start the proxy server (it runs as a foreground process).",
        "command": command_str,
        "binary": binary,
        "configuration": {
            "api_spec": api_spec,
            "target_url": target_url,
            "proxy_port": port,
            "ui_port": ui_port,
            "config_file": config_file,
            "base_path": base,
            "static_dir": static_dir
        },
        "urls": {
            "proxy": f"http://localhost:{port}",
            "dashboard": f"http://localhost:{ui_port}"
        },
        "note": "wiretap runs as an interactive foreground process. Use the command above in a separate terminal. The dashboard UI will be available at the ui_port URL once started."
    }


@mcp.tool()
async def validate_request(
    api_spec: str,
    method: str,
    path: str,
    request_body: Optional[str] = None,
    response_body: Optional[str] = None,
    response_code: int = 200,
    headers: Optional[List[str]] = None,
) -> dict:
    """
    Validate a specific HTTP request and response pair against an OpenAPI specification
    without running the full proxy. Use this to check a single API call for contract compliance,
    useful in CI/CD pipelines or batch validation scenarios.
    """
    binary = find_wiretap_binary()
    if not binary:
        return {
            "success": False,
            "error": "wiretap binary not found. Install it via: npm install -g @pb33f/wiretap or brew install pb33f/taps/wiretap",
            "install_instructions": {
                "npm": "npm install -g @pb33f/wiretap",
                "yarn": "yarn global add @pb33f/wiretap",
                "homebrew": "brew install pb33f/taps/wiretap"
            }
        }

    # Build the wiretap validate command
    cmd = [
        binary,
        "validate",
        "-s", api_spec,
        "--method", method.upper(),
        "--path", path,
        "--response-code", str(response_code),
    ]

    if request_body:
        cmd.extend(["--request-body", request_body])
    if response_body:
        cmd.extend(["--response-body", response_body])
    if headers:
        for header in headers:
            cmd.extend(["--header", header])

    command_str = " ".join(cmd)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout + result.stderr

        return {
            "success": result.returncode == 0,
            "command": command_str,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "violations_detected": result.returncode != 0,
            "validation_details": {
                "api_spec": api_spec,
                "method": method.upper(),
                "path": path,
                "response_code": response_code,
                "headers": headers or []
            }
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "command": command_str,
            "error": "Validation timed out after 30 seconds"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"wiretap binary not found at path: {binary}",
            "command": command_str
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "command": command_str
        }


@mcp.tool()
async def configure_wiretap(
    target_url: str,
    api_spec: str,
    output_file: str = ".wiretap",
    path_rewrites: Optional[List[str]] = None,
    ignore_paths: Optional[List[str]] = None,
    inject_headers: Optional[List[str]] = None,
    strip_base_path: Optional[str] = None,
    hard_errors: bool = False,
) -> dict:
    """
    Generate or update a wiretap configuration file with path rewrites, ignored paths,
    header injections, and other proxy settings. Use this to set up advanced routing rules
    before starting the proxy, or to modify an existing configuration.
    """
    config_lines = []
    config_lines.append(f"# wiretap configuration file")
    config_lines.append(f"# Generated by wiretap MCP server")
    config_lines.append("")
    config_lines.append(f"contract: {api_spec}")
    config_lines.append(f"upstreamURL: {target_url}")
    config_lines.append("")

    if hard_errors:
        config_lines.append("hardErrors: true")
        config_lines.append("")

    if strip_base_path:
        config_lines.append(f"stripBasePath: {strip_base_path}")
        config_lines.append("")

    if inject_headers:
        config_lines.append("headers:")
        for header in inject_headers:
            parts = header.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                config_lines.append(f"  - name: {key}")
                config_lines.append(f"    value: \"{value}\"")
        config_lines.append("")

    if ignore_paths:
        config_lines.append("ignorePaths:")
        for p in ignore_paths:
            config_lines.append(f"  - {p}")
        config_lines.append("")

    if path_rewrites:
        config_lines.append("pathConfigurations:")
        for rewrite in path_rewrites:
            parts = rewrite.split(":", 1)
            if len(parts) == 2:
                original = parts[0].strip()
                rewritten = parts[1].strip()
                config_lines.append(f"  - path: {original}")
                config_lines.append(f"    rewritePath: {rewritten}")
        config_lines.append("")

    config_content = "\n".join(config_lines)

    try:
        output_path = os.path.abspath(output_file)
        with open(output_path, "w") as f:
            f.write(config_content)

        return {
            "success": True,
            "message": f"Configuration file written to {output_path}",
            "output_file": output_path,
            "config_content": config_content,
            "configuration_summary": {
                "target_url": target_url,
                "api_spec": api_spec,
                "hard_errors": hard_errors,
                "strip_base_path": strip_base_path,
                "path_rewrites": path_rewrites or [],
                "ignore_paths": ignore_paths or [],
                "inject_headers": inject_headers or []
            },
            "next_steps": f"Start wiretap with: wiretap -u {target_url} -s {api_spec} -c {output_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "config_content": config_content,
            "message": "Failed to write config file. Config content is provided above for manual use."
        }


@mcp.tool()
async def inspect_violations(
    host: str = "localhost",
    ui_port: int = 9091,
    filter_path: Optional[str] = None,
    filter_method: Optional[str] = None,
    limit: int = 50,
    show_request_violations: bool = True,
    show_response_violations: bool = True,
) -> dict:
    """
    Query and display OpenAPI contract violations captured by a running wiretap instance.
    Use this to retrieve details about request/response mismatches, schema violations,
    and missing required fields detected during proxied traffic.
    """
    base_url = f"http://{host}:{ui_port}"

    # wiretap exposes a WebSocket/API on the ui_port for the dashboard
    # We attempt to query the API endpoint for transactions/violations
    api_endpoints_to_try = [
        f"{base_url}/api/transactions",
        f"{base_url}/transactions",
        f"{base_url}/api/violations",
        f"{base_url}/violations",
    ]

    async with httpx.AsyncClient(timeout=10.0) as client:
        # First check if wiretap is running
        try:
            health_resp = await client.get(base_url)
            wiretap_running = True
            status_code = health_resp.status_code
        except httpx.ConnectError:
            return {
                "success": False,
                "error": f"Cannot connect to wiretap at {base_url}. Make sure wiretap is running.",
                "wiretap_running": False,
                "dashboard_url": base_url,
                "suggestion": "Start wiretap first using the start_wiretap tool or run: wiretap -u <target_url> -s <api_spec>"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "dashboard_url": base_url
            }

        # Try to get violations data from the API
        violations_data = None
        working_endpoint = None

        for endpoint in api_endpoints_to_try:
            try:
                resp = await client.get(
                    endpoint,
                    headers={"Accept": "application/json"}
                )
                if resp.status_code == 200:
                    try:
                        violations_data = resp.json()
                        working_endpoint = endpoint
                        break
                    except Exception:
                        pass
            except Exception:
                continue

        if violations_data is None:
            return {
                "success": True,
                "wiretap_running": True,
                "dashboard_url": base_url,
                "message": "wiretap is running but the violations API endpoint could not be reached directly. "
                           "Violations are best viewed through the wiretap dashboard UI.",
                "dashboard_access": {
                    "url": base_url,
                    "note": "Open this URL in your browser to see real-time violations and traffic"
                },
                "filter_params": {
                    "filter_path": filter_path,
                    "filter_method": filter_method,
                    "limit": limit,
                    "show_request_violations": show_request_violations,
                    "show_response_violations": show_response_violations
                }
            }

        # Process and filter violations
        transactions = violations_data
        if isinstance(violations_data, dict):
            transactions = violations_data.get("transactions", violations_data.get("data", []))

        if not isinstance(transactions, list):
            transactions = []

        # Apply filters
        filtered = []
        for t in transactions:
            path = t.get("path", t.get("url", ""))
            method = t.get("method", "").upper()

            if filter_path and filter_path not in path:
                continue
            if filter_method and method != filter_method.upper():
                continue

            # Filter violation types
            result_t = dict(t)
            if not show_request_violations:
                result_t.pop("requestViolations", None)
                result_t.pop("request_violations", None)
            if not show_response_violations:
                result_t.pop("responseViolations", None)
                result_t.pop("response_violations", None)

            filtered.append(result_t)

        # Apply limit
        filtered = filtered[:limit]

        return {
            "success": True,
            "wiretap_running": True,
            "dashboard_url": base_url,
            "api_endpoint": working_endpoint,
            "total_transactions": len(transactions),
            "filtered_count": len(filtered),
            "filters_applied": {
                "path": filter_path,
                "method": filter_method,
                "limit": limit,
                "show_request_violations": show_request_violations,
                "show_response_violations": show_response_violations
            },
            "transactions": filtered
        }


@mcp.tool()
async def run_pipeline_check(
    api_spec: str,
    har_file: Optional[str] = None,
    output_format: str = "console",
    output_file: Optional[str] = None,
    fail_on_violations: bool = True,
    severity_threshold: str = "warn",
) -> dict:
    """
    Run wiretap in CI/CD pipeline mode to validate a HAR (HTTP Archive) file or recorded
    traffic against an OpenAPI specification and output violations as a structured report.
    Use this for automated compliance checks in build pipelines where no interactive proxy is needed.
    """
    binary = find_wiretap_binary()
    if not binary:
        return {
            "success": False,
            "error": "wiretap binary not found. Install it via: npm install -g @pb33f/wiretap or brew install pb33f/taps/wiretap",
            "install_instructions": {
                "npm": "npm install -g @pb33f/wiretap",
                "yarn": "yarn global add @pb33f/wiretap",
                "homebrew": "brew install pb33f/taps/wiretap",
                "curl": "curl -fsSL https://pb33f.io/wiretap/install.sh | sh"
            }
        }

    if not har_file:
        return {
            "success": False,
            "error": "A HAR file is required for pipeline validation mode.",
            "suggestion": "Record API traffic using browser dev tools or a tool like Charles Proxy, then save as a .har file.",
            "command_template": f"{binary} pipeline -s {api_spec} -f <path-to-traffic.har>"
        }

    # Build pipeline command
    cmd = [
        binary,
        "pipeline",
        "-s", api_spec,
        "-f", har_file,
    ]

    if output_format and output_format != "console":
        cmd.extend(["--format", output_format])

    if output_file:
        cmd.extend(["-o", output_file])

    if severity_threshold:
        cmd.extend(["--severity", severity_threshold])

    command_str = " ".join(cmd)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        violations_found = result.returncode != 0
        pipeline_passed = not violations_found or not fail_on_violations

        report = {
            "success": pipeline_passed,
            "command": command_str,
            "return_code": result.returncode,
            "violations_found": violations_found,
            "pipeline_passed": pipeline_passed,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "configuration": {
                "api_spec": api_spec,
                "har_file": har_file,
                "output_format": output_format,
                "output_file": output_file,
                "fail_on_violations": fail_on_violations,
                "severity_threshold": severity_threshold
            }
        }

        if output_file and os.path.exists(output_file):
            try:
                with open(output_file, "r") as f:
                    report_content = f.read()
                if output_format == "json":
                    try:
                        report["report_data"] = json.loads(report_content)
                    except Exception:
                        report["report_content"] = report_content
                else:
                    report["report_content"] = report_content
            except Exception as e:
                report["report_read_error"] = str(e)

        return report

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "command": command_str,
            "error": "Pipeline check timed out after 120 seconds"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": f"wiretap binary not found at path: {binary}",
            "command": command_str
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "command": command_str
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
