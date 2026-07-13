#!/usr/bin/env python3

import argparse
import subprocess
import sys
import tempfile
import os
import shutil
import re
import threading
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Colors ---
BLUE = '\033[38;5;117m'
YELLOW = '\033[38;5;226m'
GREEN = '\033[0;32m'
RED = '\033[0;31m'
GREY = '\033[38;5;244m'
NC = '\033[0m'

# Thread lock for synchronized output
print_lock = threading.Lock()

# Global debug flag
DEBUG_MODE = False

# Protocol port mappings
PROTO_PORTS = {
    'nfs': 2049,
    'ftp': 21,
    'smb': 445,
    'vnc': 5900,
    'winrm': 5985,
    'ssh': 22,
    'rdp': 3389,
    'wmi': 135,
    'ldap': 389,
    'mssql': 1433
}

ALL_PROTOS = ['nfs', 'ftp', 'smb', 'vnc', 'winrm', 'ssh', 'rdp', 'wmi', 'ldap', 'mssql']


def safe_print(*args, **kwargs):
    """Thread-safe print function."""
    with print_lock:
        print(*args, **kwargs)


def debug_print(*args, **kwargs):
    """
    Only prints if DEBUG_MODE is True.
    """
    global DEBUG_MODE
    if DEBUG_MODE:
        # Add grey color to the message if not already colored
        colored_args = []
        for arg in args:
            if isinstance(arg, str) and not arg.startswith('\033'):
                colored_args.append(f"{GREY}{arg}{NC}")
            else:
                colored_args.append(arg)
        with print_lock:
            print(*colored_args, **kwargs)


def find_nxc() -> Optional[str]:
    """
    Find nxc (NetExec) executable in the system PATH.
    Checks for both 'nxc' and 'netexec' commands.
    """
    debug_print(f"[*] Searching for nxc in PATH...")
    
    nxc_path = shutil.which("nxc") or shutil.which("netexec")
    
    if not nxc_path:
        debug_print(f"[*] nxc not found, trying netexec...")
        nxc_path = shutil.which("netexec")
    
    if nxc_path:
        debug_print(f"[*] Found nxc at: {nxc_path}")
    else:
        debug_print(f"[*] nxc not found in PATH")
        safe_print(f"{RED}[!] ERROR: nxc (netexec) not found in system{NC}")
        safe_print(f"{RED}[!] Make sure it's installed and in your PATH{NC}")
        safe_print(f"{RED}[!] Installation: pip install netexec{NC}")
        sys.exit(1)
    
    return nxc_path


def parse_nxc_output(output: str, protocol: str, username: str, password: str) -> Tuple[bool, str]:
    """
    Parse nxc output to determine if credentials were valid.
    
    Looks for the following patterns:
    Valid: [+] domain\\username:password
    Invalid: [-] domain\\username:password STATUS_ERROR
    Invalid: [-] domain\\username:password 
    """
    # Clean the output for parsing
    output_lines = output.strip().split('\n')
    
    # Pattern to extract username:password combination from nxc output
    domain_user_pass_pattern = r'\[([+-])\]\s+([^\\]+)\\([^:]+):([^\s]*)(?:\s+(.+))?'
    
    # Track if we found a match for our specific credentials
    found_our_creds = False
    is_valid = False
    status_message = ""
    
    debug_print(f"[*] Parsing nxc output for {protocol} ({len(output_lines)} lines)")
    
    for line in output_lines:
        match = re.search(domain_user_pass_pattern, line)
        if match:
            sign = match.group(1)  # + or -
            domain = match.group(2)  # domain or hostname
            found_username = match.group(3)  # username
            # found_password = match.group(4)  # password (could be empty)
            status = match.group(5) if match.group(5) else ""  # status message
            
            debug_print(f"[*] Found pattern: [{sign}] {domain}\\{found_username}")
            
            # Check if this line matches our credentials
            username_matches = (found_username.lower() == username.lower())
            
            if username_matches:
                found_our_creds = True
                
                # Check if credentials are valid based on sign
                if sign == "+":
                    is_valid = True
                    status_message = "Authentication successful"
                    debug_print(f"[*] Found [+] pattern for {protocol}: {domain}\\{found_username}")
                    break  # Stop at first successful match
                else:  # sign == "-"
                    is_valid = False
                    # Use the status from the output if available
                    status_message = status if status else "Authentication failed"
                    debug_print(f"[*] Found [-] pattern for {protocol}: {domain}\\{found_username} - {status_message}")
                    # Don't break, continue looking for a [+] match
    
    # If we found a [-] match but no [+] match, return the status
    if found_our_creds and not is_valid:
        return False, status_message
       
    # If we found a [+] match 
    if found_our_creds and is_valid:
        return True, "Authentication successful"
    
    # If we didn't find our specific credentials in the output,
    # look for any [+] or [-] pattern with any username
    if not found_our_creds:
        debug_print(f"[*] No specific credential match found for {username}, checking for any [+] patterns")
        
        # Look for ANY [+] pattern (successful auth with any user)
        any_success_pattern = r'\[\+\]\s+[^\\]+\\[^:]+:[^\s]*'
        any_failure_pattern = r'\[\-\]\s+[^\\]+\\[^:]+:[^\s]*(?:\s+(.+))?'
        
        # First check for any success
        success_match = re.search(any_success_pattern, output, re.IGNORECASE)
        if success_match:
            debug_print(f"[*] Found generic [+] pattern for {protocol}: {success_match.group(0)}")
            return True, "Authentication successful"
        
        # Then check for any failure with status
        failure_match = re.search(any_failure_pattern, output, re.IGNORECASE)
        if failure_match:
            status_from_match = failure_match.group(1) if failure_match.group(1) else "Authentication failed"
            debug_print(f"[*] Found generic [-] pattern for {protocol} with status: {status_from_match}")
            return False, status_from_match
    
    # If no patterns found at all, assume invalid
    debug_print(f"[*] No [+] or [-] patterns found for {protocol}, assuming invalid")
    return False, "No authentication response detected"


def check_xargs_available():
    """Check if xargs is available and return max jobs."""
    debug_print("[*] Checking xargs availability...")
    
    xargs_available = shutil.which('xargs') is not None
    max_jobs = 20
    
    if xargs_available:
        debug_print(f"[*] xargs available")
        try:
            max_jobs = int(subprocess.check_output(['nproc'], text=True).strip())
            debug_print(f"[*] Max jobs (nproc): {max_jobs}")
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError) as e:
            debug_print(f"[*] Could not determine nproc: {e}")
    else:
        debug_print(f"[*] xargs not available, using sequential mode")
    
    return xargs_available, max_jobs


def apply_protocol_defaults(proto):
    """Apply per-protocol default flags."""
    defaults = {
        'smb': ['--shares'],
        'ftp': ['--ls'],
        'mssql': ['-q', 'SELECT name FROM master.sys.databases;'],
        'nfs': ['--shares'],
        'vnc': ['--check'],
        'wmi': ['--wmi'],
        'ldap': ['--users'],
        'ssh': ['--sudo-check'],
        'winrm': ['--exec-method', 'smbexec'],
        'rdp': ['--screenshot']
    }
    result = defaults.get(proto, [])
    debug_print(f"[*] Protocol defaults for {proto}: {result}")
    return result


def get_protocol_specific_auth_flags(proto):
    """
    Get protocol-specific authentication flags for auth-only testing.
    These flags optimize the authentication check.
    """
    auth_flags = {
        'ldap': ['--simple'],      # Use simple bind for LDAP
        'ssh': ['-k'],             # Accept any SSH key
    }
    result = auth_flags.get(proto, [])
    debug_print(f"[*] Auth flags for {proto}: {result}")
    return result


def build_safe_flags(proto, use_local_auth, use_continue, auth_only=False):
    """Build safe flags list for a protocol."""
    safe_flags = []
    
    debug_print(f"[*] Building flags for {proto} (auth_only={auth_only}, local_auth={use_local_auth})")
    
    if auth_only:
        # Authentication-only mode flags
        safe_flags.extend(['--no-bruteforce', '--continue-on-success'])
        # Add protocol-specific auth flags
        safe_flags.extend(get_protocol_specific_auth_flags(proto))
    else:
        # Normal mode - add protocol defaults
        safe_flags.extend(apply_protocol_defaults(proto))
    
    # --local-auth only applies to certain protocols (Windows-based auth)
    local_auth_protos = ['smb', 'winrm', 'rdp', 'mssql', 'wmi']
    if use_local_auth and proto in local_auth_protos:
        safe_flags.append('--local-auth')
        debug_print(f"{BLUE}[!] Applying '--local-auth' for {proto}{NC}")
    
    if use_continue:
        safe_flags.append('--continue-on-success')
    
    debug_print(f"[*] Final flags for {proto}: {safe_flags}")
    return safe_flags


def execute_nxc_auth_check(nxc_path: str, protocol: str, hosts: List[str], 
                          username: str, password: str, use_local_auth: bool = False,
                          timeout: int = 20) -> Tuple[bool, str, str]:
    """
    Execute nxc command for authentication check only.
    Returns (is_valid, output, status_message).
    """
    try:
        # Build authentication-only command
        command = [
            nxc_path,
            protocol
        ] + hosts + [
            '-u', username,
            '-p', password,
            '--no-bruteforce',
            '--continue-on-success'
        ]
        
        # Add protocol-specific authentication flags
        auth_flags = get_protocol_specific_auth_flags(protocol)
        if auth_flags:
            command.extend(auth_flags)
        
        # Add local-auth if applicable
        if use_local_auth and protocol in ['smb', 'winrm', 'rdp', 'mssql', 'wmi']:
            command.append('--local-auth')
        
        debug_print(f"[*] Testing {protocol} authentication on {hosts}")
        if use_local_auth:
            debug_print(f"[*] Using --local-auth")
        debug_print(f"[*] Command: {' '.join(command)}")
        
        # Execute with timeout for auth check
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        output = result.stdout + result.stderr
        debug_print(f"[*] Raw output for {protocol}:\n{output[:500]}")
        
        # Parse output to check if authentication was successful
        is_valid, status_message = parse_nxc_output(output, protocol, username, password)
        
        return is_valid, output, status_message
        
    except subprocess.TimeoutExpired:
        debug_print(f"[*] Timeout checking {protocol} authentication")
        return False, f"Timeout checking {protocol}", "Timeout"
    except Exception as e:
        debug_print(f"[*] Error checking {protocol}: {e}")
        return False, str(e), f"Error: {e}"


def test_protocol_with_local_auth(nxc_path: str, protocol: str, hosts: List[str], 
                                  username: str, password: str, timeout: int = 20) -> Tuple[bool, str]:
    """
    Test SMB or WMI protocol both with and without --local-auth flag.
    """
    debug_print(f"[*] Starting dual authentication test for {protocol}")
    
    # Track status messages from both attempts
    status_messages = []
    
    # Test 1: Without --local-auth (default)
    is_valid_default, output_default, status_default = execute_nxc_auth_check(
        nxc_path, protocol, hosts, username, password, use_local_auth=False, timeout=timeout
    )
    
    if is_valid_default:
        debug_print(f"[*] {protocol} authentication successful without --local-auth")
        return True, status_default
    
    status_messages.append(f"Without --local-auth: {status_default}")
    debug_print(f"[*] {protocol} default auth failed: {status_default}")
    
    # Test 2: With --local-auth
    is_valid_local, output_local, status_local = execute_nxc_auth_check(
        nxc_path, protocol, hosts, username, password, use_local_auth=True, timeout=timeout
    )
    
    if is_valid_local:
        debug_print(f"[*] {protocol} authentication successful with --local-auth")
        return True, status_local
    
    status_messages.append(f"With --local-auth: {status_local}")
    debug_print(f"[*] {protocol} local auth failed: {status_local}")
    
    # Return combined status
    combined_status = "; ".join(status_messages)
    debug_print(f"[*] {protocol} authentication failed both with and without --local-auth")
    return False, combined_status


def find_live_hosts(port, hosts, xargs_available, max_jobs, timeout=1):
    """Find live hosts by checking if port is open."""
    live_hosts = []
    
    if not hosts:
        return live_hosts
    
    debug_print(f"[*] Scanning port {port} for {len(hosts)} host(s)")
    
    if xargs_available and len(hosts) > 1:
        # Use xargs with parallel execution
        debug_print(f"[*] Using xargs with {max_jobs} parallel jobs")
        hosts_str = '\n'.join(hosts)
        try:
            result = subprocess.run(
                ['xargs', '-P', str(max_jobs), '-I{}', 'bash', '-c',
                 f'nc -z -w {timeout} "$1" "$2" 2>/dev/null && printf "%s\\n" "$1"',
                 '_', '{}', str(port)],
                input=hosts_str,
                text=True,
                capture_output=True,
                timeout=60
            )
            live_hosts = [h for h in result.stdout.strip().split('\n') if h]
            debug_print(f"[*] xargs found {len(live_hosts)} live host(s) on port {port}")
        except subprocess.TimeoutExpired:
            debug_print(f"[*] Timeout while scanning hosts for port {port}")
            safe_print(f"{YELLOW}[!] Timeout while scanning hosts for port {port}{NC}")
            return []
        except Exception as e:
            debug_print(f"[*] Error scanning hosts: {e}")
            safe_print(f"{YELLOW}[!] Error scanning hosts: {e}{NC}")
            return []
    else:
        # Sequential execution
        debug_print(f"[*] Using sequential host scanning")
        for host in hosts:
            try:
                subprocess.run(
                    ['nc', '-z', '-w', str(timeout), host, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                live_hosts.append(host)
                debug_print(f"[*] Host {host} is alive on port {port}")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                debug_print(f"[*] Host {host} is not responding on port {port}")
    
    return live_hosts


def parse_targets(targets_raw):
    """Parse targets from file or string."""
    targets_path = Path(targets_raw)
    debug_print(f"[*] Parsing targets: {targets_raw}")
    
    if targets_path.is_file():
        debug_print(f"[*] Reading targets from file: {targets_path}")
        with open(targets_path, 'r') as f:
            hosts = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        debug_print(f"[*] Loaded {len(hosts)} host(s) from file")
    else:
        hosts = [targets_raw]
        debug_print(f"[*] Using single target: {targets_raw}")
    
    return hosts


def process_single_protocol(proto_data):
    """
    Process a single protocol for scanning.
    This function is designed to be called in parallel.
    
    Args:
        proto_data: Tuple containing (proto, host_list, args, nxc_path, xargs_available, max_jobs)
    
    Returns:
        Tuple of (proto, is_valid, status_message, live_count, total_count)
    """
    proto, host_list, args, nxc_path, xargs_available, max_jobs = proto_data
    port = PROTO_PORTS.get(proto)
    
    debug_print(f"[*] Processing protocol: {proto} (port {port})")
    
    # Port checking phase
    if args.no_port_check or port is None:
        live_hosts = host_list.copy()
        debug_print(f"[*] Skipping port check for {proto}")
        debug_print(f"{BLUE}[*] [{proto.upper()}] Skipping port check{NC}")
    else:
        debug_print(f"{GREY}[*] [{proto.upper()}] Checking port {port}...{NC}")
        live_hosts = find_live_hosts(port, host_list, xargs_available, max_jobs, args.port_timeout)
        debug_print(f"{GREY}[*] [{proto.upper()}] Found {len(live_hosts)} live host(s){NC}")
    
    if not live_hosts:
        debug_print(f"[*] No live hosts for {proto}")
        debug_print(f"{GREY}○ {proto.upper():6s} | 0/{len(host_list):<3d} hosts | port {port} - No live hosts{NC}")
        return (proto, False, "No live hosts", 0, len(host_list))
    
    # Authentication testing phase
    debug_print(f"[*] Starting auth test for {proto} on {len(live_hosts)} host(s)")
    safe_print(f"{GREEN}[+] [{proto.upper()}] Testing {len(live_hosts)} host(s)...{NC}")
    
    # For SMB and WMI, test both with and without --local-auth
    if proto in ["smb", "wmi"]:
        debug_print(f"[*] Using dual auth test for {proto}")
        is_valid, status_message = test_protocol_with_local_auth(
            nxc_path, proto, live_hosts, args.username, args.password, args.timeout
        )
    else:
        # For other protocols, use normal authentication check
        debug_print(f"[*] Using single auth test for {proto}")
        is_valid, output, status_message = execute_nxc_auth_check(
            nxc_path, proto, live_hosts, args.username, args.password, 
            use_local_auth=args.local_auth, timeout=args.timeout
        )
    
    # Display result
    if is_valid:
        debug_print(f"[*] {proto} authentication SUCCESS: {status_message}")
        safe_print(f"{GREEN}✓ {proto.upper():6s} | {len(live_hosts):3d}/{len(host_list):<3d} hosts | port {port} - {status_message}{NC}")
    else:
        debug_print(f"[*] {proto} authentication FAILED: {status_message}")
        safe_print(f"{RED}✗ {proto.upper():6s} | {len(live_hosts):3d}/{len(host_list):<3d} hosts | port {port} - {status_message}{NC}")
    
    return (proto, is_valid, status_message, len(live_hosts), len(host_list))


def main():
    global DEBUG_MODE
    
    # Custom help formatter to show protocols
    class CustomFormatter(argparse.RawDescriptionHelpFormatter):
        pass
    
    parser = argparse.ArgumentParser(
        description=f'''
{YELLOW}╔═══════════════════════════════════════════════════════════════════╗
║            nxc-sweep - Multi-Protocol Sprayer for NetExec         ║
╚═══════════════════════════════════════════════════════════════════╝{NC}

{GREEN}Available Protocols:{NC}
  all                 - Spray all protocols
  nfs  (2049)        - Network File System
  ftp  (21)          - File Transfer Protocol
  smb  (445)         - Server Message Block
  vnc  (5900)        - Virtual Network Computing
  winrm (5985)       - Windows Remote Management
  ssh  (22)          - Secure Shell
  rdp  (3389)        - Remote Desktop Protocol
  wmi  (135)         - Windows Management Instrumentation
  ldap (389)         - Lightweight Directory Access Protocol
  mssql (1433)       - Microsoft SQL Server

{GREY}Note: Each protocol sprays with sensible built-in defaults automatically.
For SMB and WMI, both local and domain auth are tested automatically.
Protocols are tested in parallel using worker threads.
Use -d/--debug for verbose debug output.{NC}
        ''',
        formatter_class=CustomFormatter,
        add_help=True
    )
    
    # Positional arguments
    parser.add_argument('protocols', 
                       help='Protocol(s) to use (comma-separated or "all")')
    parser.add_argument('targets', 
                       help='Target IP(s), CIDR range, or file containing targets')
    
    # Required arguments
    parser.add_argument('-u', '--username', required=True, 
                       help='Username for authentication')
    parser.add_argument('-p', '--password', required=True, 
                       help='Password for authentication')
    
    # Optional flags
    parser.add_argument('-w', '--workers', type=int, default=5,
                       help='Number of parallel workers for protocol testing (default: 5)')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Enable debug output (verbose grey text messages)')
    parser.add_argument('--local-auth', action='store_true',
                       help='Authenticate against local accounts (smb, winrm, rdp, mssql, wmi)')
    parser.add_argument('--continue-on-success', action='store_true',
                       help='Keep testing remaining credentials/hosts after success')
    parser.add_argument('--no-port-check', action='store_true',
                       help='Skip port checking and spray all targets')
    parser.add_argument('--timeout', type=int, default=20,
                       help='Timeout for authentication checks in seconds (default: 20)')
    parser.add_argument('--port-timeout', type=int, default=1,
                       help='Timeout for port checking in seconds (default: 1)')
    
    # Parse arguments
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    args = parser.parse_args()
    
    # Set global debug mode
    DEBUG_MODE = args.debug
    
    if DEBUG_MODE:
        safe_print(f"{GREY}[*] Debug mode enabled{NC}")
    
    # Check for nxc executable early
    nxc_path = find_nxc()
    
    # Check for xargs availability early
    xargs_available, max_jobs = check_xargs_available()
    
    debug_print(f"[*] NXC Path: {nxc_path}")
    debug_print(f"[*] Xargs available: {xargs_available}")
    debug_print(f"[*] Max jobs: {max_jobs}")
    
    # Parse protocols
    if args.protocols.lower() == 'all':
        proto_array = ALL_PROTOS
    else:
        proto_array = [p.strip().lower() for p in args.protocols.split(',')]
    
    debug_print(f"[*] Requested protocols: {proto_array}")
    
    # Validate protocols
    valid_protos = []
    invalid_protos = []
    for proto in proto_array:
        if proto in PROTO_PORTS:
            valid_protos.append(proto)
        else:
            invalid_protos.append(proto)
    
    if invalid_protos:
        debug_print(f"[*] Invalid protocols: {invalid_protos}")
        safe_print(f"{YELLOW}[!] Warning: Unknown protocols skipped: {', '.join(invalid_protos)}{NC}")
        safe_print(f"    Valid protocols: {', '.join(ALL_PROTOS)}")
    
    if not valid_protos:
        safe_print(f"{YELLOW}[-] No valid protocols specified.{NC}")
        sys.exit(1)
    
    debug_print(f"[*] Valid protocols to test: {valid_protos}")
    
    # Parse targets
    host_list = parse_targets(args.targets)
    
    if not host_list:
        safe_print(f"{YELLOW}[-] No valid targets found.{NC}")
        sys.exit(1)
    
    debug_print(f"[*] Total targets: {len(host_list)}")
    
    safe_print(f"\n{GREEN}[+] Starting nxc-sweep{NC}")
    safe_print(f"    nxc Path:    {nxc_path}")
    safe_print(f"    Protocols:   {', '.join(valid_protos).upper()}")
    safe_print(f"    Targets:     {len(host_list)} host(s)")
    safe_print(f"    Username:    {args.username}")
    safe_print(f"    Password:    {'*' * len(args.password)}")
    safe_print(f"    Workers:     {args.workers}")
    safe_print(f"    Timeout:     {args.timeout}s")
    safe_print(f"    Port Timeout: {args.port_timeout}s")
    safe_print(f"    Debug Mode:  {'ON' if DEBUG_MODE else 'OFF'}")
    safe_print()
    
    # Create temp directory for target file
    tmp_dir = tempfile.mkdtemp()
    target_file = os.path.join(tmp_dir, 'targets.txt')
    
    debug_print(f"[*] Temp directory: {tmp_dir}")
    
    # Results tracking
    results = {}
    success_count = 0
    failed_count = 0
    
    try:
        # Prepare data for parallel execution
        protocol_tasks = [
            (proto, host_list, args, nxc_path, xargs_available, max_jobs)
            for proto in valid_protos
        ]
        
        debug_print(f"[*] Created {len(protocol_tasks)} protocol tasks")
        debug_print(f"[*] Starting ThreadPoolExecutor with {args.workers} workers")
        
        # Use ThreadPoolExecutor for parallel protocol testing
        safe_print(f"{GREEN}[+] Starting parallel scan with {args.workers} workers...{NC}")
        safe_print(f"{'='*60}")
        
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            # Submit all tasks
            future_to_proto = {
                executor.submit(process_single_protocol, task): task[0]
                for task in protocol_tasks
            }
            
            debug_print(f"[*] Submitted {len(future_to_proto)} tasks to executor")
            
            # Process completed tasks as they finish
            for future in as_completed(future_to_proto):
                proto = future_to_proto[future]
                try:
                    proto_result = future.result()
                    proto_name, is_valid, status_message, live_count, total_count = proto_result
                    results[proto_name] = (is_valid, status_message)
                    
                    debug_print(f"[*] Task completed for {proto_name}: valid={is_valid}")
                    
                    if is_valid:
                        success_count += 1
                    else:
                        failed_count += 1
                        
                except Exception as e:
                    debug_print(f"[*] Error processing {proto}: {e}")
                    safe_print(f"{RED}[!] Error processing {proto}: {e}{NC}")
                    results[proto] = (False, f"Error: {e}")
                    failed_count += 1
        
        debug_print(f"[*] All tasks completed")
        safe_print(f"{'='*60}")
    
    except KeyboardInterrupt:
        safe_print(f"\n{YELLOW}[!] Scan interrupted by user.{NC}")
    finally:
        # Cleanup temp directory
        debug_print(f"[*] Cleaning up temp directory: {tmp_dir}")
        shutil.rmtree(tmp_dir, ignore_errors=True)
    
    # Final summary
    total = success_count + failed_count
    safe_print(f"\n{'='*60}")
    safe_print("NXC-SWEEP SCAN SUMMARY")
    safe_print(f"{'='*60}")
    safe_print(f"Protocols tested: {total}")
    safe_print(f"{GREEN}Valid credentials: {success_count}{NC}")
    safe_print(f"{RED}Invalid credentials: {failed_count}{NC}")
    safe_print(f"\nDetailed Results:")
    safe_print(f"{'-'*60}")
    
    for proto in valid_protos:
        if proto in results:
            is_valid, status = results[proto]
            if is_valid:
                safe_print(f"  {GREEN}✓ {proto.upper():6s} - {status}{NC}")
            else:
                safe_print(f"  {RED}✗ {proto.upper():6s} - {status}{NC}")
        else:
            safe_print(f"  {GREY}[*] {proto.upper():6s} - Not tested{NC}")
    
    safe_print(f"{'='*60}\n")
    
    debug_print(f"[*] Exiting with code {'0' if success_count > 0 else '1'}")
    
    # Exit with appropriate code
    sys.exit(0 if success_count > 0 else 1)


if __name__ == '__main__':
    main()