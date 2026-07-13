#!/usr/bin/env python3

import argparse
import subprocess
import sys
import tempfile
import os
import shutil
import re
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

# --- Colors ---
BLUE = '\033[38;5;117m'
YELLOW = '\033[38;5;226m'
GREEN = '\033[0;32m'
RED = '\033[0;31m'
GREY = '\033[38;5;244m'
NC = '\033[0m'

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


def find_nxc() -> Optional[str]:
    """
    Find nxc (NetExec) executable in the system PATH.
    Checks for both 'nxc' and 'netexec' commands.
    """
    nxc_path = shutil.which("nxc") or shutil.which("netexec")
    
    if not nxc_path:
        print(f"{RED}[!] ERROR: nxc (netexec) not found in system{NC}")
        print(f"{RED}[!] Make sure it's installed and in your PATH{NC}")
        print(f"{RED}[!] Installation: pip install netexec{NC}")
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
    # Matches patterns like:
    # [+] domain\username:password
    # [-] domain\username:password STATUS_REASON
    domain_user_pass_pattern = r'\[([+-])\]\s+([^\\]+)\\([^:]+):([^\s]*)(?:\s+(.+))?'
    
    # Track if we found a match for our specific credentials
    found_our_creds = False
    is_valid = False
    status_message = ""
    
    for line in output_lines:
        match = re.search(domain_user_pass_pattern, line)
        if match:
            sign = match.group(1)  # + or -
            domain = match.group(2)  # domain or hostname
            found_username = match.group(3)  # username
            found_password = match.group(4)  # password (could be empty)
            status = match.group(5) if match.group(5) else ""  # status message
            
            # Check if this line matches our credentials
            username_matches = (found_username.lower() == username.lower())
            
            if username_matches:
                found_our_creds = True
                
                # Check if credentials are valid based on sign
                if sign == "+":
                    is_valid = True
                    status_message = "Authentication successful"
                    break  # Stop at first successful match
                else:  # sign == "-"
                    is_valid = False
                    # Use the status from the output if available
                    status_message = status if status else "Authentication failed"
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
        # Look for ANY [+] pattern (successful auth with any user)
        any_success_pattern = r'\[\+\]\s+[^\\]+\\[^:]+:[^\s]*'
        any_failure_pattern = r'\[\-\]\s+[^\\]+\\[^:]+:[^\s]*(?:\s+(.+))?'
        
        # First check for any success
        success_match = re.search(any_success_pattern, output, re.IGNORECASE)
        if success_match:
            return True, "Authentication successful"
        
        # Then check for any failure with status
        failure_match = re.search(any_failure_pattern, output, re.IGNORECASE)
        if failure_match:
            status_from_match = failure_match.group(1) if failure_match.group(1) else "Authentication failed"
            return False, status_from_match
    
    # If no patterns found at all, assume invalid
    return False, "No authentication response detected"


def check_xargs_available():
    """Check if xargs is available and return max jobs."""
    xargs_available = shutil.which('xargs') is not None
    max_jobs = 20
    if xargs_available:
        try:
            max_jobs = int(subprocess.check_output(['nproc'], text=True).strip())
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
            pass
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
    return defaults.get(proto, [])


def get_protocol_specific_auth_flags(proto):
    """
    Get protocol-specific authentication flags for auth-only testing.
    These flags optimize the authentication check.
    """
    auth_flags = {
        'ldap': ['--simple'],      # Use simple bind for LDAP
        'ssh': ['-k'],             # Accept any SSH key
    }
    return auth_flags.get(proto, [])


def build_safe_flags(proto, use_local_auth, use_continue, auth_only=False):
    """Build safe flags list for a protocol."""
    safe_flags = []
    
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
        print(f"{BLUE}[!] Applying '--local-auth' for {proto}{NC}")
    
    if use_continue:
        safe_flags.append('--continue-on-success')
    
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
        
        # Execute with timeout for auth check
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        output = result.stdout + result.stderr
        
        # Parse output to check if authentication was successful
        is_valid, status_message = parse_nxc_output(output, protocol, username, password)
        
        return is_valid, output, status_message
        
    except subprocess.TimeoutExpired:
        return False, f"Timeout checking {protocol}", "Timeout"
    except Exception as e:
        return False, str(e), f"Error: {e}"


def test_protocol_with_local_auth(nxc_path: str, protocol: str, hosts: List[str], 
                                  username: str, password: str, timeout: int = 20) -> Tuple[bool, str]:
    """
    Test SMB or WMI protocol both with and without --local-auth flag.
    """
    # Track status messages from both attempts
    status_messages = []
    
    # Test 1: Without --local-auth (default)
    is_valid_default, output_default, status_default = execute_nxc_auth_check(
        nxc_path, protocol, hosts, username, password, use_local_auth=False, timeout=timeout
    )
    
    if is_valid_default:
        return True, status_default
    
    status_messages.append(f"Without --local-auth: {status_default}")
    
    # Test 2: With --local-auth
    is_valid_local, output_local, status_local = execute_nxc_auth_check(
        nxc_path, protocol, hosts, username, password, use_local_auth=True, timeout=timeout
    )
    
    if is_valid_local:
        return True, status_local
    
    status_messages.append(f"With --local-auth: {status_local}")
    
    # Return combined status
    combined_status = "; ".join(status_messages)
    return False, combined_status


def find_live_hosts(port, hosts, xargs_available, max_jobs, timeout=1):
    """Find live hosts by checking if port is open."""
    live_hosts = []
    
    if not hosts:
        return live_hosts
    
    if xargs_available and len(hosts) > 1:
        # Use xargs with parallel execution
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
        except subprocess.TimeoutExpired:
            print(f"{YELLOW}[!] Timeout while scanning hosts for port {port}{NC}")
            return []
        except Exception as e:
            print(f"{YELLOW}[!] Error scanning hosts: {e}{NC}")
            return []
    else:
        # Sequential execution
        for host in hosts:
            try:
                subprocess.run(
                    ['nc', '-z', '-w', str(timeout), host, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2
                )
                live_hosts.append(host)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
    
    return live_hosts


def parse_targets(targets_raw):
    """Parse targets from file or string."""
    targets_path = Path(targets_raw)
    if targets_path.is_file():
        with open(targets_path, 'r') as f:
            hosts = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    else:
        hosts = [targets_raw]
    return hosts


def spray_protocol(proto, live_hosts, user, password, safe_flags):
    """Execute nxc spray for a protocol."""
    cmd = ['nxc', proto] + live_hosts + ['-u', user, '-p', password] + safe_flags
    
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode
    except FileNotFoundError:
        print(f"{YELLOW}[-] Error: 'nxc' command not found. Please install NetExec.{NC}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Spray interrupted by user.{NC}")
        sys.exit(1)


def print_summary(protocol, live_count, total_count, success=False):
    """Print a summary line for protocol spraying."""
    status = f"{GREEN}✓{NC}" if success else f"{GREY}○{NC}"
    print(f"{status} {protocol.upper():6s} | {live_count:3d}/{total_count:<3d} hosts | port {PROTO_PORTS.get(protocol, 'N/A')}")


def main():
    # Check for nxc executable early
    nxc_path = find_nxc()
    
    # Check for xargs availability early
    xargs_available, max_jobs = check_xargs_available()
    
    # Custom help formatter to show protocols
    class CustomFormatter(argparse.RawDescriptionHelpFormatter):
        pass
    
    parser = argparse.ArgumentParser(
        description=f'''
{YELLOW}╔══════════════════════════════════════════════════════════════╗
║                    NXCStorm - Multi-Protocol Sprayer         ║
╚══════════════════════════════════════════════════════════════╝{NC}

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
For SMB and WMI, both local and domain auth are tested automatically.{NC}
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
    
    # Parse protocols
    if args.protocols.lower() == 'all':
        proto_array = ALL_PROTOS
    else:
        proto_array = [p.strip().lower() for p in args.protocols.split(',')]
    
    # Validate protocols
    valid_protos = []
    invalid_protos = []
    for proto in proto_array:
        if proto in PROTO_PORTS:
            valid_protos.append(proto)
        else:
            invalid_protos.append(proto)
    
    if invalid_protos:
        print(f"{YELLOW}[!] Warning: Unknown protocols skipped: {', '.join(invalid_protos)}{NC}")
        print(f"    Valid protocols: {', '.join(ALL_PROTOS)}")
    
    if not valid_protos:
        print(f"{YELLOW}[-] No valid protocols specified.{NC}")
        sys.exit(1)
    
    # Parse targets
    host_list = parse_targets(args.targets)
    
    if not host_list:
        print(f"{YELLOW}[-] No valid targets found.{NC}")
        sys.exit(1)
    
    print(f"\n{GREEN}[+] Starting NXCStorm{NC}")
    print(f"    NXC Path:  {nxc_path}")
    print(f"    Protocols: {', '.join(valid_protos).upper()}")
    print(f"    Targets:   {len(host_list)} host(s)")
    print(f"    Username:  {args.username}")
    print(f"    Password:  {'*' * len(args.password)}")
    print(f"    Timeout:   {args.timeout}s")
    print()
    
    # Create temp directory for target file
    tmp_dir = tempfile.mkdtemp()
    target_file = os.path.join(tmp_dir, 'targets.txt')
    
    success_count = 0
    failed_count = 0
    
    try:
        # Spray loop
        for proto in valid_protos:
            port = PROTO_PORTS.get(proto)
            
            if args.no_port_check or port is None:
                live_hosts = host_list.copy()
                print(f"{BLUE}[*] Skipping port check for {proto}{NC}")
            else:
                print(f"{GREY}[*] Checking port {port} for {proto}...{NC}", end=' ', flush=True)
                live_hosts = find_live_hosts(port, host_list, xargs_available, max_jobs, args.port_timeout)
                print(f"Found {len(live_hosts)} live host(s)")
            
            if not live_hosts:
                print_summary(proto, 0, len(host_list))
                print()
                failed_count += 1
                continue
            
            print(f"\n{GREEN}[+] Testing {proto.upper()} ({len(live_hosts)} host(s)){NC}")
            
            # For SMB and WMI, test both with and without --local-auth
            if proto in ["smb", "wmi"]:
                is_valid, status_message = test_protocol_with_local_auth(
                    nxc_path, proto, live_hosts, args.username, args.password, args.timeout
                )
            else:
                # For other protocols, use normal authentication check
                is_valid, output, status_message = execute_nxc_auth_check(
                    nxc_path, proto, live_hosts, args.username, args.password, 
                    use_local_auth=args.local_auth, timeout=args.timeout
                )
            
            # Display result
            if is_valid:
                print(f"  {GREEN}✓ VALID - {status_message}{NC}")
                success_count += 1
            else:
                print(f"  {RED}✗ INVALID - {status_message}{NC}")
                failed_count += 1
            
            # If valid and not continuing, stop
            if is_valid and not args.continue_on_success:
                print(f"{GREEN}[!] Valid credentials found. Stopping.{NC}")
                break
            
            print()
    
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Spraying interrupted by user.{NC}")
    finally:
        # Cleanup temp directory
        shutil.rmtree(tmp_dir, ignore_errors=True)
    
    # Final summary
    total = success_count + failed_count
    print(f"\n{'='*60}")
    print("NXCSTORM SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"Protocols tested: {total}")
    print(f"{GREEN}Valid credentials: {success_count}{NC}")
    print(f"{RED}Invalid credentials: {failed_count}{NC}")
    print(f"\nValid access for:")
    
    if success_count > 0:
        for proto in valid_protos:
            # We'd need to track this per protocol, but for simplicity just show count
            pass
        print(f"  {GREEN}Credentials valid on {success_count} protocol(s){NC}")
    else:
        print(f"  {RED}None{NC}")
    
    print(f"{'='*60}\n")
    
    # Exit with appropriate code
    sys.exit(0 if success_count > 0 else 1)


if __name__ == '__main__':
    main()
