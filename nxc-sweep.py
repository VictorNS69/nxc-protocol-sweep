#!/usr/bin/env python3

import argparse
import subprocess
import sys
import tempfile
import os
import shutil
from pathlib import Path

# --- Colors ---
BLUE = '\033[38;5;117m'
YELLOW = '\033[38;5;226m'
GREEN = '\033[0;32m'
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
        'nfs': ['--shares'],  # List NFS shares by default
        'vnc': ['--check'],   # Basic VNC connectivity check
        'wmi': ['--wmi'],     # WMI query
        'ldap': ['--users'],  # Enumerate users by default
        'ssh': ['--sudo-check'],  # Check sudo access
        'winrm': ['--exec-method', 'smbexec'],  # Default execution method
        'rdp': ['--screenshot']  # Take screenshot on successful login
    }
    return defaults.get(proto, [])


def build_safe_flags(proto, use_local_auth, use_continue):
    """Build safe flags list for a protocol."""
    safe_flags = apply_protocol_defaults(proto)
    
    # --local-auth only applies to certain protocols (Windows-based auth)
    local_auth_protos = ['smb', 'winrm', 'rdp', 'mssql', 'wmi']
    if use_local_auth and proto in local_auth_protos:
        safe_flags.append('--local-auth')
        print(f"{BLUE}[!] Applying '--local-auth' for {proto}{NC}")
    
    if use_continue:
        safe_flags.append('--continue-on-success')
    
    return safe_flags


def find_live_hosts(port, hosts, xargs_available, max_jobs):
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
                 'nc -z -w 1 "$1" "$2" 2>/dev/null && printf "%s\n" "$1"',
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
                    ['nc', '-z', '-w', '1', host, str(port)],
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
Example: nxc-protocol-sweep smb,rdp,ssh targets.txt -u admin -p Pass123 --local-auth{NC}
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
    parser.add_argument('--timeout', type=int, default=1,
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
    print(f"    Protocols: {', '.join(valid_protos).upper()}")
    print(f"    Targets:   {len(host_list)} host(s)")
    print(f"    Username:  {args.username}")
    print(f"    Password:  {'*' * len(args.password)}")
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
                live_hosts = find_live_hosts(port, host_list, xargs_available, max_jobs)
                print(f"Found {len(live_hosts)} live host(s)")
            
            if not live_hosts:
                print_summary(proto, 0, len(host_list))
                print()
                failed_count += 1
                continue
            
            # Build per-protocol flag list
            safe_flags = build_safe_flags(proto, args.local_auth, args.continue_on_success)
            
            print(f"\n{GREEN}[+] Spraying {proto.upper()} ({len(live_hosts)} host(s)){NC}")
            
            # Prepare targets for nxc
            if len(live_hosts) == 1:
                targets_for_nxc = [live_hosts[0]]
            else:
                # Write targets to temp file for nxc
                with open(target_file, 'w') as f:
                    f.write('\n'.join(live_hosts))
                targets_for_nxc = [target_file]
            
            returncode = spray_protocol(proto, targets_for_nxc, args.username, args.password, safe_flags)
            
            if returncode == 0:
                success_count += 1
                print_summary(proto, len(live_hosts), len(host_list), success=True)
            else:
                failed_count += 1
                print_summary(proto, len(live_hosts), len(host_list))
            
            print()
    
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Spraying interrupted by user.{NC}")
    finally:
        # Cleanup temp directory
        shutil.rmtree(tmp_dir, ignore_errors=True)
    
    # Final summary
    print(f"\n{GREEN}╔══════════════════════════════════════════════════════════════╗")
    print(f"║  Spray Complete!                                             ║")
    print(f"║  Successful: {success_count:<2} | Failed: {failed_count:<2} | Total: {success_count + failed_count:<2}                                    ║")
    print(f"╚══════════════════════════════════════════════════════════════╝{NC}\n")


if __name__ == '__main__':
    main()
