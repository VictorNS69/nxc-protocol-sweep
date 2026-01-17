#!/usr/bin/env python3
"""
Multi-protocol scanner using nxc (NetExec)
Scans a target against 10 predefined protocols
Returns which credentials are valid for each protocol
"""

import subprocess
import shutil
import sys
import re
from argparse import ArgumentParser
from typing import List, Optional, Dict, Any, Tuple

# Color codes for terminal output
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_GREY = "\033[90m"
COLOR_RESET = "\033[0m"

class NxcSweep:
    """
    Scanner class to handle nxc execution across multiple protocols
    """
    
    def __init__(self, debug_mode: bool = False):
        # Fixed list of protocols
        self.protocols = ["nfs", "ftp", "smb", "vnc", "winrm", "ssh", "rdp", "wmi", "ldap", "mssql"]
        self.debug_mode = debug_mode
        self.valid_access = {}  # Store valid protocol accesses
    
    def debug_print(self, message: str) -> None:
        """Print message only if debug mode is enabled"""
        if self.debug_mode:
            print(f"{COLOR_GREY}[DEBUG] {message} {COLOR_RESET}")
    
    def find_nxc(self) -> Optional[str]:
        """
        Find nxc (NetExec) executable in the system PATH
        """
        self.debug_print("Searching for nxc in PATH...")
        nxc_path = shutil.which("nxc") or shutil.which("netexec")
        
        if not nxc_path:
            self.debug_print("nxc not found, trying netexec...")
            nxc_path = shutil.which("netexec")
            
        if nxc_path:
            self.debug_print(f"Found nxc at: {nxc_path}")
        else:
            self.debug_print("nxc not found in PATH")
            
        return nxc_path
    
    def parse_nxc_output(self, output: str, protocol: str, username: str, password: str) -> Tuple[bool, str]:
        """
        Parse nxc output to determine if credentials were valid
        
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
        # Note: The password part might be empty for accounts like Guest
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
                # Note: nxc might show the attempted username/password
                username_matches = (found_username.lower() == username.lower())
                
                if username_matches:
                    found_our_creds = True
                    
                    # Check if credentials are valid based on sign
                    if sign == "+":
                        is_valid = True
                        status_message = "Authentication successful"
                        self.debug_print(f"Found [+] pattern for {protocol}: {domain}\\{found_username}")
                        break  # Stop at first successful match
                    else:  # sign == "-"
                        is_valid = False
                        # Use the status from the output if available
                        status_message = status if status else "Authentication failed"
                        self.debug_print(f"Found [-] pattern for {protocol}: {domain}\\{found_username} - {status_message}")
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
            self.debug_print(f"No specific credential match found for {username}, checking for any [+] patterns")
            
            # Look for ANY [+] pattern (successful auth with any user)
            any_success_pattern = r'\[\+\]\s+[^\\]+\\[^:]+:[^\s]*'
            any_failure_pattern = r'\[\-\]\s+[^\\]+\\[^:]+:[^\s]*(?:\s+(.+))?'
            
            # First check for any success
            success_match = re.search(any_success_pattern, output, re.IGNORECASE)
            if success_match:
                self.debug_print(f"Found generic [+] pattern for {protocol}: {success_match.group(0)}")
                # If there's any [+] in the output, check if it might be our credentials
                # (nxc might show different formatting)
                return True, "Authentication successful"
            
            # Then check for any failure with status
            failure_match = re.search(any_failure_pattern, output, re.IGNORECASE)
            if failure_match:
                status_from_match = failure_match.group(1) if failure_match.group(1) else "Authentication failed"
                self.debug_print(f"Found generic [-] pattern for {protocol} with status: {status_from_match}")
                return False, status_from_match
        
        # If no patterns found at all, assume invalid
        self.debug_print(f"No [+] or [-] patterns found for {protocol}, assuming invalid")
        return False, "No authentication response detected"
    
    def execute_nxc_for_auth_check(self, nxc_path: str, protocol: str, ip: str, 
                                  username: str, password: str, use_local_auth: bool = False) -> Tuple[bool, str, str]:
        """
        Execute nxc command for authentication check only
        """
        try:
            if use_local_auth:
                self.debug_print(f"Testing {protocol} authentication on {ip} with --local-auth")
            else:
                self.debug_print(f"Testing {protocol} authentication on {ip}")
            
            # Build authentication-only command
            command = [
                nxc_path,
                protocol,
                ip,
                "-u", username,
                "-p", password,
                "--no-bruteforce",  # Skip brute force
                "--continue-on-success"  # Exit after success
            ]
            
            # Protocol-specific authentication options
            if use_local_auth and protocol in ["smb", "wmi"]:
                command.extend(["--local-auth"])  # Try local authentication
            elif protocol == "ldap":
                command.extend(["--simple"])  # Use simple bind
            elif protocol == "ssh":
                command.extend(["-k"])  # Accept any SSH key
            
            self.debug_print(f"Command: {' '.join(command)}")
            
            # Execute with short timeout for auth check
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20,  # Shorter timeout for auth checks
                check=False
            )
            
            output = result.stdout + result.stderr
            self.debug_print(f"Raw output for {protocol}:\n{output[:500]}")
            
            # Parse output to check if authentication was successful
            is_valid, status_message = self.parse_nxc_output(output, protocol, username, password)
            
            return is_valid, output, status_message
            
        except subprocess.TimeoutExpired:
            self.debug_print(f"Timeout checking {protocol} authentication")
            return False, f"Timeout checking {protocol}", "Timeout"
        except Exception as e:
            self.debug_print(f"Error checking {protocol}: {e}")
            return False, str(e), f"Error: {e}"
    
    def test_protocol_with_local_auth(self, nxc_path: str, protocol: str, ip: str, 
                                     username: str, password: str) -> Tuple[bool, str]:
        """
        Test SMB or WMI protocol both with and without --local-auth flag
        """
        self.debug_print(f"Starting dual test for {protocol}")
        
        # Track status messages from both attempts
        status_messages = []
        
        # Test 1: Without --local-auth (default)
        is_valid_default, output_default, status_default = self.execute_nxc_for_auth_check(
            nxc_path, protocol, ip, username, password, use_local_auth=False
        )
        
        if is_valid_default:
            self.debug_print(f"{protocol} authentication successful without --local-auth")
            return True, status_default
        
        status_messages.append(f"Without --local-auth: {status_default}")
        
        # Test 2: With --local-auth
        is_valid_local, output_local, status_local = self.execute_nxc_for_auth_check(
            nxc_path, protocol, ip, username, password, use_local_auth=True
        )
        
        if is_valid_local:
            self.debug_print(f"{protocol} authentication successful with --local-auth")
            return True, status_local
        
        status_messages.append(f"With --local-auth: {status_local}")
        
        self.debug_print(f"{protocol} authentication failed both with and without --local-auth")
        # Return the last status message or combine them
        combined_status = "; ".join(status_messages)
        return False, combined_status
    
    def scan_target(self, ip: str, username: str, password: str) -> Dict[str, Tuple[bool, str]]:
        """
        Perform authentication check for all predefined protocols
        """
        print(f"[*] Starting authentication scan for {ip}")
        self.debug_print(f"Username: {username}")
        
        # Find nxc executable
        nxc_path = self.find_nxc()
        
        if not nxc_path:
            print("[!] ERROR: nxc (netexec) not found in system")
            print("[!] Make sure it's installed and in your PATH")
            print("[!] Installation: pip install netexec")
            sys.exit(1)
        
        self.debug_print(f"Using nxc from: {nxc_path}")
        self.debug_print(f"Testing {len(self.protocols)} protocols\n")
        
        # Reset valid access dictionary
        self.valid_access = {}
        
        # Iterate through all protocols
        for i, protocol in enumerate(self.protocols, 1):
            print(f"[*] Testing {i}/{len(self.protocols)}: {protocol.upper():6s}", end="")
            
            # For SMB and WMI, test both with and without --local-auth
            if protocol in ["smb", "wmi"]:
                self.debug_print(f"Starting dual authentication test for {protocol}")
                is_valid, status_message = self.test_protocol_with_local_auth(
                    nxc_path, protocol, ip, username, password
                )
            else:
                # For other protocols, use normal single test
                is_valid, _, status_message = self.execute_nxc_for_auth_check(
                    nxc_path, protocol, ip, username, password, use_local_auth=False
                )
            
            self.valid_access[protocol] = (is_valid, status_message)
            
            if is_valid:
                print(f" - {COLOR_GREEN}VALID ✓ {COLOR_RESET}")
            else:
                print(f" - {COLOR_RED}INVALID ✗ ({status_message}){COLOR_RESET}")
        
        return self.valid_access
    
    def print_summary(self) -> None:
        """
        Print a summary of valid accesses
        """
        print(f"\n{'='*60}")
        print("AUTHENTICATION SCAN SUMMARY")
        print(f"{'='*60}")
        
        # Count valid accesses
        valid_count = sum(1 for is_valid, _ in self.valid_access.values() if is_valid)
        
        print(f"Protocols tested: {len(self.protocols)}")
        print(f"{COLOR_GREEN}Valid credentials: {valid_count} {COLOR_RESET}")
        print(f"{COLOR_RED}Invalid credentials: {len(self.protocols) - valid_count} {COLOR_RESET}")
        print(f"\nValid access for:")
        
        # List valid protocols
        valid_protocols = [(p, status) for p, (is_valid, status) in self.valid_access.items() if is_valid]
        if valid_protocols:
            for protocol, status in valid_protocols:
                print(f"  - {COLOR_GREEN}{protocol.upper()}: {status} {COLOR_RESET}")
        else:
            print("  None")
        
        print(f"\nInvalid access details:")
        invalid_protocols = [(p, status) for p, (is_valid, status) in self.valid_access.items() if not is_valid]
        if invalid_protocols:
            for protocol, status in invalid_protocols:
                print(f"  - {COLOR_RED}{protocol.upper()}: {status} {COLOR_RESET}")
        else:
            print("  None")
        
        print(f"{'='*60}")


def parse_arguments() -> Tuple[str, str, str, bool]:
    parser = ArgumentParser(
        description="Multi-protocol authentication scanner using nxc",
        epilog="Tests credentials against: nfs, ftp, smb, vnc, winrm, ssh, rdp, wmi, ldap, mssql"
    )
    
    # Required arguments with flags
    parser.add_argument(
        "ip",
        help="Target IP address"
    )
    
    parser.add_argument(
        "-u", "--username",
        required=True,
        help="Username"
    )
    
    parser.add_argument(
        "-p", "--password",
        required=True,
        help="Password"
    )
    
    # Optional debug flag
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug output [DEBUG] messages"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    return args.ip, args.username, args.password, args.debug


def main():
    """
    Main function to parse arguments and initiate scan
    """
    
    # Parse command line arguments
    ip, username, password, debug_mode = parse_arguments()
    
    # Create scanner instance
    scanner = NxcSweep(debug_mode=debug_mode)
    
    # Perform authentication scan
    valid_access = scanner.scan_target(ip, username, password)
    
    # Print summary
    scanner.print_summary()
    
    # Exit with appropriate code
    valid_count = sum(1 for is_valid, _ in valid_access.values() if is_valid)
    if valid_count > 0:
        sys.exit(0)  # Success - at least one valid access
    else:
        sys.exit(1)  # Failure - no valid accesses


if __name__ == "__main__":
    main()
