"""
Port scanning functionality for local system
"""

import socket
import threading
import logging
from typing import List, Dict, Tuple, Callable, Optional
import time
import subprocess
import platform

class PortScanner:
    """Local port scanner for TCP and UDP ports"""
    
    def __init__(self):
        self.is_scanning = False
        self.scan_thread = None
        self.progress_callback = None
        self.result_callback = None
        
    def scan_tcp_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Scan a single TCP port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            logging.debug(f"TCP scan error on port {port}: {e}")
            return False
    
    def scan_udp_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Scan a single UDP port (basic check)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b'', (host, port))
            sock.close()
            return True
        except Exception as e:
            logging.debug(f"UDP scan error on port {port}: {e}")
            return False
    
    def get_listening_ports(self) -> List[Dict]:
        """Get currently listening ports using netstat"""
        listening_ports = []
        
        try:
            if platform.system() == "Windows":
                cmd = ["netstat", "-an"]
            else:
                cmd = ["netstat", "-tuln"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'LISTEN' in line or 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        address = parts[3] if platform.system() == "Windows" else parts[3]
                        if ':' in address:
                            try:
                                port = int(address.split(':')[-1])
                                protocol = 'TCP' if 'tcp' in line.lower() else 'UDP'
                                listening_ports.append({
                                    'port': port,
                                    'protocol': protocol,
                                    'address': address,
                                    'state': 'LISTENING'
                                })
                            except ValueError:
                                continue
        except Exception as e:
            logging.error(f"Error getting listening ports: {e}")
        
        return listening_ports
    
    def scan_common_ports(self, ports_to_scan: List[Dict], 
                         progress_callback: Optional[Callable] = None,
                         result_callback: Optional[Callable] = None) -> None:
        """Scan a list of common ports"""
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        self.is_scanning = True
        
        def scan_worker():
            open_ports = []
            total_ports = len(ports_to_scan)
            
            # Get currently listening ports for reference
            listening_ports = self.get_listening_ports()
            listening_port_numbers = [p['port'] for p in listening_ports]
            
            for i, port_info in enumerate(ports_to_scan):
                if not self.is_scanning:
                    break
                
                port = port_info['port']
                protocols = port_info.get('protocols', ['TCP'])
                
                # Check if port is in listening ports first
                if port in listening_port_numbers:
                    open_ports.append({
                        'port': port,
                        'protocol': 'TCP/UDP',
                        'service': port_info.get('service', 'Unknown'),
                        'risk_level': port_info.get('risk_level', 'Low'),
                        'state': 'LISTENING'
                    })
                else:
                    # Scan the port
                    for protocol in protocols:
                        is_open = False
                        if protocol == 'TCP':
                            is_open = self.scan_tcp_port('127.0.0.1', port, timeout=0.5)
                        elif protocol == 'UDP':
                            is_open = self.scan_udp_port('127.0.0.1', port, timeout=0.5)
                        
                        if is_open:
                            open_ports.append({
                                'port': port,
                                'protocol': protocol,
                                'service': port_info.get('service', 'Unknown'),
                                'risk_level': port_info.get('risk_level', 'Low'),
                                'state': 'OPEN'
                            })
                            break
                
                # Update progress
                if progress_callback:
                    progress = int((i + 1) / total_ports * 100)
                    progress_callback(progress)
                
                time.sleep(0.01)  # Small delay to prevent overwhelming the system
            
            self.is_scanning = False
            if result_callback:
                result_callback(open_ports)
        
        self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2)
