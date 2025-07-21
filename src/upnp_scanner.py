"""
UPnP port discovery functionality
"""

import socket
import threading
import logging
import time
from typing import List, Dict, Callable, Optional
import xml.etree.ElementTree as ET
import requests
import re

class UPnPScanner:
    """UPnP port scanner for discovering exposed ports on local network"""
    
    def __init__(self):
        self.is_scanning = False
        self.scan_thread = None
        
    def discover_upnp_devices(self, timeout: int = 5) -> List[str]:
        """Discover UPnP devices on the local network"""
        devices = []
        
        # SSDP discovery message
        ssdp_msg = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'ST: upnp:rootdevice\r\n'
            'MX: 3\r\n\r\n'
        )
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Send SSDP discovery
            sock.sendto(ssdp_msg.encode(), ('239.255.255.250', 1900))
            
            # Collect responses
            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    data, addr = sock.recvfrom(1024)
                    response = data.decode('utf-8', errors='ignore')
                    
                    # Extract LOCATION header
                    location_match = re.search(r'LOCATION:\s*(.+)', response, re.IGNORECASE)
                    if location_match:
                        location = location_match.group(1).strip()
                        if location not in devices:
                            devices.append(location)
                            
                except socket.timeout:
                    break
                except Exception as e:
                    logging.debug(f"UPnP discovery error: {e}")
                    continue
            
            sock.close()
            
        except Exception as e:
            logging.error(f"UPnP discovery failed: {e}")
        
        return devices
    
    def get_device_info(self, location: str) -> Dict:
        """Get device information from UPnP location"""
        try:
            response = requests.get(location, timeout=5)
            if response.status_code == 200:
                root = ET.fromstring(response.content)
                
                # Extract device info
                device_info = {
                    'location': location,
                    'friendly_name': '',
                    'device_type': '',
                    'manufacturer': '',
                    'model_name': '',
                    'services': []
                }
                
                # Find device element
                ns = {'upnp': 'urn:schemas-upnp-org:device-1-0'}
                device = root.find('.//upnp:device', ns)
                
                if device is not None:
                    friendly_name = device.find('upnp:friendlyName', ns)
                    if friendly_name is not None:
                        device_info['friendly_name'] = friendly_name.text or ''
                    
                    device_type = device.find('upnp:deviceType', ns)
                    if device_type is not None:
                        device_info['device_type'] = device_type.text or ''
                    
                    manufacturer = device.find('upnp:manufacturer', ns)
                    if manufacturer is not None:
                        device_info['manufacturer'] = manufacturer.text or ''
                    
                    model_name = device.find('upnp:modelName', ns)
                    if model_name is not None:
                        device_info['model_name'] = model_name.text or ''
                
                return device_info
                
        except Exception as e:
            logging.debug(f"Error getting device info from {location}: {e}")
        
        return {}
    
    def scan_upnp_ports(self, progress_callback: Optional[Callable] = None,
                       result_callback: Optional[Callable] = None) -> None:
        """Scan for UPnP exposed ports"""
        
        def scan_worker():
            upnp_ports = []
            
            try:
                if progress_callback:
                    progress_callback(10)
                
                # Discover UPnP devices
                devices = self.discover_upnp_devices()
                
                if progress_callback:
                    progress_callback(40)
                
                # Get device information
                for i, device_location in enumerate(devices):
                    if not self.is_scanning:
                        break
                    
                    device_info = self.get_device_info(device_location)
                    if device_info:
                        # Parse URL to get port
                        try:
                            import urllib.parse
                            parsed = urllib.parse.urlparse(device_location)
                            port = parsed.port or (80 if parsed.scheme == 'http' else 443)
                            
                            upnp_ports.append({
                                'port': port,
                                'protocol': 'TCP',
                                'service': f"UPnP - {device_info.get('friendly_name', 'Unknown Device')}",
                                'risk_level': 'Medium',
                                'state': 'UPnP EXPOSED',
                                'device_info': device_info
                            })
                        except Exception as e:
                            logging.debug(f"Error parsing UPnP device URL: {e}")
                    
                    if progress_callback:
                        progress = 40 + int((i + 1) / len(devices) * 60)
                        progress_callback(progress)
                
                if progress_callback:
                    progress_callback(100)
                
            except Exception as e:
                logging.error(f"UPnP scan failed: {e}")
            
            self.is_scanning = False
            if result_callback:
                result_callback(upnp_ports)
        
        self.is_scanning = True
        self.scan_thread = threading.Thread(target=scan_worker, daemon=True)
        self.scan_thread.start()
    
    def stop_scan(self):
        """Stop the current UPnP scan"""
        self.is_scanning = False
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2)
