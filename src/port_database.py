"""
Port database management and risk assessment
"""

import json
import os
import logging
from typing import Dict, List

class PortDatabase:
    """Manages the port database with risk assessments and educational content"""
    
    def __init__(self):
        self.ports_data = {}
        self.load_port_data()
    
    def load_port_data(self):
        """Load port data from JSON file"""
        try:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
            ports_file = os.path.join(data_dir, 'ports.json')
            
            with open(ports_file, 'r', encoding='utf-8') as f:
                self.ports_data = json.load(f)
            
            logging.info(f"Loaded {len(self.ports_data)} port definitions")
            
        except Exception as e:
            logging.error(f"Failed to load port data: {e}")
            self.ports_data = self.get_default_port_data()
    
    def get_default_port_data(self) -> Dict:
        """Return default port data if file loading fails"""
        return {
            "21": {
                "service": "FTP",
                "protocols": ["TCP"],
                "risk_level": "Medium",
                "description_en": "File Transfer Protocol - Transfers files in plaintext",
                "description_es": "Protocolo de Transferencia de Archivos - Transfiere archivos en texto plano",
                "risk_explanation_en": "FTP transmits data including passwords in plaintext, making it vulnerable to interception.",
                "risk_explanation_es": "FTP transmite datos incluyendo contraseñas en texto plano, haciéndolo vulnerable a interceptación.",
                "learn_more_url": "https://owasp.org/www-community/vulnerabilities/Insecure_Transport"
            },
            "22": {
                "service": "SSH",
                "protocols": ["TCP"],
                "risk_level": "High",
                "description_en": "Secure Shell - Remote access protocol",
                "description_es": "Shell Seguro - Protocolo de acceso remoto",
                "risk_explanation_en": "SSH provides remote access to your system. If exposed, attackers may attempt brute force attacks.",
                "risk_explanation_es": "SSH proporciona acceso remoto a su sistema. Si está expuesto, los atacantes pueden intentar ataques de fuerza bruta.",
                "learn_more_url": "https://www.sans.org/white-papers/1988/"
            },
            "80": {
                "service": "HTTP",
                "protocols": ["TCP"],
                "risk_level": "Low",
                "description_en": "Hypertext Transfer Protocol - Web traffic",
                "description_es": "Protocolo de Transferencia de Hipertexto - Tráfico web",
                "risk_explanation_en": "Standard web traffic port. Generally safe but consider using HTTPS (443) for sensitive data.",
                "risk_explanation_es": "Puerto estándar de tráfico web. Generalmente seguro pero considere usar HTTPS (443) para datos sensibles.",
                "learn_more_url": "https://owasp.org/www-project-top-ten/"
            }
        }
    
    def get_port_info(self, port: int) -> Dict:
        """Get information about a specific port"""
        port_str = str(port)
        if port_str in self.ports_data:
            return self.ports_data[port_str]
        else:
            # Return generic info for unknown ports
            return {
                "service": "Unknown Service",
                "protocols": ["TCP"],
                "risk_level": "Medium",
                "description_en": f"Unknown service on port {port}",
                "description_es": f"Servicio desconocido en puerto {port}",
                "risk_explanation_en": "This port is not in our database. Research the service running on this port.",
                "risk_explanation_es": "Este puerto no está en nuestra base de datos. Investigue el servicio que se ejecuta en este puerto.",
                "learn_more_url": "https://www.speedguide.net/ports.php"
            }
    
    def get_all_monitored_ports(self) -> List[Dict]:
        """Get all ports that should be monitored"""
        monitored_ports = []
        
        for port_str, port_data in self.ports_data.items():
            try:
                port_num = int(port_str)
                monitored_ports.append({
                    'port': port_num,
                    'service': port_data.get('service', 'Unknown'),
                    'protocols': port_data.get('protocols', ['TCP']),
                    'risk_level': port_data.get('risk_level', 'Medium')
                })
            except ValueError:
                continue
        
        return monitored_ports
    
    def get_risk_color(self, risk_level: str) -> str:
        """Get color code for risk level"""
        colors = {
            'High': '#FF4444',      # Red
            'Medium': '#FF8C00',    # Orange
            'Low': '#00CC66'        # Green
        }
        return colors.get(risk_level, '#FFA500')  # Default to orange
    
    def filter_ports_by_risk(self, ports: List[Dict], risk_filter: str) -> List[Dict]:
        """Filter ports by risk level"""
        if risk_filter == "All":
            return ports
        
        return [port for port in ports if port.get('risk_level') == risk_filter]
