"""
Main GUI application using tkinter
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import webbrowser
import logging
from typing import Dict, List, Callable
import threading

from scanner import PortScanner
from upnp_scanner import UPnPScanner
from port_database import PortDatabase
from localization import LocalizationManager
import sys
import os

# Import styles from assets directory
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'assets'))
try:
    from styles import AppStyles
except ImportError:
    # Fallback if styles module not found
    class AppStyles:
        def __init__(self):
            self.colors = {
                'bg_primary': '#1a1a1a',
                'bg_secondary': '#2d2d2d',
                'text_primary': '#ffffff',
                'text_secondary': '#b3b3b3',
                'accent_primary': '#00bcd4',
                'accent_secondary': '#0097a7'
            }
            self.fonts = {
                'title': ('Arial', 18, 'bold'),
                'heading': ('Arial', 14, 'bold'),
                'body': ('Arial', 10),
                'button': ('Arial', 10, 'bold'),
                'small': ('Arial', 9)
            }

class NetworkSecurityApp:
    """Main GUI application class"""
    
    def __init__(self, root: tk.Tk, localization: LocalizationManager):
        self.root = root
        self.localization = localization
        self.port_scanner = PortScanner()
        self.upnp_scanner = UPnPScanner()
        self.port_db = PortDatabase()
        self.styles = AppStyles()
        
        self.open_ports = []
        self.filtered_ports = []
        self.is_scanning = False
        
        self.setup_window()
        self.create_widgets()
        self.update_language()
    
    def setup_window(self):
        """Setup main window properties"""
        self.root.title("Network Port Security Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        self.root.configure(bg=self.styles.colors['bg_primary'])
        
        # Configure style for ttk widgets
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure dark theme
        style.configure('TFrame', background=self.styles.colors['bg_primary'])
        style.configure('TLabel', background=self.styles.colors['bg_primary'], 
                       foreground=self.styles.colors['text_primary'])
        style.configure('TButton', background=self.styles.colors['accent_primary'],
                       foreground=self.styles.colors['text_primary'])
        style.map('TButton', background=[('active', self.styles.colors['accent_secondary'])])
        style.configure('TCombobox', background=self.styles.colors['bg_secondary'])
        style.configure('TProgressbar', background=self.styles.colors['accent_primary'])
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        self.title_label = tk.Label(header_frame, 
                                   text="Network Port Security Scanner",
                                   font=self.styles.fonts['title'],
                                   bg=self.styles.colors['bg_primary'],
                                   fg=self.styles.colors['text_primary'])
        self.title_label.pack(side=tk.LEFT)
        
        # Language selector
        lang_frame = ttk.Frame(header_frame)
        lang_frame.pack(side=tk.RIGHT)
        
        self.lang_label = ttk.Label(lang_frame, text="Language:")
        self.lang_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.lang_var = tk.StringVar(value="English")
        self.lang_combo = ttk.Combobox(lang_frame, textvariable=self.lang_var,
                                      values=list(self.localization.get_available_languages().values()),
                                      state="readonly", width=10)
        self.lang_combo.pack(side=tk.LEFT)
        self.lang_combo.bind('<<ComboboxSelected>>', self.on_language_change)
        
        # Control frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Scan button
        self.scan_button = tk.Button(control_frame,
                                    text="Start Scan",
                                    command=self.start_scan,
                                    font=self.styles.fonts['button'],
                                    bg=self.styles.colors['accent_primary'],
                                    fg=self.styles.colors['text_primary'],
                                    relief=tk.FLAT,
                                    padx=20, pady=8)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Risk filter
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(side=tk.LEFT, padx=(20, 0))
        
        self.filter_label = ttk.Label(filter_frame, text="Filter by Risk:")
        self.filter_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.risk_filter_var = tk.StringVar(value="All")
        self.risk_filter_combo = ttk.Combobox(filter_frame, 
                                             textvariable=self.risk_filter_var,
                                             values=["All", "High", "Medium", "Low"],
                                             state="readonly", width=10)
        self.risk_filter_combo.pack(side=tk.LEFT)
        self.risk_filter_combo.bind('<<ComboboxSelected>>', self.apply_filter)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(control_frame, 
                                           variable=self.progress_var,
                                           length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=(10, 0))
        
        self.progress_label = ttk.Label(control_frame, text="")
        self.progress_label.pack(side=tk.RIGHT, padx=(0, 10))
        
        # Results frame
        results_frame = ttk.Frame(main_frame)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create scrollable frame for port cards
        self.canvas = tk.Canvas(results_frame, 
                               bg=self.styles.colors['bg_primary'],
                               highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(results_frame, orient="vertical", 
                                      command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Bind mouse wheel to canvas
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.root.bind("<MouseWheel>", self._on_mousewheel)
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="Ready to scan")
        self.status_label.pack(pady=(10, 0))
    
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def on_language_change(self, event=None):
        """Handle language change"""
        lang_name = self.lang_var.get()
        lang_codes = {v: k for k, v in self.localization.get_available_languages().items()}
        
        if lang_name in lang_codes:
            self.localization.set_language(lang_codes[lang_name])
            self.update_language()
    
    def update_language(self):
        """Update all text elements with current language"""
        self.title_label.config(text=self.localization.get_text('app_title'))
        self.scan_button.config(text=self.localization.get_text('scan_button'))
        self.lang_label.config(text=self.localization.get_text('language') + ":")
        self.filter_label.config(text=self.localization.get_text('filter_by_risk') + ":")
        
        # Update filter combo values
        filter_values = [
            self.localization.get_text('all_risks'),
            self.localization.get_text('high_risk'),
            self.localization.get_text('medium_risk'),
            self.localization.get_text('low_risk')
        ]
        self.risk_filter_combo.config(values=filter_values)
        
        # Refresh port display
        self.display_ports(self.filtered_ports)
    
    def start_scan(self):
        """Start port scanning"""
        if self.is_scanning:
            self.stop_scan()
            return
        
        self.is_scanning = True
        self.scan_button.config(text=self.localization.get_text('stop_button'))
        self.status_label.config(text=self.localization.get_text('scanning'))
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        
        # Clear previous results
        self.clear_results()
        
        # Start scanning in separate thread
        threading.Thread(target=self.run_scan, daemon=True).start()
    
    def stop_scan(self):
        """Stop current scan"""
        self.is_scanning = False
        self.port_scanner.stop_scan()
        self.upnp_scanner.stop_scan()
        self.scan_button.config(text=self.localization.get_text('scan_button'))
        self.status_label.config(text="Scan stopped")
        self.progress_var.set(0)
        self.progress_label.config(text="")
    
    def run_scan(self):
        """Run the complete scan process"""
        try:
            all_ports = []
            
            # Get ports to scan
            monitored_ports = self.port_db.get_all_monitored_ports()
            
            # Phase 1: Local port scan
            self.port_scanner.scan_common_ports(
                monitored_ports,
                progress_callback=self.update_scan_progress,
                result_callback=lambda ports: all_ports.extend(ports)
            )
            
            # Wait for local scan to complete
            while self.port_scanner.is_scanning and self.is_scanning:
                threading.Event().wait(0.1)
            
            if not self.is_scanning:
                return
            
            # Phase 2: UPnP scan
            self.upnp_scanner.scan_upnp_ports(
                progress_callback=self.update_upnp_progress,
                result_callback=lambda ports: all_ports.extend(ports)
            )
            
            # Wait for UPnP scan to complete
            while self.upnp_scanner.is_scanning and self.is_scanning:
                threading.Event().wait(0.1)
            
            if self.is_scanning:
                # Scan completed successfully
                self.root.after(0, self.scan_completed, all_ports)
            
        except Exception as e:
            logging.error(f"Scan error: {e}")
            self.root.after(0, self.scan_error, str(e))
    
    def update_scan_progress(self, progress: int):
        """Update scan progress (0-70% for local scan)"""
        if self.is_scanning:
            adjusted_progress = int(progress * 0.7)
            self.root.after(0, self._update_progress, adjusted_progress)
    
    def update_upnp_progress(self, progress: int):
        """Update UPnP scan progress (70-100%)"""
        if self.is_scanning:
            adjusted_progress = 70 + int(progress * 0.3)
            self.root.after(0, self._update_progress, adjusted_progress)
    
    def _update_progress(self, progress: int):
        """Update progress bar and label"""
        self.progress_var.set(progress)
        self.progress_label.config(text=f"{progress}%")
    
    def scan_completed(self, ports: List[Dict]):
        """Handle scan completion"""
        self.is_scanning = False
        self.scan_button.config(text=self.localization.get_text('scan_button'))
        self.progress_var.set(100)
        self.progress_label.config(text="100%")
        
        self.open_ports = ports
        self.apply_filter()
        
        if ports:
            self.status_label.config(text=f"{self.localization.get_text('scan_complete')} - {len(ports)} ports found")
        else:
            self.status_label.config(text=self.localization.get_text('no_open_ports'))
    
    def scan_error(self, error_msg: str):
        """Handle scan error"""
        self.is_scanning = False
        self.scan_button.config(text=self.localization.get_text('scan_button'))
        self.status_label.config(text=f"{self.localization.get_text('error')}: {error_msg}")
        messagebox.showerror(self.localization.get_text('error'), f"Scan failed: {error_msg}")
    
    def apply_filter(self, event=None):
        """Apply risk level filter"""
        filter_value = self.risk_filter_var.get()
        
        # Map localized filter values to English
        filter_map = {
            self.localization.get_text('all_risks'): 'All',
            self.localization.get_text('high_risk'): 'High',
            self.localization.get_text('medium_risk'): 'Medium',
            self.localization.get_text('low_risk'): 'Low'
        }
        
        english_filter = filter_map.get(filter_value, filter_value)
        self.filtered_ports = self.port_db.filter_ports_by_risk(self.open_ports, english_filter)
        self.display_ports(self.filtered_ports)
    
    def clear_results(self):
        """Clear all port result widgets"""
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
    
    def display_ports(self, ports: List[Dict]):
        """Display port information in cards"""
        self.clear_results()
        
        if not ports:
            no_ports_label = tk.Label(self.scrollable_frame,
                                     text=self.localization.get_text('no_open_ports'),
                                     font=self.styles.fonts['body'],
                                     bg=self.styles.colors['bg_primary'],
                                     fg=self.styles.colors['text_secondary'])
            no_ports_label.pack(pady=20)
            return
        
        for i, port_info in enumerate(ports):
            self.create_port_card(port_info, i)
    
    def create_port_card(self, port_info: Dict, index: int):
        """Create a card widget for a port"""
        port_data = self.port_db.get_port_info(port_info['port'])
        risk_color = self.port_db.get_risk_color(port_info['risk_level'])
        
        # Main card frame
        card_frame = tk.Frame(self.scrollable_frame,
                             bg=self.styles.colors['bg_secondary'],
                             relief=tk.RAISED,
                             bd=1)
        card_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Risk indicator bar
        risk_bar = tk.Frame(card_frame, bg=risk_color, height=4)
        risk_bar.pack(fill=tk.X)
        
        # Card content
        content_frame = tk.Frame(card_frame, bg=self.styles.colors['bg_secondary'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        # Header row
        header_frame = tk.Frame(content_frame, bg=self.styles.colors['bg_secondary'])
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Port and service info
        port_label = tk.Label(header_frame,
                             text=f"{self.localization.get_text('port')} {port_info['port']} ({port_info['protocol']})",
                             font=self.styles.fonts['heading'],
                             bg=self.styles.colors['bg_secondary'],
                             fg=self.styles.colors['text_primary'])
        port_label.pack(side=tk.LEFT)
        
        # Risk level badge
        risk_label = tk.Label(header_frame,
                             text=port_info['risk_level'],
                             font=self.styles.fonts['small'],
                             bg=risk_color,
                             fg='white',
                             padx=8, pady=2)
        risk_label.pack(side=tk.RIGHT)
        
        # Service name
        service_label = tk.Label(content_frame,
                               text=f"{self.localization.get_text('service')}: {port_info['service']}",
                               font=self.styles.fonts['body'],
                               bg=self.styles.colors['bg_secondary'],
                               fg=self.styles.colors['text_secondary'])
        service_label.pack(anchor=tk.W, pady=(0, 5))
        
        # State
        state_label = tk.Label(content_frame,
                              text=f"{self.localization.get_text('state')}: {port_info['state']}",
                              font=self.styles.fonts['body'],
                              bg=self.styles.colors['bg_secondary'],
                              fg=self.styles.colors['text_secondary'])
        state_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Description
        desc_key = f"description_{self.localization.current_language}"
        description = port_data.get(desc_key, port_data.get('description_en', ''))
        
        if description:
            desc_label = tk.Label(content_frame,
                                 text=description,
                                 font=self.styles.fonts['body'],
                                 bg=self.styles.colors['bg_secondary'],
                                 fg=self.styles.colors['text_primary'],
                                 wraplength=600,
                                 justify=tk.LEFT)
            desc_label.pack(anchor=tk.W, pady=(0, 10))
        
        # Buttons frame
        buttons_frame = tk.Frame(content_frame, bg=self.styles.colors['bg_secondary'])
        buttons_frame.pack(fill=tk.X)
        
        # Learn more button
        learn_btn = tk.Button(buttons_frame,
                             text=self.localization.get_text('learn_more'),
                             command=lambda: self.open_learn_more(port_data),
                             font=self.styles.fonts['button'],
                             bg=self.styles.colors['accent_primary'],
                             fg=self.styles.colors['text_primary'],
                             relief=tk.FLAT,
                             padx=15, pady=5)
        learn_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # How to close button
        close_btn = tk.Button(buttons_frame,
                             text=self.localization.get_text('how_to_close'),
                             command=lambda: self.show_close_guide(port_info),
                             font=self.styles.fonts['button'],
                             bg=self.styles.colors['bg_primary'],
                             fg=self.styles.colors['text_primary'],
                             relief=tk.FLAT,
                             padx=15, pady=5)
        close_btn.pack(side=tk.LEFT)
    
    def open_learn_more(self, port_data: Dict):
        """Open learn more URL in browser"""
        url = port_data.get('learn_more_url', 'https://owasp.org')
        try:
            webbrowser.open(url)
        except Exception as e:
            logging.error(f"Failed to open URL {url}: {e}")
            messagebox.showerror("Error", f"Failed to open URL: {url}")
    
    def show_close_guide(self, port_info: Dict):
        """Show guide on how to close the port"""
        guide_window = tk.Toplevel(self.root)
        guide_window.title("How to Close Port")
        guide_window.geometry("600x500")
        guide_window.configure(bg=self.styles.colors['bg_primary'])
        guide_window.resizable(True, True)
        
        # Make window modal
        guide_window.transient(self.root)
        guide_window.grab_set()
        
        # Title
        title_label = tk.Label(guide_window,
                              text=f"How to Close Port {port_info['port']}",
                              font=self.styles.fonts['title'],
                              bg=self.styles.colors['bg_primary'],
                              fg=self.styles.colors['text_primary'])
        title_label.pack(pady=10)
        
        # Scrolled text for guide content
        text_frame = tk.Frame(guide_window, bg=self.styles.colors['bg_primary'])
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        guide_text = scrolledtext.ScrolledText(text_frame,
                                              wrap=tk.WORD,
                                              bg=self.styles.colors['bg_secondary'],
                                              fg=self.styles.colors['text_primary'],
                                              font=self.styles.fonts['body'],
                                              height=20)
        guide_text.pack(fill=tk.BOTH, expand=True)
        
        # Insert guide content
        guide_content = self.get_close_guide_content(port_info)
        guide_text.insert(tk.END, guide_content)
        guide_text.config(state=tk.DISABLED)
        
        # Close button
        close_btn = tk.Button(guide_window,
                             text="Close",
                             command=guide_window.destroy,
                             font=self.styles.fonts['button'],
                             bg=self.styles.colors['accent_primary'],
                             fg=self.styles.colors['text_primary'],
                             relief=tk.FLAT,
                             padx=20, pady=8)
        close_btn.pack(pady=10)
    
    def get_close_guide_content(self, port_info: Dict) -> str:
        """Get content for the port closing guide"""
        if self.localization.current_language == 'es':
            return f"""Cómo cerrar el puerto {port_info['port']} ({port_info['service']})

IMPORTANTE: Antes de cerrar cualquier puerto, asegúrese de que no necesita el servicio que se ejecuta en él.

Métodos para cerrar puertos:

1. FIREWALL DEL SISTEMA
   
   Windows:
   - Presione Win + R, escriba "wf.msc" y presione Enter
   - Seleccione "Reglas de entrada" en el panel izquierdo
   - Haga clic en "Nueva regla..." en el panel derecho
   - Seleccione "Puerto" y haga clic en "Siguiente"
   - Seleccione TCP o UDP según corresponda
   - Ingrese el número de puerto: {port_info['port']}
   - Seleccione "Bloquear la conexión"
   - Aplique la regla a todos los perfiles
   - Dele un nombre descriptivo a la regla
   
   Linux (iptables):
   - Abra una terminal
   - Para bloquear entrada: sudo iptables -A INPUT -p tcp --dport {port_info['port']} -j DROP
   - Para bloquear salida: sudo iptables -A OUTPUT -p tcp --dport {port_info['port']} -j DROP
   - Guarde las reglas: sudo iptables-save
   
   Linux (UFW):
   - sudo ufw deny {port_info['port']}
   - sudo ufw reload

2. DETENER EL SERVICIO
   
   Windows:
   - Presione Win + R, escriba "services.msc" y presione Enter
   - Busque el servicio relacionado con {port_info['service']}
   - Haga clic derecho y seleccione "Detener"
   - Para deshabilitarlo permanentemente, haga clic derecho > Propiedades > Tipo de inicio: Deshabilitado
   
   Linux:
   - sudo systemctl stop [nombre-del-servicio]
   - sudo systemctl disable [nombre-del-servicio]

3. CONFIGURACIÓN DEL ROUTER (para puertos UPnP)
   
   - Abra un navegador web
   - Vaya a la dirección IP de su router (generalmente 192.168.1.1 o 192.168.0.1)
   - Inicie sesión con las credenciales de administrador
   - Busque la sección "UPnP" o "Reenvío de puertos"
   - Deshabilite UPnP o elimine reglas de reenvío específicas
   - Guarde la configuración

4. VERIFICACIÓN
   
   Después de realizar cambios:
   - Reinicie este escáner para verificar que el puerto esté cerrado
   - Use herramientas en línea como ShieldsUP! para pruebas externas
   - Monitoree los registros del sistema para detectar intentos de conexión

ADVERTENCIAS:
- Cerrar puertos puede afectar la funcionalidad de aplicaciones
- Algunos puertos son necesarios para el funcionamiento del sistema
- Siempre haga una copia de seguridad de su configuración antes de realizar cambios
- Si no está seguro, consulte con un profesional de TI

Para obtener ayuda específica del proveedor:
- Busque en línea: "[modelo de su router] manual del usuario"
- Visite el sitio web del fabricante de su router
- Consulte la documentación de su sistema operativo"""
        else:
            return f"""How to Close Port {port_info['port']} ({port_info['service']})

IMPORTANT: Before closing any port, ensure you don't need the service running on it.

Methods to close ports:

1. SYSTEM FIREWALL
   
   Windows:
   - Press Win + R, type "wf.msc" and press Enter
   - Select "Inbound Rules" in the left panel
   - Click "New Rule..." in the right panel
   - Select "Port" and click "Next"
   - Choose TCP or UDP as appropriate
   - Enter port number: {port_info['port']}
   - Select "Block the connection"
   - Apply rule to all profiles
   - Give the rule a descriptive name
   
   Linux (iptables):
   - Open terminal
   - To block incoming: sudo iptables -A INPUT -p tcp --dport {port_info['port']} -j DROP
   - To block outgoing: sudo iptables -A OUTPUT -p tcp --dport {port_info['port']} -j DROP
   - Save rules: sudo iptables-save
   
   Linux (UFW):
   - sudo ufw deny {port_info['port']}
   - sudo ufw reload

2. STOP THE SERVICE
   
   Windows:
   - Press Win + R, type "services.msc" and press Enter
   - Find the service related to {port_info['service']}
   - Right-click and select "Stop"
   - To permanently disable, right-click > Properties > Startup type: Disabled
   
   Linux:
   - sudo systemctl stop [service-name]
   - sudo systemctl disable [service-name]

3. ROUTER CONFIGURATION (for UPnP ports)
   
   - Open a web browser
   - Go to your router's IP address (usually 192.168.1.1 or 192.168.0.1)
   - Log in with administrator credentials
   - Look for "UPnP" or "Port Forwarding" section
   - Disable UPnP or remove specific forwarding rules
   - Save configuration

4. VERIFICATION
   
   After making changes:
   - Restart this scanner to verify the port is closed
   - Use online tools like ShieldsUP! for external testing
   - Monitor system logs for connection attempts

WARNINGS:
- Closing ports may affect application functionality
- Some ports are required for system operation
- Always backup your configuration before making changes
- When in doubt, consult with an IT professional

For vendor-specific help:
- Search online: "[your router model] user manual"
- Visit your router manufacturer's website
- Consult your operating system documentation"""
