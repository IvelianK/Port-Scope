#!/usr/bin/env python3
"""
Network Port Security Scanner
A cross-platform desktop application for scanning and educating users about network port security risks.

Licensed under MIT License
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox
import threading
import logging

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from gui import NetworkSecurityApp
from localization import LocalizationManager

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('network_scanner.log'),
            logging.StreamHandler()
        ]
    )

def main():
    """Main application entry point"""
    try:
        setup_logging()
        logging.info("Starting Network Port Security Scanner")
        
        # Create main window
        root = tk.Tk()
        
        # Initialize localization manager
        localization = LocalizationManager()
        
        # Create and run the application
        app = NetworkSecurityApp(root, localization)
        
        # Center the window on screen
        root.update_idletasks()
        width = root.winfo_reqwidth()
        height = root.winfo_reqheight()
        pos_x = (root.winfo_screenwidth() // 2) - (width // 2)
        pos_y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f"{width}x{height}+{pos_x}+{pos_y}")
        
        # Start the GUI event loop
        root.mainloop()
        
    except Exception as e:
        logging.error(f"Application failed to start: {e}")
        messagebox.showerror("Error", f"Failed to start application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
