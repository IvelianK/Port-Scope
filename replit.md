# Network Port Security Scanner

## Overview

The Network Port Security Scanner is a cross-platform desktop application built with Python and tkinter that empowers users to scan their local systems for open network ports and understand associated security risks. The application provides educational content about port security and supports both English and Spanish languages with a modern dark-themed interface.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **GUI Framework**: tkinter with ttk for modern UI components
- **Styling System**: Custom AppStyles class implementing a dark theme with turquoise accents
- **Layout**: Single-window application with tabbed interface and responsive design
- **Threading**: Separate threads for scanning operations to maintain UI responsiveness

### Backend Architecture
- **Modular Design**: Separated concerns across multiple modules:
  - `scanner.py`: Local port scanning functionality
  - `upnp_scanner.py`: UPnP device discovery
  - `port_database.py`: Port information and risk assessment
  - `localization.py`: Multi-language support
  - `gui.py`: Main application interface

### Data Storage Solutions
- **JSON-based Configuration**: 
  - Port definitions with risk levels in `data/ports.json`
  - Localization strings in `data/localization/` directory
  - No database required - all data stored in structured JSON files

### Authentication and Authorization
- **No Authentication Required**: Application runs locally without user accounts
- **System-level Access**: Uses standard socket operations and system commands (netstat)
- **No Network Authentication**: Direct local scanning without external service authentication

## Key Components

### Port Scanning Engine
- **TCP Scanner**: Socket-based connection testing for TCP ports
- **UDP Scanner**: Basic UDP port detection
- **System Integration**: Uses netstat command for listening port detection
- **Multi-threaded**: Concurrent scanning for improved performance

### UPnP Discovery Module
- **SSDP Protocol**: Implements Simple Service Discovery Protocol for UPnP device detection
- **Network Scanning**: Discovers UPnP-exposed ports on local network
- **XML Parsing**: Processes UPnP device descriptions for port mapping information

### Risk Assessment System
- **Three-tier Classification**: High, Medium, and Low risk categorization
- **Educational Content**: Detailed explanations for each port type
- **External Resources**: Links to OWASP and SANS security documentation
- **Localized Explanations**: Risk information available in English and Spanish

### Internationalization System
- **Two-language Support**: Complete English and Spanish translations
- **Runtime Language Switching**: Users can change language without restart
- **Fallback Mechanism**: Graceful degradation to English if translation missing

## Data Flow

1. **Application Startup**: 
   - Load localization files and port definitions
   - Initialize GUI with default language
   - Setup styling and theme

2. **Scan Process**:
   - User initiates scan through GUI
   - Scanner modules run in background threads
   - Progress updates sent to main thread via callbacks
   - Results processed and displayed in real-time

3. **Risk Assessment**:
   - Discovered ports matched against port database
   - Risk level assigned based on predefined criteria
   - Educational content retrieved in user's language

4. **User Interaction**:
   - Port details displayed in structured table
   - Links to external security resources
   - Guidance for port closure and security improvements

## External Dependencies

### Required Python Packages
- **requests**: HTTP client for UPnP device communication and external resource links
- **tkinter**: GUI framework (included with Python)
- **xml.etree.ElementTree**: XML parsing for UPnP responses (standard library)
- **socket**: Network operations (standard library)
- **threading**: Concurrent execution (standard library)

### System Dependencies
- **netstat**: Command-line utility for network statistics (available on Windows and Linux)
- **Python 3.7+**: Minimum Python version requirement

### External Resources
- **OWASP**: Open Web Application Security Project documentation
- **SANS**: Security education and research organization
- Links provided for educational purposes only

## Deployment Strategy

### Cross-platform Compatibility
- **Pure Python**: No platform-specific dependencies
- **Standard Library Focus**: Minimal external dependencies
- **OS Detection**: Platform-specific command execution for netstat

### Distribution Method
- **Source Code Distribution**: Users install Python and run from source
- **Package Management**: Dependencies installed via pip
- **No Installation Required**: Can run directly from any directory

### Runtime Requirements
- **No Background Services**: Application runs only when explicitly launched
- **No System Modifications**: Read-only operations, no system configuration changes
- **Minimal Resource Usage**: Lightweight operation suitable for various hardware configurations

### Security Considerations
- **Local-only Operations**: No data transmitted to external servers
- **Read-only Network Access**: Only scans, does not modify network configuration
- **Educational Focus**: Provides information but does not perform security modifications