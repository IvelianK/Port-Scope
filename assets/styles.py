"""
Application styling and theming
"""

class AppStyles:
    """Application styling constants and theme definitions"""
    
    def __init__(self):
        # Dark theme color palette
        self.colors = {
            # Primary colors
            'bg_primary': '#1a1a1a',        # Dark background
            'bg_secondary': '#2d2d2d',      # Slightly lighter dark
            'bg_tertiary': '#404040',       # Even lighter for contrast
            
            # Text colors
            'text_primary': '#ffffff',      # White text
            'text_secondary': '#b3b3b3',    # Light gray text
            'text_tertiary': '#808080',     # Medium gray text
            
            # Accent colors (turquoise blue theme)
            'accent_primary': '#00bcd4',    # Main turquoise
            'accent_secondary': '#0097a7',  # Darker turquoise
            'accent_light': '#33d9de',      # Lighter turquoise
            
            # Risk level colors
            'risk_high': '#ff4444',         # Red
            'risk_medium': '#ff8c00',       # Orange
            'risk_low': '#00cc66',          # Green
            
            # State colors
            'success': '#4caf50',           # Green
            'warning': '#ff9800',           # Orange
            'error': '#f44336',             # Red
            'info': '#2196f3',              # Blue
            
            # Border and separator colors
            'border': '#404040',
            'separator': '#333333'
        }
        
        # Font definitions
        self.fonts = {
            'title': ('Segoe UI', 18, 'bold'),
            'heading': ('Segoe UI', 14, 'bold'),
            'subheading': ('Segoe UI', 12, 'bold'),
            'body': ('Segoe UI', 10),
            'small': ('Segoe UI', 9),
            'button': ('Segoe UI', 10, 'bold'),
            'monospace': ('Consolas', 10)
        }
        
        # Spacing constants
        self.spacing = {
            'xs': 2,
            'sm': 5,
            'md': 10,
            'lg': 15,
            'xl': 20,
            'xxl': 30
        }
        
        # Component specific styles
        self.card = {
            'padding': self.spacing['md'],
            'margin': self.spacing['sm'],
            'border_radius': 4,
            'shadow': '0 2px 4px rgba(0,0,0,0.3)'
        }
        
        self.button = {
            'padding_x': self.spacing['lg'],
            'padding_y': self.spacing['sm'],
            'border_radius': 4,
            'min_width': 100
        }
        
    def get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level"""
        risk_colors = {
            'High': self.colors['risk_high'],
            'Medium': self.colors['risk_medium'],
            'Low': self.colors['risk_low']
        }
        return risk_colors.get(risk_level, self.colors['accent_primary'])
    
    def get_state_color(self, state: str) -> str:
        """Get color for connection state"""
        state_colors = {
            'LISTENING': self.colors['warning'],
            'OPEN': self.colors['error'],
            'CLOSED': self.colors['success'],
            'UPnP EXPOSED': self.colors['risk_high']
        }
        return state_colors.get(state, self.colors['info'])
