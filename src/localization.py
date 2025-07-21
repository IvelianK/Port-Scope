"""
Localization management for multi-language support
"""

import json
import os
import logging
from typing import Dict

class LocalizationManager:
    """Manages localization for English and Spanish"""
    
    def __init__(self, default_language: str = 'en'):
        self.current_language = default_language
        self.translations = {}
        self.load_translations()
    
    def load_translations(self):
        """Load translation files"""
        try:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'localization')
            
            # Load English
            en_file = os.path.join(data_dir, 'en.json')
            with open(en_file, 'r', encoding='utf-8') as f:
                self.translations['en'] = json.load(f)
            
            # Load Spanish
            es_file = os.path.join(data_dir, 'es.json')
            with open(es_file, 'r', encoding='utf-8') as f:
                self.translations['es'] = json.load(f)
            
            logging.info("Loaded translations for English and Spanish")
            
        except Exception as e:
            logging.error(f"Failed to load translations: {e}")
            self.translations = self.get_default_translations()
    
    def get_default_translations(self) -> Dict:
        """Return default translations if file loading fails"""
        return {
            'en': {
                'app_title': 'Network Port Security Scanner',
                'scan_button': 'Start Scan',
                'stop_button': 'Stop Scan',
                'language': 'Language',
                'filter_by_risk': 'Filter by Risk',
                'all_risks': 'All',
                'high_risk': 'High',
                'medium_risk': 'Medium',
                'low_risk': 'Low',
                'port': 'Port',
                'service': 'Service',
                'protocol': 'Protocol',
                'risk_level': 'Risk Level',
                'state': 'State',
                'learn_more': 'Learn More',
                'how_to_close': 'How to Close',
                'scanning': 'Scanning...',
                'scan_complete': 'Scan Complete',
                'no_open_ports': 'No open ports found',
                'error': 'Error',
                'progress': 'Progress'
            },
            'es': {
                'app_title': 'Escáner de Seguridad de Puertos de Red',
                'scan_button': 'Iniciar Escaneo',
                'stop_button': 'Detener Escaneo',
                'language': 'Idioma',
                'filter_by_risk': 'Filtrar por Riesgo',
                'all_risks': 'Todos',
                'high_risk': 'Alto',
                'medium_risk': 'Medio',
                'low_risk': 'Bajo',
                'port': 'Puerto',
                'service': 'Servicio',
                'protocol': 'Protocolo',
                'risk_level': 'Nivel de Riesgo',
                'state': 'Estado',
                'learn_more': 'Saber Más',
                'how_to_close': 'Cómo Cerrar',
                'scanning': 'Escaneando...',
                'scan_complete': 'Escaneo Completo',
                'no_open_ports': 'No se encontraron puertos abiertos',
                'error': 'Error',
                'progress': 'Progreso'
            }
        }
    
    def get_text(self, key: str) -> str:
        """Get translated text for the current language"""
        try:
            return self.translations[self.current_language][key]
        except KeyError:
            # Fallback to English
            try:
                return self.translations['en'][key]
            except KeyError:
                return key  # Return the key itself if not found
    
    def set_language(self, language: str):
        """Set the current language"""
        if language in self.translations:
            self.current_language = language
            logging.info(f"Language changed to {language}")
        else:
            logging.warning(f"Language {language} not available")
    
    def get_available_languages(self) -> Dict[str, str]:
        """Get available languages"""
        return {
            'en': 'English',
            'es': 'Español'
        }
