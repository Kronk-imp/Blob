#!/usr/bin/env python3
"""
Module de filtrage simple basé sur le contexte d'injection
Suit la répartition logique des vecteurs selon où ils sont pertinents
"""

import re
from urllib.parse import urlparse

class VectorFilter:
    def __init__(self):
        # Extensions statiques (pas d'injection)
        self.static_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
            '.css', '.js', '.woff', '.woff2', '.ttf',
            '.mp4', '.mp3', '.zip', '.pdf'
        }
        
        # Mapping simple : contexte -> vecteurs valides
        self.context_vectors = {
            'header': {
                # Headers spécifiques et leurs vecteurs
                'User-Agent': ['cmdi', 'xss', 'ssti', 'oast'],
                'Referer': ['xss', 'oast'],
                'X-Forwarded-For': ['cmdi', 'xss', 'oast'],
                'X-Real-IP': ['cmdi', 'oast'],
                'Authorization': ['ldap', 'jwt', 'oast'],
                'Content-Type': ['xxe', 'oast'],
                'Accept': ['xxe', 'oast'],
                'Accept-Language': ['ssti', 'oast'],
                'X-User-DN': ['ldap', 'oast'],
                # Headers custom/autres
                'default': ['cmdi', 'ssti', 'oast']
            },
            'param': {
                # Tous les vecteurs possibles pour les params
                'all': ['cmdi', 'sqli', 'nosqli', 'xss', 'ssti', 'lfi', 
                       'jsoni', 'xxe', 'jwt', 'ldap', 'oast']
            },
            'cookie': {
                # Vecteurs pour les cookies
                'all': ['jwt', 'sqli', 'xss', 'ssti', 'oast']
            },
            'json': {
                # Pour les bodies JSON
                'all': ['sqli', 'nosqli', 'jsoni', 'xss', 'ssti', 'oast']
            },
            'xml': {
                # Pour les bodies XML
                'all': ['xxe', 'sqli', 'xss', 'oast']
            },
            'multipart': {
                # Pour les uploads
                'all': ['xxe', 'lfi', 'ssti', 'oast']
            }
        }
        
        # Détection GraphQL simple
        self.graphql_patterns = ['/graphql', '/query', '/gql', 'graphql']

    def is_static_resource(self, url):
        """Check si c'est une ressource statique"""
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in self.static_extensions)

    def should_test_endpoint(self, url, method='GET'):
        """Détermine si on doit tester cet endpoint"""
        # Skip les fichiers statiques
        if self.is_static_resource(url):
            return False
        
        # Toujours tester les POST
        if method == 'POST':
            return True
            
        # Tester si paramètres GET
        if '?' in url:
            return True
            
        return True  # Par défaut on teste

    def get_context_type(self, injection_point, content_type=''):
        """Détermine le type de contexte depuis l'injection point"""
        point_lower = injection_point.lower()
        
        # Headers
        if 'header' in point_lower:
            return 'header'
        
        # Cookies
        elif 'cookie' in point_lower:
            return 'cookie'
            
        # JSON
        elif 'json' in point_lower or 'application/json' in content_type.lower():
            return 'json'
            
        # XML
        elif 'xml' in point_lower or 'xml' in content_type.lower():
            return 'xml'
            
        # Multipart/Upload
        elif 'multipart' in content_type.lower():
            return 'multipart'
            
        # Par défaut : paramètre
        else:
            return 'param'

    def filter_vectors(self, url, injection_point, all_vectors, content_type=''):
        """
        Filtre les vecteurs selon le contexte
        Simple et direct : contexte -> vecteurs valides
        """
        # Skip les ressources statiques
        if self.is_static_resource(url):
            return []
        
        # Déterminer le contexte
        context = self.get_context_type(injection_point, content_type)
        
        # Récupérer les vecteurs valides pour ce contexte
        valid_vectors = []
        
        if context == 'header':
            # Extraire le nom du header
            match = re.search(r'header `([^`]+)`', injection_point, re.I)
            if match:
                header_name = match.group(1)
                # Chercher les vecteurs pour ce header spécifique
                header_vectors = self.context_vectors['header'].get(
                    header_name, 
                    self.context_vectors['header']['default']
                )
                valid_vectors = header_vectors
            else:
                valid_vectors = self.context_vectors['header']['default']
                
        else:
            # Pour tous les autres contextes
            valid_vectors = self.context_vectors.get(context, {}).get('all', [])
        
        # Ajouter GraphQL si c'est un endpoint GraphQL
        if any(pattern in url.lower() for pattern in self.graphql_patterns):
            if 'graphql' in all_vectors and 'graphql' not in valid_vectors:
                valid_vectors.append('graphql')
        
        # Retourner seulement les vecteurs disponibles
        return [v for v in valid_vectors if v in all_vectors]

    def get_stats(self):
        """Retourne des stats sur le filtrage"""
        return {
            'mode': 'context-based',
            'contexts': list(self.context_vectors.keys()),
            'total_rules': sum(len(v) for v in self.context_vectors.values())
        }

# Pour la compatibilité avec l'ancien code
class FilterStats:
    def __init__(self):
        self.total_tests = 0
        self.filtered_tests = 0
        self.skipped_endpoints = 0
        
    def record_filtering(self, original_count, filtered_count):
        self.total_tests += original_count
        self.filtered_tests += filtered_count
        
    def record_skip(self):
        self.skipped_endpoints += 1
        
    def print_stats(self):
        if self.total_tests > 0:
            reduction = ((self.total_tests - self.filtered_tests) / self.total_tests) * 100
            print(f"\n[*] Statistiques de filtrage:")
            print(f"    - Tests possibles: {self.total_tests}")
            print(f"    - Tests effectués: {self.filtered_tests}")
            print(f"    - Réduction: {reduction:.1f}%")
            print(f"    - Endpoints ignorés: {self.skipped_endpoints}")
