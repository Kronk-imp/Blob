#!/usr/bin/env python3

import argparse
import json
import re
import statistics
from pathlib import Path
from typing import Any, Dict, List, Tuple
import base64
import binascii
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from lxml import html as lxml_html
import zmq
import sys
import time
from datetime import datetime, timedelta
from collections import OrderedDict
try:
    from interactsh import InteractshSession
except Exception:
    InteractshSession = None
import threading
import queue

# --- CONFIGURATION ---
SERVER_ERROR_STATUSES = [500, 501, 502, 503, 504]
SCRIPT_INDICATORS = [r"<script", r"alert\(", r"eval\("]
EXECUTION_INDICATORS = ['onerror', 'onload', 'onclick', 'onmouseover', 'javascript:', r'setTimeout\(', r'setInterval\(']
ERROR_MESSAGES = ['invalid email or password', 'login failed', 'invalid credentials', 'error']
ERROR_PATTERNS = [
    "you have an error in your sql syntax", "mysql_fetch", "unclosed quotation mark after the character string",
    "ODBC SQL Server Driver", "System.Exception", "Server Error in '/' Application", "ORA-00933",
    "psycopg2.errors", "PG::SyntaxError", "no such table", "cannot execute statement"
]
BASELINE_MARKER = '__BASELINE__'
TIME_THRESHOLD_FACTOR = 2.0

# Patterns de détection de vulnérabilités
VULNERABILITY_PATTERNS = {
    'xxe': [
        r'root:x:0:0:root',  # /etc/passwd
        r'<!ENTITY',
        r'SAXParseException',
        r'XMLParserError',
        r'XML document structures must start and end',
        r'Premature end of data in tag',
        r'SYSTEM.*file:',  # XXE avec protocole file
        r'expects parameter.*entity'  # Erreur d'entité XML
    ],
    'sqli': [
        r'mysql_fetch_array\(\)',
        r'Warning.*mysql_',
        r'MySQLSyntaxErrorException',
        r'pg_query\(\)',
        r'PostgreSQL.*ERROR',
        r'warning.*\Wpg_',
        r'valid PostgreSQL result',
        r'mssql_query\(\)',
        r'Unclosed quotation mark',
        r'Microsoft OLE DB Provider',
        r'UNION.*SELECT',
        r'sqlite3\.OperationalError',  # SQLite
        r'no such column',  # Erreur SQLite
        r'SQL syntax.*MariaDB',  # MariaDB
        r'Column count doesn\'t match',  # Erreur de colonnes
        r'GROUP BY.*clause',  # Erreur GROUP BY
        r'convert.*varchar'  # Erreur de conversion SQL Server
    ],
    'xss': [
        r'<script[^>]*>alert\([^)]*\)</script>',
        r'onerror\s*=\s*["\']?alert',
        r'javascript:\s*alert',
        r'<svg.*onload\s*=',  # SVG XSS
        r'<iframe.*srcdoc\s*=',  # iframe XSS
        r'<marquee.*onstart\s*=',  # Marquee XSS
        r'expression\s*\(.*\)',  # IE CSS expression
        r'vbscript:',  # VBScript protocol
        r'data:.*base64.*script'  # Data URI XSS
    ],
    'ssti': [
        r'49',  # 7*7
        r'uid=\d+\([^)]+\)',  # Résultat de 'id'
        r'jinja2\.exceptions',
        r'freemarker\.core',
        r'velocity\.exception',
        r'smarty.*error',  # Smarty
        r'twig.*error',  # Twig
        r'tornado\.template',  # Tornado
        r'erb.*error',  # Ruby ERB
        r'groovy\..*Exception'  # Groovy
    ],
    'lfi': [
        r'root:x:0:0:root',
        r'\[boot loader\]',  # Windows
        r'<?php',  # PHP source
        r'Failed opening.*for inclusion',
        r'include_path',  # PHP include error
        r'No such file or directory',
        r'system32.*config',  # Windows paths
        r'etc.*shadow',  # Shadow file
        r'\.\..*traversal',  # Path traversal
        r'file_get_contents\(\)'  # PHP file read
    ],
    'rce': [
        r'uid=\d+\([^)]+\)',
        r'Windows NT',
        r'Microsoft Windows',
        r'GNU/Linux',
        r'www-data.*www-data',  # Apache user
        r'nginx.*nginx',  # Nginx user  
        r'tomcat.*tomcat',  # Tomcat user
        r'/bin/.*sh',  # Shell paths
        r'Command.*not found',  # Command error
        r'is not recognized as'  # Windows command error
    ],
    'nosql': [
        r'MongoError',
        r'Cannot.*property.*undefined',
        r'CastError.*ObjectId',
        r'query.*timed out',
        r'maxTimeMS',
        r'collection\..*is not a function'
    ],
    'ldap': [
        r'ldap_bind',
        r'Invalid DN syntax',
        r'No such object',
        r'ldap_search\(\)',
        r'LDAP.*Operations error',
        r'Bad search filter'
    ],
    'graphql': [
        r'errors.*graphql',
        r'graphql.*error',
        r'cannot query field',
        r'field.*on type.*not found',
        r'expected type',
        r'syntax error.*graphql',
        r'validation error.*graphql',
        r'unknown argument',
        r'field.*doesn\'t exist on type',
        r'cannot be non-input type',
        r'expected at least one field',
        r'must be an object',
        r'graphql.*schema',
        r'introspection.*disabled',
        r'__schema',  # Introspection query
        r'__type',    # Type introspection
    ],
    'jwt': [
        r'invalid signature',
        r'jwt malformed',
        r'jwt expired',
        r'invalid token',
        r'signature verification failed',
        r'algorithm.*not supported',
        r'jwt.*decode.*error',
        r'token.*expired',
        r'invalid audience',
        r'invalid issuer',
        r'jwt.*none.*algorithm',  # Détection de l'algo none
        r'invalid jwt',
        r'could not decode token',
        r'signature.*required',
        r'token.*revoked',
    ],
    'prototype_pollution': [
        r'__proto__',
        r'constructor\[',
        r'constructor\.prototype',
        r'Object\.prototype',
        r'Cannot assign to read only property',
        r'prototype.*pollution',
        r'polluted',
        r'hasOwnProperty',
        r'isPrototypeOf',
        r'\[constructor\]',
        r'__proto__.*modified',
    ],
    'cache_poisoning': [
        r'X-Cache.*hit',
        r'Age:.*[0-9]+',
        r'X-Cache-Status',
        r'CF-Cache-Status',
        r'X-Varnish',
        r'X-Served-By',
        r'cache.*poisoned',
        r'vary:.*host',
        r'X-Forwarded-Host',
        r'X-Original-URL',
        r'X-Rewrite-URL',
    ]
}

# PATCH: Extension des patterns de vulnérabilité
VULNERABILITY_PATTERNS_EXTENDED = {
    **VULNERABILITY_PATTERNS,
    'graphql': [
        r'errors.*graphql',
        r'graphql.*error',
        r'cannot query field',
        r'field.*on type.*not found',
        r'expected type',
        r'syntax error.*graphql',
        r'validation error.*graphql',
        r'unknown argument',
        r'field.*doesn\'t exist on type',
        r'cannot be non-input type',
        r'expected at least one field',
        r'must be an object',
        r'graphql.*schema',
        r'introspection.*disabled',
        r'__schema',  # Introspection query
        r'__type',    # Type introspection
    ],
    'jwt': [
        r'invalid signature',
        r'jwt malformed',
        r'jwt expired',
        r'invalid token',
        r'signature verification failed',
        r'algorithm.*not supported',
        r'jwt.*decode.*error',
        r'token.*expired',
        r'invalid audience',
        r'invalid issuer',
        r'jwt.*none.*algorithm',  # Détection de l'algo none
        r'invalid jwt',
        r'could not decode token',
        r'signature.*required',
        r'token.*revoked',
    ],
    'prototype_pollution': [
        r'__proto__',
        r'constructor\[',
        r'constructor\.prototype',
        r'Object\.prototype',
        r'Cannot assign to read only property',
        r'prototype.*pollution',
        r'polluted',
        r'hasOwnProperty',
        r'isPrototypeOf',
        r'\[constructor\]',
        r'__proto__.*modified',
    ],
    'cache_poisoning': [
        r'X-Cache.*hit',
        r'Age:.*[0-9]+',
        r'X-Cache-Status',
        r'CF-Cache-Status',
        r'X-Varnish',
        r'X-Served-By',
        r'cache.*poisoned',
        r'vary:.*host',
        r'X-Forwarded-Host',
        r'X-Original-URL',
        r'X-Rewrite-URL',
    ]
}
VULNERABILITY_PATTERNS = VULNERABILITY_PATTERNS_EXTENDED

# --- UTILITAIRES ENCODAGE & REFLET ---
def html_encodings(payload):
    import html
    return [
        html.escape(payload),
        payload.encode("unicode_escape").decode(),
        ''.join('&#x{:x};'.format(ord(c)) for c in payload),
        ''.join('&#{};'.format(ord(c)) for c in payload),
        payload.encode("ascii", "xmlcharrefreplace").decode(),
    ]

def js_encodings(payload):
    encodings = []
    try:
        encodings.append(''.join('\\x{:02x}'.format(ord(c)) for c in payload))
        encodings.append(''.join('\\u{:04x}'.format(ord(c)) for c in payload))
        encodings.append(''.join('%{:02X}'.format(ord(c)) for c in payload))
        encodings.append(base64.b64encode(payload.encode()).decode())
    except Exception:
        pass
    return encodings

def split_payloads(payload):
    L = []
    if len(payload) > 6:
        n = len(payload) // 2
        L += [payload[:n], payload[n:], payload[:4], payload[-4:]]
    return list(set(x for x in L if len(x) >= 3 and x != payload))

def payload_mutations(payload):
    variants = set()
    variants.add(payload)
    for f in [html_encodings, js_encodings, split_payloads]:
        for v in f(payload):
            variants.add(v)
    return list(variants)

def detect_payload_reflection(snippet, payload):
    if not snippet or snippet.strip() == "":
        return (False, "", False, "")
    try:
        tree = lxml_html.fromstring(snippet)
    except Exception:
        if payload in snippet:
            return (True, "raw", False, "raw")
        return (False, "", False, "")
    payloads = payload_mutations(payload)
    for context, expr in [
        ("script", ".//script"),
        ("input_value", ".//input|.//textarea"),
        ("attribute", ".//*[@*]"),
        ("text", ".//text()"),
    ]:
        for el in tree.xpath(expr):
            target = el if isinstance(el, str) else (el.text or "") + " ".join([str(a) for a in el.attrib.values()])
            for pay in payloads:
                if pay in target:
                    encoded = any(e in target for e in html_encodings(pay) + js_encodings(pay))
                    mut = pay != payload
                    mutation = "mutation" if mut else ("encoded" if encoded else "exact")
                    return (True, context, encoded, mutation)
    for pay in payloads:
        if pay in snippet and pay != payload:
            encoded = any(e in snippet for e in html_encodings(pay) + js_encodings(pay))
            return (True, "any", encoded, "mutation")
    return (False, "", False, "")


def extract_title_hash(html_text):
    """Compute SHA1 of the <title> text (baseline helper)."""
    try:
        tree = lxml_html.fromstring(html_text or '')
        title = ''.join(tree.xpath('//title/text()')) or ''
        if not title:
            return ''
        import hashlib
        return hashlib.sha1(title.strip().encode('utf-8', errors='ignore')).hexdigest()
    except Exception:
        return ''
# --- OUTILS ANALYSE ---
def load_results(path):
    results = []
    with path.open(encoding='utf-8') as f:
        for line in f:
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return results

def calc_latency_threshold(times, factor=TIME_THRESHOLD_FACTOR):
    if not times:
        return float('inf')
    mean = statistics.mean(times)
    stdev = statistics.stdev(times) if len(times) > 1 else 0.0
    return mean + max(factor * stdev, 0.1)

def extract_response_time(entry):
    return float(entry.get('response_time') or entry.get('elapsed') or 0.0)

def detect_execution_sink(html_content):
    for pat in EXECUTION_INDICATORS:
        if re.search(pat, html_content, flags=re.IGNORECASE):
            return pat
    return ''

def detect_chaining(entry, html_content):
    inj = entry.get('injection_point', '').lower()
    return inj.startswith('get') and '<script' in html_content.lower()

def build_baseline(url, param):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = BASELINE_MARKER
    new_qs = urlencode(qs, doseq=True)
    new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_qs, ''))
    try:
        r = requests.get(new_url, timeout=5, verify=False)
        return r.text
    except requests.exceptions.SSLError as e:
        print(f"[!] Erreur SSL lors de la requête baseline pour {url}: {str(e)}")
        return ''
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Erreur de connexion lors de la requête baseline pour {url}: {str(e)}")
        return ''
    except requests.exceptions.Timeout as e:
        print(f"[!] Timeout lors de la requête baseline pour {url}: {str(e)}")
        return ''
    except Exception as e:
        print(f"[!] Erreur inattendue lors de la requête baseline pour {url}: {str(e)}")
        return ''

def build_post_baseline(url, fields, is_json=False):
    """
    Envoie un POST (form ou JSON) avec des identifiants volontairement invalides.
    Retourne le contenu de la réponse (HTML ou JSON).
    """
    try:
        # Remplit tous les champs avec valeurs "connues mauvaises"
        data = {k: '__BASELINE__' for k in fields}
        if is_json:
            resp = requests.post(url, json=data, timeout=5, verify=False)
        else:
            resp = requests.post(url, data=data, timeout=5, verify=False)
        return resp.text
    except requests.exceptions.SSLError as e:
        print(f"[!] Erreur SSL lors de la requête POST baseline pour {url}: {str(e)}")
        return ''
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Erreur de connexion lors de la requête POST baseline pour {url}: {str(e)}")
        return ''
    except requests.exceptions.Timeout as e:
        print(f"[!] Timeout lors de la requête POST baseline pour {url}: {str(e)}")
        return ''
    except Exception as e:
        print(f"[!] Erreur inattendue lors de la requête POST baseline pour {url}: {str(e)}")
        return ''


def detect_logout_or_session(text):
    return any(x in text.lower() for x in ['logout', 'se déconnecter', 'sign out', 'déconnexion'])

def detect_userid_or_email(text):
    if re.search(r"user.?id\s*[=:]\s*\d+", text, re.I):
        return True
    if re.search(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", text):
        return True
    return False

def detect_state_change(baseline_html, test_html):
    try:
        baseline_tree = lxml_html.fromstring(baseline_html)
        test_tree = lxml_html.fromstring(test_html)
        baseline_forms = baseline_tree.xpath("//form")
        test_forms = test_tree.xpath("//form")
        login_baseline = any('login' in (f.attrib.get('id', '') + f.attrib.get('name', '') + (f.text_content() or '')).lower() for f in baseline_forms)
        login_test = any('login' in (f.attrib.get('id', '') + f.attrib.get('name', '') + (f.text_content() or '')).lower() for f in test_forms)
        dashboard_test = any('dashboard' in (f.attrib.get('id', '') + f.attrib.get('name', '') + (f.text_content() or '')).lower() for f in test_forms)
        if login_baseline and not login_test and dashboard_test:
            return True
    except Exception:
        pass
    return False

def detect_session_indicators(text):
    """Détecte des indicateurs de session authentifiée"""
    indicators = [
        r"welcome\s+\w+",
        r"logged\s+in\s+as",
        r"dashboard",
        r"profile",
        r"settings",
        r"my\s+account",
        r"admin\s+panel",
        r"control\s+panel",
        r"user\s+id\s*[:=]\s*\d+",
        r"session\s+active",
        r"authenticated"
    ]
    
    text_lower = text.lower()
    for pattern in indicators:
        if re.search(pattern, text_lower):
            return True
    return False

def detect_xss_sinks(html_content):
    """Détecte des sinks XSS potentiels"""
    sinks = [
        r"document\.write\s*\(",
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"insertAdjacentHTML\s*\(",
        r"document\.writeln\s*\(",
        r"document\.domain\s*=",
        r"document\.cookie\s*=",
        r"window\.location",
        r"document\.location",
        r"window\.name\s*=",
        r"eval\s*\(",
        r"setTimeout\s*\(",
        r"setInterval\s*\(",
        r"Function\s*\(",
        r"execScript\s*\("
    ]
    
    for sink in sinks:
        if re.search(sink, html_content, re.IGNORECASE):
            return sink
    return None

def detect_vulnerability_type(response_content, payload):
    """Détecte le type de vulnérabilité basé sur la réponse"""
    vulns_detected = []
    
    for vuln_type, patterns in VULNERABILITY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                vulns_detected.append(vuln_type)
                break
    
    # Détection basée sur le payload
    if '{{7*7}}' in payload and '49' in response_content:
        vulns_detected.append('ssti')
    
    return vulns_detected
def detect_graphql_injection(response_content, payload):
    """Détecte les injections GraphQL spécifiques"""
    indicators = []
    
    # Vérifier si c'est une réponse GraphQL
    try:
        import json
        data = json.loads(response_content)
        if 'errors' in data or 'data' in data:
            # Structure GraphQL détectée
            if 'errors' in data:
                for error in data['errors']:
                    if isinstance(error, dict):
                        msg = str(error.get('message', '')).lower()
                        if any(pattern in msg for pattern in ['syntax', 'validation', 'field', 'type']):
                            indicators.append('graphql_error')
                            
            # Vérifier l'introspection
            if 'data' in data and data['data']:
                if '__schema' in data['data'] or '__type' in data['data']:
                    indicators.append('graphql_introspection')
                    
    except:
        pass
        
    # Vérifier les patterns dans le contenu brut
    content_lower = response_content.lower()
    if 'graphql' in content_lower and any(err in content_lower for err in ['error', 'exception', 'failed']):
        indicators.append('graphql_error_text')
        
    return indicators

def detect_jwt_vulnerability(response_content, payload, headers):
    """Détecte les vulnérabilités JWT"""
    indicators = []
    
    # Vérifier dans les headers
    auth_header = headers.get('Authorization', '')
    if 'Bearer' in auth_header:
        token = auth_header.replace('Bearer ', '').strip()
        
        # Vérifier si le token a été modifié avec succès
        if payload in token or 'none' in token.lower():
            indicators.append('jwt_manipulation')
            
    # Vérifier les messages d'erreur JWT
    content_lower = response_content.lower()
    jwt_errors = ['invalid signature', 'jwt malformed', 'jwt expired', 'invalid token']
    if any(err in content_lower for err in jwt_errors):
        indicators.append('jwt_error')
        
    # Détection de l'algorithme "none"
    if '"alg":"none"' in response_content or '"alg": "none"' in response_content:
        indicators.append('jwt_none_algorithm')
        
    return indicators

def detect_prototype_pollution(response_content, payload):
    """Détecte la pollution de prototype"""
    indicators = []
    
    # Vérifier si le payload a pollué l'objet
    if '__proto__' in payload or 'constructor' in payload:
        # Chercher des signes de pollution réussie
        if any(pattern in response_content for pattern in [
            'polluted', 'Cannot assign', 'read only property', '__proto__'
        ]):
            indicators.append('prototype_pollution_success')
            
    # Vérifier les erreurs JavaScript
    js_errors = ['TypeError', 'Cannot assign', 'prototype']
    if any(err in response_content for err in js_errors):
        indicators.append('prototype_pollution_error')
        
    return indicators

def detect_cache_poisoning(headers, response_content):
    """Détecte le cache poisoning"""
    indicators = []
    
    # Headers de cache
    cache_headers = ['X-Cache', 'Age', 'CF-Cache-Status', 'X-Varnish']
    for header in cache_headers:
        if header in headers:
            value = headers[header]
            if 'hit' in value.lower() or 'HIT' in value:
                indicators.append('cache_hit')
            elif 'miss' in value.lower() or 'MISS' in value:
                indicators.append('cache_miss')
                
    # Vérifier les headers manipulables
    poisonable_headers = ['X-Forwarded-Host', 'X-Original-URL', 'X-Rewrite-URL']
    for header in poisonable_headers:
        if header in headers:
            indicators.append('poisonable_header_reflected')
            
    return indicators

def detect_auth_bypass(bl_html, snippet, error_messages):
    """Fonction commune pour détecter un auth bypass"""
    bl = bl_html.lower()
    sn = snippet.lower()
    error_disappeared = any(err in bl and err not in sn for err in error_messages)
    state_change = detect_state_change(bl_html, snippet)
    logout_found = detect_logout_or_session(snippet)
    user_id_found = detect_userid_or_email(snippet)
    return error_disappeared and (logout_found or user_id_found or state_change or detect_session_indicators(snippet))

# --- ANALYSE D'UNE ENTRÉE ---
def analyze_entry(entry, time_thresh, get_baseline_func, entries=None):
    # Refined OAST handling:
    # - Only confirmed callbacks are priority 5 (and early-return)
    # - Bare 'OAST' vector probes should NOT be auto-marked as findings
    vec = str(entry.get("vector", "")).lower()
    oast_confirmed = bool(entry.get("oast_event") or entry.get("oast_url") or entry.get("oast_data") or entry.get("oast_raw_event"))
    if oast_confirmed:
        result = {
            'url': entry.get('url'),
            'injection_point': entry.get('injection_point'),
            'vector': 'OAST',
            'payload': entry.get('payload'),
            'priority': 5,
            'reasons': (entry.get('reasons') or []) + ['Confirmed OAST callback'],
            'reflected_context': '',
            'reflected_encoded': False,
            'mutation_type': '',
            'execution_sink': '',
            'can_chain': False,
            'method': entry.get('method'),
            'request_headers': entry.get('request_headers'),
            'request_body': entry.get('request_body'),
            'request_cookies': entry.get('request_cookies'),
            'request_params': entry.get('request_params'),
            'status_code': entry.get('status_code'),
            'response_time': entry.get('response_time'),
            'content_length': entry.get('content_length'),
            'response_snippet': entry.get('response_snippet'),
            'headers': entry.get('headers'),
            'error': entry.get('error'),
        }
        return result, True
    # else: continue normal analysis; we will only tag 'oast_probe' later if vec == 'oast'
    reasons = []
    if str(entry.get('vector','')).lower() == 'oast':
        reasons.append('oast_probe')

    priority = 0
    snippet = entry.get('response_snippet', '') or ''
    payload = entry.get('payload', '') or ''
    url = entry.get('url')
    inj_point = entry.get('injection_point', '')
    headers = entry.get('headers', {})
    status = int(entry.get('status_code') or 0)
    vector = entry.get('vector', '')

    # AJOUT: Détection des vulnérabilités
    vulns = detect_vulnerability_type(snippet, payload)
    if vulns:
        priority = max(priority, 5)
        reasons.append(f'Vulnérabilités détectées')

    # 1. Erreurs serveur (500+) seulement si déclenchée par un payload non trivial
    if status in SERVER_ERROR_STATUSES and payload:
        priority = max(priority, 3)
        reasons.append(f'Erreur serveur {status} (avec payload)')

    # 2. Réponse JSON success/admin
    content_type = headers.get('Content-Type', '').lower()
    if 'application/json' in content_type or snippet.lstrip().startswith('{'):
        try:
            data = json.loads(snippet)
            # PATCH : détecter status: success ou success: true (bool ou str), admin (bool ou str)
            if (
                data.get('success') is True or
                str(data.get('success', '')).lower() == 'true' or
                data.get('status', '').lower() == 'success'
            ):
                priority = max(priority, 5)
                reasons.append('Réponse JSON: succès détecté')
            if (
                data.get('is_admin') is True or
                str(data.get('is_admin', '')).lower() == 'true' or
                str(data.get('role', '')).lower() == 'admin'
            ):
                priority = max(priority, 5)
                reasons.append('Réponse JSON: admin détecté')
        except Exception:
            pass

    # 3. Stacktrace ou erreur technique
    low_snip = snippet.lower()
    for pat in ERROR_PATTERNS:
        if pat in low_snip:
            priority = max(priority, 3)
            reasons.append(f'Erreur détectée: {pat}')
            break

    # 4. Auth bypass fort uniquement (disparition erreur + présence user/admin/dashboard)
    m = re.match(r"GET param `([^`]+)`", inj_point, flags=re.IGNORECASE)
    if m:
        param = m.group(1)
        bl_html = get_baseline_func(url, param, "GET")
        # PATCH: Δlength vs baseline
        try:
            bl_len = len(bl_html or "")
            cur_len = int(entry.get('content_length') or 0)
            if bl_len and cur_len and abs(cur_len - bl_len) > 100:
                priority = max(priority, 3)
                reasons.append('Δlength>100B vs baseline')
        except Exception:
            pass
        if detect_auth_bypass(bl_html, snippet, ERROR_MESSAGES):
            priority = max(priority, 5)
            reasons.append('Auth bypass confirmé (indicateurs de session)')

    # 4b. Auth bypass POST form
    m2 = re.match(r"POST form `([^`]+)`", inj_point, flags=re.IGNORECASE)
    if m2:
        field = m2.group(1)
        bl_html = get_baseline_func(url, field, "POST")
        # PATCH: Δlength vs baseline
        try:
            bl_len = len(bl_html or "")
            cur_len = int(entry.get('content_length') or 0)
            if bl_len and cur_len and abs(cur_len - bl_len) > 100:
                priority = max(priority, 3)
                reasons.append('Δlength>100B vs baseline')
        except Exception:
            pass
        # PATCH: Δlength vs baseline
        try:
            bl_len = len(bl_html or "")
            cur_len = int(entry.get('content_length') or 0)
            if bl_len and cur_len and abs(cur_len - bl_len) > 100:
                priority = max(priority, 3)
                reasons.append('Δlength>100B vs baseline')
        except Exception:
            pass
        if detect_auth_bypass(bl_html, snippet, ERROR_MESSAGES):
            priority = max(priority, 5)
            reasons.append('Auth bypass POST confirmé (indicateurs de session)')

    # 4c. Auth bypass POST JSON
    m3 = re.match(r"json `([^`]+)`", inj_point, flags=re.IGNORECASE)
    if m3:
        field = m3.group(1)
        bl_html = get_baseline_func(url, field, "POSTJSON")
        if detect_auth_bypass(bl_html, snippet, ERROR_MESSAGES):
            priority = max(priority, 5)
            reasons.append('Auth bypass POST JSON confirmé (indicateurs de session)')

    # 5. Reflet du payload — stricte sur contexte
    is_reflected, reflected_context, reflected_encoded, mutation_type = detect_payload_reflection(snippet, payload)
    if is_reflected:
        if reflected_context == 'script' and not reflected_encoded:
            priority = max(priority, 5)
            reasons.append('XSS potentiel (script non encodé)')
            # AJOUT: Vérifier les sinks XSS
            xss_sink = detect_xss_sinks(snippet)
            if xss_sink:
                priority = max(priority, 5)
                reasons.append(f'XSS sink détecté: {xss_sink}')
        elif reflected_context == 'input_value' and not reflected_encoded:
            priority = max(priority, 4)
            reasons.append('Reflet input non encodé')
            # AJOUT: Vérifier les sinks XSS même pour les inputs
            xss_sink = detect_xss_sinks(snippet)
            if xss_sink:
                priority = max(priority, 5)
                reasons.append(f'XSS sink détecté: {xss_sink}')
        elif reflected_context == 'attribute' and not reflected_encoded and 'on' in snippet:
            priority = max(priority, 4)
            reasons.append('Reflet attribut JS')
            # AJOUT: Vérifier les sinks XSS pour les attributs
            xss_sink = detect_xss_sinks(snippet)
            if xss_sink:
                priority = max(priority, 5)
                reasons.append(f'XSS sink détecté: {xss_sink}')
        # Tous les autres cas (texte, mutation, encodé) : PAS intéressant

    # 6. Indicators script/sink
    for pat in SCRIPT_INDICATORS:
        if re.search(pat, snippet, flags=re.IGNORECASE):
            priority = max(priority, 5); reasons.append(f'Indicator {pat}')
            break
    exec_sink = detect_execution_sink(snippet)
    if exec_sink:
        priority = max(priority, 5); reasons.append(f'Sink {exec_sink}')

    # 7. Chaining
    can_chain = detect_chaining(entry, snippet)
    if can_chain: reasons.append('Chaînage possible')

    # 7. Attaques par timing
    if entries is not None:
        baseline_times = []
        for e in entries:
            if e.get('url') == url and e.get('injection_point') == inj_point:
                baseline_times.append(extract_response_time(e))
        if baseline_times:
            is_timing, z_score = detect_timing_attack(entry, baseline_times)
            if is_timing:
                priority = max(priority, 4)
                reasons.append(f'Attaque par timing possible (z-score: {z_score:.2f})')
    
    interesting = priority > 0 or entry.get('interesting', False)

    result = {
        'url': url,
        'injection_point': inj_point,
        'vector': entry.get('vector', None),
        'payload': payload,
        'priority': priority,
        'reasons': reasons,
        'reflected_context': reflected_context,
        'reflected_encoded': reflected_encoded,
        'mutation_type': mutation_type,
        'execution_sink': exec_sink,
        'can_chain': can_chain,
        'method': entry.get('method'),
        'request_headers': entry.get('request_headers'),
        'request_body': entry.get('request_body'),
        'request_cookies': entry.get('request_cookies'),
        'request_params': entry.get('request_params'),
        'status_code': entry.get('status_code'),
        'response_time': entry.get('response_time'),
        'content_length': entry.get('content_length'),
        'response_snippet': entry.get('response_snippet'),
        'headers': entry.get('headers'),
        'error': entry.get('error'),
    }
    return result, interesting

def analyze_entry_extended(entry, time_thresh, get_baseline_func, entries=None):
    """Version étendue de analyze_entry avec nouvelles détections"""
    # Appeler l'ancienne fonction
    result, interesting = analyze_entry(entry, time_thresh, get_baseline_func, entries)
    
    # Variables pour l'analyse étendue
    snippet = entry.get('response_snippet', '') or ''
    payload = entry.get('payload', '') or ''
    headers = entry.get('headers', {})
    vector = entry.get('vector', '')
    
    # Détections supplémentaires selon le vecteur
    if vector == 'graphql' or 'graphql' in payload.lower():
        graphql_indicators = detect_graphql_injection(snippet, payload)
        if graphql_indicators:
            result['priority'] = max(result.get('priority', 0), 5)
            result['reasons'] = result.get('reasons', []) + [f'GraphQL: {", ".join(graphql_indicators)}']
            result['graphql_indicators'] = graphql_indicators
            interesting = True
            
    if vector == 'jwt' or 'jwt' in payload.lower() or 'bearer' in str(headers).lower():
        jwt_indicators = detect_jwt_vulnerability(snippet, payload, headers)
        if jwt_indicators:
            result['priority'] = max(result.get('priority', 0), 5)
            result['reasons'] = result.get('reasons', []) + [f'JWT: {", ".join(jwt_indicators)}']
            result['jwt_indicators'] = jwt_indicators
            interesting = True
            
    if '__proto__' in payload or 'constructor' in payload:
        pollution_indicators = detect_prototype_pollution(snippet, payload)
        if pollution_indicators:
            result['priority'] = max(result.get('priority', 0), 5)
            result['reasons'] = result.get('reasons', []) + [f'Prototype Pollution: {", ".join(pollution_indicators)}']
            result['prototype_pollution_indicators'] = pollution_indicators
            interesting = True
            
    # Cache poisoning pour tous les vecteurs
    cache_indicators = detect_cache_poisoning(headers, snippet)
    if cache_indicators and any(poison in cache_indicators for poison in ['poisonable_header_reflected', 'cache_hit']):
        result['priority'] = max(result.get('priority', 0), 4)
        result['reasons'] = result.get('reasons', []) + [f'Cache Poisoning: {", ".join(cache_indicators)}']
        result['cache_indicators'] = cache_indicators
        interesting = True
        
    return result, interesting

class StreamingAnalyzer:
    def __init__(self):
        self.context = zmq.Context()
        self.receiver = self.context.socket(zmq.PULL)
        self.receiver.bind("tcp://*:5556")
        
        # Socket pour heartbeat
        self.heartbeat = self.context.socket(zmq.PUB)
        self.heartbeat.bind("tcp://*:5557")
        
        # Cache des baselines avec TTL
        self.baseline_cache = OrderedDict()  # Pour maintenir l'ordre d'insertion
        self.baseline_ttl = timedelta(minutes=30)  # TTL de 30 minutes
        self.baseline_timestamps = {}  # Timestamps des entrées
        self.baseline_cache_size = 1000
        # OAST structures
        self.oast_sessions = {}
        self.oast_session_keys = set()
        self.oast_map = {}
        self.internal_queue = queue.Queue()
        self.running = True
        self.results = {'interesting': [], 'uninteresting': []}
        if InteractshSession is not None:
            self.oast_thread = threading.Thread(target=self._oast_consumer_loop, daemon=True)
            self.oast_thread.start()
        self.last_message_time = time.time()
        self.pending_count = 0
        self.IDLE_TIMEOUT = 120  # Timeout augmenté à 120s
        
    def get_baseline(self, url, param, method="GET"):
        """Récupère une baseline avec cache et TTL"""
        cache_key = (url, param, method)
        now = datetime.now()
        
        # Vérifier si l'entrée existe et n'est pas expirée
        if cache_key in self.baseline_cache:
            timestamp = self.baseline_timestamps.get(cache_key)
            if timestamp and (now - timestamp) < self.baseline_ttl:
                # Déplacer à la fin pour LRU
                self.baseline_cache.move_to_end(cache_key)
                return self.baseline_cache[cache_key]
            else:
                # Entrée expirée, la supprimer
                del self.baseline_cache[cache_key]
                del self.baseline_timestamps[cache_key]
        
        # Nettoyer le cache si trop grand
        while len(self.baseline_cache) >= self.baseline_cache_size:
            # Supprimer l'entrée la plus ancienne
            oldest_key = next(iter(self.baseline_cache))
            del self.baseline_cache[oldest_key]
            if oldest_key in self.baseline_timestamps:
                del self.baseline_timestamps[oldest_key]
        
        # Construire la baseline
        if method == "GET":
            baseline = build_baseline(url, param)
        else:
            baseline = build_post_baseline(url, {param: "baseline"}, is_json=(method == "POSTJSON"))
            
        # Stocker avec timestamp
        self.baseline_cache[cache_key] = baseline
        self.baseline_timestamps[cache_key] = now
        
        return baseline
        
    # --- OAST centralization (analyzer owns callback polling) ---
    def _register_oast_session(self, session_dict):
        if InteractshSession is None or not session_dict:
            return
        key = f"{session_dict.get('server_hostname')}::{session_dict.get('cid')}"
        if key in self.oast_session_keys:
            return
        try:
            session = InteractshSession.from_dict(session_dict)
        except Exception as e:
            print(f"[analyzer] OAST session revive failed: {e}")
            return
        self.oast_sessions[key] = session
        self.oast_session_keys.add(key)
        print(f"[analyzer] OAST session registered for {session_dict.get('server_hostname')} cid={session_dict.get('cid')}")

    def _oast_consumer_loop(self):
        if InteractshSession is None:
            print("[analyzer] OAST disabled (interactsh not available)")
            return
        print("[analyzer] OAST consumer started")
        while self.running:
            try:
                for key, session in list(self.oast_sessions.items()):
                    try:
                        for ev in session.poll():
                            try:
                                host = ev.full_hostname()
                            except Exception:
                                host = None
                            meta = self.oast_map.get(host) or {}
                            entry = {
                                'vector': 'OAST',
                                'oast_event': True,
                                'oast_url': host,
                                'url': meta.get('url'),
                                'injection_point': meta.get('injection_point'),
                                'payload': meta.get('payload'),
                                'method': meta.get('method'),
                                'reasons': ['oast_callback'],
                                'timestamp': time.time(),
                            }
                            try:
                                self.internal_queue.put_nowait(entry)
                            except Exception:
                                pass
                    except Exception as e:
                        print(f"[analyzer] OAST poll error for {key}: {e}")
                time.sleep(2)
            except Exception as e:
                print(f"[analyzer] OAST loop error: {e}")
                time.sleep(2)
    def run_streaming(self):
        print("[+] Streaming Analyzer démarré sur port 5556")
        
        # Créer le dossier de sortie
        results_dir = Path("results")
        results_dir.mkdir(exist_ok=True)
        
        interesting_file = results_dir / "results_filtered.jsonl"
        
        # Ouvrir le fichier en mode append
        interesting_out = open(interesting_file, 'a', encoding='utf-8')
        
        while self.running:
            try:
                if self.receiver.poll(1000):
                    entry = self.receiver.recv_json()
                    self.last_message_time = time.time()
                    self.pending_count += 1
                    
                    # OAST: register session + correlation when a probe arrives
                    if entry.get('oast_probe'):
                        if entry.get('oast_session'):
                            self._register_oast_session(entry.get('oast_session'))
                        if entry.get('oast_host'):
                            self.oast_map[entry['oast_host']] = {
                                'url': entry.get('url'),
                                'injection_point': entry.get('injection_point'),
                                'payload': entry.get('payload'),
                                'method': entry.get('method'),
                                'ts': time.time(),
                            }
                    
                    print(f"[analyzer] Reçu: {entry.get('url')} - {entry.get('injection_point')}")
                    print(f"[analyzer] Payload: {entry.get('payload')}")
                    
                    # Analyser avec le cache de baseline
                    result, interesting = analyze_entry_extended(
                        entry, 
                        float('inf'),  # Pas de threshold en streaming
                        self.get_baseline  # Passer la fonction de cache
                    )
                    
                    self.pending_count -= 1
                    
                    # Log de progression
                    print(f"[analyzer] Résultat: interesting={interesting}, priority={result.get('priority')}")
                    if result.get('reasons'):
                        print(f"[analyzer] Raisons: {result.get('reasons')}")
                    
                    # IMPORTANT: Écrire le résultat immédiatement uniquement si intéressant
                    if interesting:
                        self.results['interesting'].append(result)
                        json.dump(result, interesting_out, ensure_ascii=False)
                        interesting_out.write('\n')
                        interesting_out.flush()  # Forcer l'écriture sur disque
                        print(f"[analyzer] ✓ Résultat intéressant sauvegardé: {result.get('url')} - Priority: {result.get('priority')}")
                    # Sinon, on ignore simplement
                    
                    # Drain internal OAST queue (confirmed callbacks)
                    try:
                        while True:
                            oast_entry = self.internal_queue.get_nowait()
                            result, interesting = analyze_entry_extended(
                                oast_entry,
                                float('inf'),
                                self.get_baseline
                            )
                            if interesting:
                                self.results['interesting'].append(result)
                                json.dump(result, interesting_out, ensure_ascii=False)
                                interesting_out.write('\n')
                                interesting_out.flush()
                    except queue.Empty:
                        pass
                    
                    # Envoyer un heartbeat
                    self.heartbeat.send_string("heartbeat")
                    
            except zmq.error.ZMQError as e:
                if e.errno == zmq.EAGAIN:
                    # Timeout normal, continuer
                    pass
                else:
                    print(f"[!] Erreur ZMQ dans le streaming: {str(e)}")
                    time.sleep(1)
            except Exception as e:
                print(f"[!] Erreur dans le streaming: {str(e)}")
                import traceback
                traceback.print_exc()
                time.sleep(1)
                
            # Vérifier le timeout
            if time.time() - self.last_message_time > self.IDLE_TIMEOUT:
                print(f"[!] Timeout après {self.IDLE_TIMEOUT}s sans activité")
                self.running = False
        
        # Fermer le fichier
        interesting_out.close()
        
        print(f"[+] Résultats finaux: {len(self.results['interesting'])} intéressants")
        print(f"[+] Fichier sauvegardé dans: {results_dir}")
        
        self.cleanup()
        
    def cleanup(self):
        self.running = False
        self.receiver.close()
        self.heartbeat.close()
        self.context.term()
        print(f"[+] Résultats: {len(self.results['interesting'])} intéressants")

# Ajouter cette nouvelle fonction pour la détection de timing attacks
def detect_timing_attack(entry, baseline_times, threshold_multiplier=3):
    """Détecte les timing attacks potentiels"""
    response_time = extract_response_time(entry)
    
    if not baseline_times or response_time == 0:
        return False, 0
    
    avg_baseline = statistics.mean(baseline_times)
    std_baseline = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0
    
    # Calculer le z-score
    if std_baseline > 0:
        z_score = (response_time - avg_baseline) / std_baseline
    else:
        z_score = (response_time - avg_baseline) / (avg_baseline * 0.1) if avg_baseline > 0 else 0
    
    # Détecter si c'est significativement plus lent
    is_timing_attack = z_score > threshold_multiplier
    
    return is_timing_attack, z_score

class BaselineManager:
    """Gestionnaire de baselines pour différents types de requêtes"""
    
    def __init__(self):
        self.baseline_map = {}
        
    def get_baseline(self, url, param, method):
        """Récupère la baseline pour une URL, un paramètre et une méthode donnés"""
        key = (url, param, method)
        return self.baseline_map.get(key)
        
    def set_baseline(self, url, param, method, baseline):
        """Définit la baseline pour une URL, un paramètre et une méthode donnés"""
        key = (url, param, method)
        self.baseline_map[key] = baseline
        
    def build_baselines(self, entries):
        """Construit les baselines pour une liste d'entrées"""
        for ent in entries:
            inj = ent.get('injection_point', '')
            url = ent.get('url')
            
            # GET baseline
            m = re.match(r"GET param `([^`]+)`", inj, flags=re.IGNORECASE)
            if m:
                param = m.group(1)
                key = (url, param, 'GET')
                if key not in self.baseline_map:
                    self.baseline_map[key] = build_baseline(url, param)
                    
            # POST form baseline
            m2 = re.match(r"POST form `([^`]+)`", inj, flags=re.IGNORECASE)
            if m2:
                field = m2.group(1)
                req_body = ent.get('request_body', {}) or {}
                if isinstance(req_body, dict) and req_body:
                    key = (url, field, 'POST')
                    if key not in self.baseline_map:
                        self.baseline_map[key] = build_post_baseline(url, list(req_body.keys()), is_json=False)
                        
            # POST JSON baseline
            m3 = re.match(r"json `([^`]+)`", inj, flags=re.IGNORECASE)
            if m3:
                field = m3.group(1)
                req_body = ent.get('request_body', {}) or {}
                if isinstance(req_body, dict) and req_body:
                    key = (url, field, 'POSTJSON')
                    if key not in self.baseline_map:
                        self.baseline_map[key] = build_post_baseline(url, list(req_body.keys()), is_json=True)

def main():
    parser = argparse.ArgumentParser(description='Analyse des résultats de scan')
    parser.add_argument('--streaming', '-s', action='store_true',
                      help='Mode streaming ZMQ (sans fichiers)')
    
    # Arguments pour le mode batch
    batch_group = parser.add_argument_group('Mode batch')
    batch_group.add_argument('--input', '-i', type=Path,
                          help='Fichier d\'entrée pour le mode batch')
    batch_group.add_argument('--output-interesting', '-oi', type=Path,
                          help='Fichier de sortie pour résultats intéressants (mode batch)')
    batch_group.add_argument('--output-uninteresting', '-ou', type=Path,
                          help='Fichier de sortie pour résultats non-intéressants (mode batch)')
    
    # Arguments communs
    parser.add_argument('--time-threshold', '-t', type=float, default=TIME_THRESHOLD_FACTOR,
                      help=f'Facteur de seuil temporel (défaut: {TIME_THRESHOLD_FACTOR})')
    
    args = parser.parse_args()
    
    if args.streaming:
        # Mode streaming
        analyzer = StreamingAnalyzer()
        try:
            analyzer.run_streaming()
        except KeyboardInterrupt:
            print("\n[*] Arrêt du mode streaming...")
            analyzer.cleanup()
        except Exception as e:
            print(f"[!] Erreur en mode streaming: {e}")
            analyzer.cleanup()
    else:
        # Mode batch - vérification des arguments requis
        if not all([args.input, args.output_interesting, args.output_uninteresting]):
            parser.error("En mode batch, les arguments --input, --output-interesting et --output-uninteresting sont requis")
            
        # Créer les dossiers parents si nécessaire
        args.input.parent.mkdir(exist_ok=True)
        args.output_interesting.parent.mkdir(exist_ok=True)
        args.output_uninteresting.parent.mkdir(exist_ok=True)
        
        try:
            with args.input.open() as f:
                entries = [json.loads(line) for line in f]
        except json.JSONDecodeError as e:
            print(f"[!] Erreur de décodage JSON dans le fichier d'entrée: {e}")
            return
        except Exception as e:
            print(f"[!] Erreur lors de la lecture du fichier d'entrée: {e}")
            return

        thresh = args.time_threshold
        baseline_mgr = BaselineManager()
        baseline_mgr.build_baselines(entries)

        try:
            with args.output_interesting.open('w', encoding='utf-8') as out_i, \
                 args.output_uninteresting.open('w', encoding='utf-8') as out_u:
                
                for ent in entries:
                    res, interesting = analyze_entry_extended(ent, thresh, baseline_mgr.get_baseline, entries=entries)
                    writer = out_i if interesting else out_u
                    writer.write(json.dumps(res, ensure_ascii=False) + '\n')
                    
            print(f"[+] Analyse batch terminée avec succès!")
            print(f"[*] Résultats intéressants: {args.output_interesting}")
            print(f"[*] Résultats non-intéressants: {args.output_uninteresting}")
                    
        except Exception as e:
            print(f"[!] Erreur lors de l'écriture des résultats: {e}")
            return

if __name__ == '__main__':
    main()
