from mitmproxy import http
import json
import os
from urllib.parse import urlparse
import zmq
import pickle
import re
import base64


from typing import Dict, Any

# === Filtrage des en-têtes hop-by-hop (inutile à tester) ===
# Réf RFC 7230 §6.1 — ces en-têtes sont consommés par les proxys/connexions
# et n'atteignent pas l'application; les garder crée du bruit côté injector.
HOP_BY_HOP = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "content-length",
    "upgrade-insecure-requests",
    "accept",
    "accept-encoding",
    "cache-control",
    "pragma",
    "sec-fetch-mode", 
    "sec-fetch-site", 
    "sec-fetch-dest", 
    "sec-ch-ua", 
    "sec-ch-ua-mobile", 
    "sec-ch-ua-platform", 
    "dnt", 
    "host", 
    "cookie", 
    "user-agent"
}

def filter_hop_by_hop(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Retourne un dict de headers sans ceux considérés hop-by-hop.
    Prend aussi en compte la liste donnée par l'en-tête 'Connection'.
    """
    if not headers:
        return {}
    # Construire le set de noms à supprimer (insensible à la casse)
    drop = set(HOP_BY_HOP)
    # Si 'Connection' précise d'autres noms hop-by-hop, les retirer aussi
    conn_val = None
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == "connection":
            conn_val = v
            break
    if conn_val:
        vals = ",".join(conn_val) if isinstance(conn_val, (list, tuple)) else str(conn_val)
        for token in vals.split(","):
            t = token.strip().lower()
            if t:
                drop.add(t)
    # Filtrer en conservant la casse d'origine des clés
    cleaned = {k: v for k, v in headers.items() if isinstance(k, str) and k.strip().lower() not in drop}
    # Ceinture+bretelles contre variantes de casse
    cleaned.pop("Content-Length", None)
    cleaned.pop("content-length", None)
    return cleaned

# === Chargement dynamique des domaines/IP depuis urls.txt ===
def load_allowed_domains():
    urls_file = os.environ.get("URLS_FILE", "urls.txt")
    allowed = set()
    try:
        with open(urls_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parsed = urlparse(line)
                    hostname = parsed.hostname
                    if hostname:
                        allowed.add(hostname)
    except Exception as e:
        print(f"[logscan] ⚠ Impossible de charger les cibles depuis {urls_file}: {e}")
    return allowed

ALLOWED_DOMAINS = load_allowed_domains()

# Initialisation ZMQ
context = zmq.Context()
socket = context.socket(zmq.PUSH)
socket.setsockopt(zmq.LINGER, 0)  # Ne pas bloquer sur close
try:
    socket.connect("tcp://localhost:5555")
    print("[logscan] Connected to injector on port 5555")
except Exception as e:
    print(f"[logscan] ⚠ Impossible de se connecter à l'injector: {e}")
    print("[logscan] Les requêtes seront sauvegardées dans reco/proxy_scans.jsonl")
    socket = None

def safe_dict(d):
    try:
        # Corrige la sérialisation pour les MultiDictView etc.
        return {str(k): str(v) for k, v in d.items()}
    except Exception:
        try:
            return dict(d)
        except Exception:
            return str(d)

def safe_body(request):
    """Extrait le body de la requête de manière sûre avec support étendu"""
    content_type = request.headers.get("content-type", "").lower()
    
    # Debug
    print(f"[logscan] Content-Type: {content_type}")
    print(f"[logscan] Body raw length: {len(request.content) if request.content else 0}")
    
    # JSON
    if "application/json" in content_type:
        try:
            parsed = request.json()
            print(f"[logscan] Parsed JSON: {parsed}")
            return parsed
        except Exception as e:
            print(f"[logscan] Erreur parsing JSON: {e}")
            # Essayer de retourner le texte brut
            try:
                return request.get_text()
            except:
                return None
    
    # URL-encoded form
    elif "application/x-www-form-urlencoded" in content_type:
        try:
            # Méthode 1 : utiliser urlencoded_form de mitmproxy
            if hasattr(request, 'urlencoded_form'):
                parsed = {str(k): str(v) for k, v in request.urlencoded_form.items()}
                print(f"[logscan] Parsed form (mitmproxy): {parsed}")
                return parsed
        except Exception as e:
            print(f"[logscan] Erreur urlencoded_form: {e}")
        
        try:
            # Méthode 2 : parser manuellement
            from urllib.parse import parse_qs
            body_str = request.content.decode('utf-8', errors='ignore')
            parsed = parse_qs(body_str, keep_blank_values=True)
            # parse_qs retourne des listes, on prend la première valeur
            parsed = {k: v[0] if isinstance(v, list) and len(v) == 1 else v 
                     for k, v in parsed.items()}
            print(f"[logscan] Parsed form (manuel): {parsed}")
            return parsed
        except Exception as e:
            print(f"[logscan] Erreur parse manuel: {e}")
    
    # Multipart form data
    elif "multipart/form-data" in content_type:
        try:
            # Extraire le boundary
            boundary = None
            for part in content_type.split(';'):
                part = part.strip()
                if part.startswith('boundary='):
                    boundary = part.split('=', 1)[1].strip('"')
                    break
            
            if boundary and request.content:
                # Parser multipart basique
                multipart_data = {}
                parts = request.content.split(f'--{boundary}'.encode())
                
                for part in parts:
                    if not part or part == b'--\r\n':
                        continue
                    
                    # Séparer headers et contenu
                    header_end = part.find(b'\r\n\r\n')
                    if header_end == -1:
                        header_end = part.find(b'\n\n')
                    
                    if header_end != -1:
                        headers = part[:header_end].decode('utf-8', errors='ignore')
                        content = part[header_end + 4:].rstrip(b'\r\n')
                        
                        # Extraire le nom du champ
                        name_match = re.search(r'name="([^"]+)"', headers)
                        if name_match:
                            field_name = name_match.group(1)
                            # Essayer de décoder le contenu
                            try:
                                multipart_data[field_name] = content.decode('utf-8')
                            except:
                                # Si échec, stocker les bytes encodés en base64
                                multipart_data[field_name] = base64.b64encode(content).decode()
                
                print(f"[logscan] Parsed multipart: {list(multipart_data.keys())}")
                return multipart_data
                
        except Exception as e:
            print(f"[logscan] Erreur parsing multipart: {e}")
    
    # XML
    elif "application/xml" in content_type or "text/xml" in content_type:
        try:
            text = request.get_text()
            if text:
                print(f"[logscan] XML content (first 200 chars): {text[:200]}")
                return {"__xml__": text}  # Marqueur spécial pour XML
        except:
            pass
    
    # Texte brut ou autre
    try:
        text = request.get_text()
        if text:
            print(f"[logscan] Body text (first 200 chars): {text[:200]}")
            # Pour les content-types non reconnus, essayer de détecter le format
            text_stripped = text.strip()
            if text_stripped.startswith('{') and text_stripped.endswith('}'):
                # Pourrait être du JSON
                try:
                    return json.loads(text)
                except:
                    pass
            elif '=' in text and '&' in text:
                # Pourrait être du form-urlencoded
                try:
                    from urllib.parse import parse_qs
                    parsed = parse_qs(text, keep_blank_values=True)
                    parsed = {k: v[0] if isinstance(v, list) and len(v) == 1 else v 
                             for k, v in parsed.items()}
                    if parsed:
                        return parsed
                except:
                    pass
            
            return text
    except Exception:
        pass
    
    # En dernier recours, retourner les bytes bruts encodés
    if request.content:
        try:
            return {"__raw_base64__": base64.b64encode(request.content).decode()}
        except:
            pass
    
    print("[logscan] Impossible de parser le body")
    return None

def is_request_too_large(request, max_size_mb=10):
    """Vérifie si la requête est trop volumineuse"""
    if request.content:
        size_mb = len(request.content) / (1024 * 1024)
        if size_mb > max_size_mb:
            print(f"[logscan] Requête trop volumineuse: {size_mb:.2f}MB > {max_size_mb}MB")
            return True
    return False

def allowed(flow):
    """Vérifie si la requête est pour une cible autorisée (domaine/IP)."""
    host = flow.request.host
    return host in ALLOWED_DOMAINS

def request(flow: http.HTTPFlow):
    if not allowed(flow):
        return
    
    # Vérifier la taille
    if is_request_too_large(flow.request):
        print(f"[logscan] Requête ignorée (trop volumineuse): {flow.request.pretty_url}")
        return
    
    entry = {
        "url": flow.request.pretty_url,
        "method": flow.request.method,
        "request_headers": filter_hop_by_hop(safe_dict(flow.request.headers)),
        "request_cookies": safe_dict(flow.request.cookies),
        "request_params": safe_dict(flow.request.query),
        "request_body": safe_body(flow.request),
        "content_type": flow.request.headers.get("content-type", ""),
        "http_version": flow.request.http_version,
        "timestamp_start": getattr(flow.request, "timestamp_start", None),
    }
    
    # Debug: afficher la requête capturée
    print(f"[logscan] Capture: {flow.request.method} {flow.request.pretty_url}")
    if flow.request.content:
        print(f"[logscan] Body: {flow.request.content}")
    
    # Envoyer via ZMQ au lieu d'écrire dans un fichier
    if socket:
        try:
            socket.send_json(entry)
            print(f"[logscan] Envoyé à injector: {flow.request.pretty_url}")
        except Exception as e:
            print(f"[logscan] Erreur ZMQ: {e}")
            # Fallback sur fichier si problème
            with open("reco/proxy_scans.jsonl", "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    else:
        # Fallback sur fichier si pas de socket
        with open("reco/proxy_scans.jsonl", "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

# La fonction response() a été supprimée car elle n'est plus nécessaire en streaming
