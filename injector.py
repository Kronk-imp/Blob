import argparse
import json
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import random
import time
import sys
import zmq
import threading
from collections import deque
from datetime import datetime, timezone
from vector_filter import VectorFilter, FilterStats

# Si tu utilises mutator.py, importe-le ici
from mutator import mutate

# --- HTTP header hygiene (hop-by-hop removal) ---
HOP_BY_HOP = {
    "proxy-connection", "connection", "keep-alive", "te",
    "trailer", "transfer-encoding", "upgrade", "content-length"
}

def sanitize_headers(headers: dict) -> dict:
    """Return a copy of headers without hop-by-hop / Content-Length."""
    clean = {}
    if not headers:
        return clean
    for k, v in headers.items():
        if not k:
            continue
        if k.lower().strip() in HOP_BY_HOP:
            continue
        clean[k] = v
    # never set Content-Length manually; let 'requests' handle it
    clean.pop("Content-Length", None)
    clean.pop("content-length", None)
    return clean


# Si tu utilises OAST/Interactsh
try:
    from interactsh import InteractshSession,random_string
except ImportError:
    InteractshSession = None
    print("[!] interactsh.py (justinsteven) n'est pas trouvé. OAST désactivé.")
# --- OASTManager pour Interactsh (justinsteven) ---
class OASTManager:
    def __init__(self):
        if InteractshSession is None:
            raise RuntimeError("InteractshSession (justinsteven) n'est pas installé.")
        self.sessions = []
        self.mapping = {}  # {oast_domain: info injection}
        self.domain_session = {}  # {oast_domain: InteractshSession}

    def generate_oast_domain(self, info=None):
        # PATCH: ignorer l'erreur SSL pour oast.fun expiré, ou mets verify=False dans interactsh.py
        session = InteractshSession.new(server_hostname="oast.fun")
        self.sessions.append(session)
        domain = session.generate_hostname()
        if info:
            self.mapping[domain] = info
        self.domain_session[domain] = session
        return domain

    def replace_in_payloads(self, payloads, info=None):
        return [p.replace("OAST_DOMAIN", self.generate_oast_domain(info)) if "OAST_DOMAIN" in p else p for p in payloads]

    def fetch_events(self):
        for session in self.sessions:
            for event in session.poll():
                domain = session.generate_hostname()
                info = self.mapping.get(domain)
                yield {'event': event, 'info': info, 'oast_url': domain}

DEFAULT_TIMEOUT = 15

def load_stack_file(stack_file="reco/stack.json"):
    """Charge la stack reco (url → [engines])"""
    try:
        with open(stack_file, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Impossible de charger stack.json: {e}")
        return {}

def load_user_agents(user_agents_file):
    with open(user_agents_file, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def is_blocked(info):
    # Customise selon ton infra (code 403, texte, etc.)
    return (info.get('status_code') in (403, 406, 429, 503)) or "access denied" in (info.get("response_snippet", "")).lower()

class PayloadLoader:
    def __init__(self, payload_dir):
        self.payload_dir = Path(payload_dir)

    def list_vectors(self):
        # Trouve TOUS les *.txt à TOUTE profondeur, unique sur le nom de vector
        vectors = set()
        for f in self.payload_dir.rglob("*.txt"):
            # On prend le chemin relatif à payload_dir pour gérer "sqli/generic/elite.txt"
            parts = f.relative_to(self.payload_dir).parts
            # Le vector = premier sous-répertoire ou le nom du fichier sans extension
            # Ex: payloads/sqli/generic/elite.txt --> "sqli"
            if len(parts) > 1:
                vectors.add(parts[0])
            else:
                vectors.add(f.stem)
        return list(vectors)

    def get_payload_file(self, vector, engine="generic"):
        # Cherche d'abord payloads/vector/engine/elite.txt
        candidates = list((self.payload_dir / vector / engine).glob("*.txt"))
        if candidates:
            return candidates[0]  # ex: payloads/sqli/generic/elite.txt
        # Sinon cherche payloads/vector/*.txt (payload générique pour le vector)
        candidates = list((self.payload_dir / vector).glob("*.txt"))
        if candidates:
            return candidates[0]
        # Sinon cherche payloads/vector.txt à la racine
        f = self.payload_dir / (vector + ".txt")
        if f.exists():
            return f
        # Sinon rien
        return None

    def load_payloads(self, file):
        with open(file, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]

class StreamingInjector():
    def _maybe_attach_oast(self, result: dict, payload: str) -> dict:
        try:
            if getattr(self, 'oast_manager', None) is None or not payload:
                return result
            m = re.search(r"\b([A-Za-z0-9.-]+\.oast\.fun)\b", str(payload))
            if not m:
                return result
            host = m.group(1)
            session = getattr(self.oast_manager, 'domain_session', {}).get(host)
            if session:
                result['oast_probe'] = True
                result['oast_host'] = host
                try:
                    result['oast_session'] = session.to_dict()
                except Exception:
                    pass
        finally:
            return result

    def __init__(self, payload_dir, timeout, user_agents_file, use_oast=False, stack_file="reco/stack.json"):
        # Initialiser TOUS les attributs nécessaires
        self.loader = PayloadLoader(payload_dir)
        self.timeout = timeout
        self.user_agents = load_user_agents(user_agents_file)
        self.use_oast = use_oast
        self.oast_manager = OASTManager() if (use_oast and InteractshSession is not None) else None
        self.stack_map = load_stack_file(stack_file)
        
        # ZMQ setup
        self.context = zmq.Context()
        self.receiver = self.context.socket(zmq.PULL)
        self.receiver.bind("tcp://*:5555")
        self.sender = self.context.socket(zmq.PUSH)
        self.sender.connect("tcp://localhost:5556")
        # STATUS REP socket on 5558
        self.status_rep = self.context.socket(zmq.REP)
        try:
            self.status_rep.bind("tcp://*:5558")
            print("[injector] STATUS REP bound on 5558")
        except Exception as e:
             print(f"[injector] STATUS REP bind failed: {e}")
        # metrics
        self.in_flight = 0
        self.done = 0
        self.errors = 0
        self._sent_ts = deque(maxlen=10000)
        # status loop thread
        self._status_thread = threading.Thread(target=self._status_loop, daemon=True)
        self._status_thread.start()
        self.heartbeat = self.context.socket(zmq.PUB)
        self.heartbeat.connect("tcp://localhost:5557")
        
        # Cache et stats
        self.tested_combinations = set()
        self.tested_combinations_limit = 50000
        self.tested_combinations_cleanup_threshold = 45000
        self.running = True
        self.last_message_time = time.time()
        self.pending_count = 0
        self.IDLE_TIMEOUT = 120
        self.stats = {'processed': 0, 'sent': 0}
        self.vector_filter = VectorFilter()
        self.filter_stats = FilterStats()

    def _status_loop(self):
        while True:
            try:
                if self.status_rep.poll(500):
                    try:
                        msg = self.status_rep.recv_json(flags=0)
                    except Exception:
                        try:
                            msg = self.status_rep.recv_string(flags=0)
                        except Exception:
                            msg = "STATUS"
                    if isinstance(msg, dict):
                        cmd = str(msg.get("cmd", "STATUS")).upper()
                    else:
                        cmd = str(msg).upper()
                    if "STATUS" in cmd:
                        now = time.time()
                        # calc rate in last 60s
                        cutoff = now - 60
                        rate = sum(1 for t in self._sent_ts if t >= cutoff)
                        payload = {
                            "ok": True,
                            "pending": max(self.pending_count - self.stats.get("processed",0), 0),
                            "in_flight": self.in_flight,
                            "done": self.stats.get("processed",0),
                            "sent": self.stats.get("sent",0),
                            "errors": self.errors,
                            "rate_last_min": rate,
                            "last_tick": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
                        }
                        self.status_rep.send_json(payload)
                    elif "PING" in cmd:
                        self.status_rep.send_json({"ok": True, "pong": True})
                    else:
                        self.status_rep.send_json({"ok": False, "error": "unknown cmd"})
            except Exception as e:
                try:
                    self.status_rep.send_json({"ok": False, "error": str(e)})
                except Exception:
                    pass

    def _send(self, method, url, params=None, data=None, json_body=None, headers=None, cookies=None):
        # DEBUG : Afficher exactement ce qui est envoyé
        print(f"[injector] === Envoi requête ===")
        print(f"[injector] URL: {url}")
        print(f"[injector] Method: {method}")
        if params:
            print(f"[injector] Params GET: {params}")
        if data:
            print(f"[injector] Data POST: {data}")
        if json_body:
            print(f"[injector] JSON: {json_body}")
        if headers:
            print(f"[injector] Headers: {headers}")
        if cookies:
            print(f"[injector] Cookies: {cookies}")
        print(f"[injector] ===================\n")

        try:
            ua = random.choice(self.user_agents)
            # Sanitize incoming headers and ensure UA
            headers = sanitize_headers(headers.copy() if headers else {})
            headers['User-Agent'] = ua

            # Decide transport: json vs form (never force Content-Length)
            req_kwargs = {}
            if json_body is not None:
                req_kwargs['json'] = json_body
                headers['Content-Type'] = 'application/json'
            elif data is not None:
                req_kwargs['data'] = data
                if isinstance(data, dict):
                    headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')

            resp = requests.request(
                method, url,
                params=params,
                headers=headers, cookies=cookies,
                timeout=self.timeout, verify=False,
                **req_kwargs
            )
            snippet = (resp.text or '').replace('\n', ' ')[:200]
            return dict(
                status_code=resp.status_code,
                response_time=resp.elapsed.total_seconds(),
                content_length=len(resp.content),
                response_snippet=snippet,
                headers=dict(resp.headers),
                error=None,
                method=method,
                request_headers=headers,
                request_body=json_body if json_body is not None else data,
                request_cookies=cookies,
                request_params=params,
            )
        except Exception as e:
            return dict(
                status_code=None,
                response_time=0,
                content_length=0,
                response_snippet='',
                headers={},
                error=str(e),
                method=method,
                request_headers=sanitize_headers(headers.copy() if headers else {}),
                request_body=json_body if json_body is not None else data,
                request_cookies=cookies,
                request_params=params,
            )

    def _send_with_bypass(self, method, url, params=None, data=None, json_body=None, 
                         headers=None, cookies=None, apply_bypass=False):
        """Version étendue de _send avec techniques de bypass WAf"""
        
        # Si pas de bypass demandé, utiliser la méthode normale
        if not apply_bypass:
            return self._send(method, url, params, data, json_body, headers, cookies)
        
        print(f"[injector] === Tentative avec bypass WAF ===")
        
        # Copier les headers
        headers = headers.copy() if headers else {}
        
        # 4. Headers additionnels de bypass
        bypass_headers = {
            "X-Originating-IP": "127.0.0.1",
            "X-Forwarded-For": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Remote-Addr": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Forwarded-Host": "localhost",
            "X-Original-URL": url,
            "X-Rewrite-URL": url,
        }
        
        # Ajouter aléatoirement quelques headers
        for h, v in bypass_headers.items():
            if random.random() > 0.7:  # 30% de chance
                headers[h] = v
        
        # Envoyer la requête modifiée
        return self._send(method, url, params, data, json_body, headers, cookies)

    def run_streaming(self):
        print("[+] Streaming Injector démarré")
        print("[+] En écoute sur port 5555, envoi vers port 5556")
        
        while self.running:
            try:
                # Recevoir une requête avec timeout
                if self.receiver.poll(1000):  # 1 seconde timeout
                    entry = self.receiver.recv_json()
                    self.last_message_time = time.time()
                    
                    # Traiter la requête de manière synchrone
                    self._process_entry_streaming(entry)
                    
                    # Envoyer un heartbeat
                    self.heartbeat.send_string("heartbeat")
                    
                # Auto-arrêt si inactif
                if time.time() - self.last_message_time > self.IDLE_TIMEOUT:
                    print(f"[...] Aucun message depuis {self.IDLE_TIMEOUT}s, arrêt...")
                    break
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Erreur streaming: {e}")
                
        self.cleanup()

    def _process_entry_streaming(self, entry):
        """Traite une entrée avec filtrage intelligent"""
        # Nettoyer le cache si trop grand
        if len(self.tested_combinations) > self.tested_combinations_cleanup_threshold:
            # Garder seulement les 30% plus récents
            to_keep = int(self.tested_combinations_limit * 0.3)
            self.tested_combinations = set(list(self.tested_combinations)[-to_keep:])
            print(f"[injector] Nettoyage cache: {len(self.tested_combinations)} entrées conservées")
        
        url = entry.get("url")
        method = entry.get("method", "GET")
        headers = entry.get("request_headers") or {}
        cookies = entry.get("request_cookies") or {}
        params = entry.get("request_params") or {}
        data = entry.get("request_body") or {}
        json_body = None
        content_type = headers.get("Content-Type", "") or headers.get("content-type", "")
        if isinstance(data, str) and data.strip().startswith('{'):
            try:
                data = json.loads(data)
            except:
                pass
        if content_type.startswith("application/json"):
            if isinstance(data, dict):
                json_body = data
                data = None
            elif isinstance(data, str):
                try:
                    json_body = json.loads(data)
                    data = None
                except:
                    pass
        elif "multipart/form-data" in content_type:
            if isinstance(data, str):
                multipart_params = {}
                parts = data.split('------')
                for part in parts:
                    if 'Content-Disposition: form-data' in part:
                        lines = part.split('\\n')
                        name = None
                        value = None
                        for i, line in enumerate(lines):
                            if 'name="' in line:
                                name = line.split('name="')[1].split('"')[0]
                            elif line.strip() == '' and i+1 < len(lines):
                                value = '\\n'.join(lines[i+1:]).strip()
                                break
                        if name and value:
                            multipart_params[name] = value
                if multipart_params:
                    data = multipart_params
        print(f"\\n[injector] === Nouvelle requête reçue ===")
        print(f"[injector] URL: {url}")
        print(f"[injector] Method: {method}")
        print(f"[injector] Params GET: {params}")
        print(f"[injector] Body: {data}")
        print(f"[injector] Type du body: {type(data)}")
        print(f"[injector] Content-Type: {content_type}")
        if json_body:
            print(f"[injector] JSON Body: {json_body}")
            print(f"[injector] Type du JSON body: {type(json_body)}")
        print(f"[injector] Headers: {headers}")
        print(f"[injector] Cookies: {cookies}")
        print(f"[injector] ============================\\n")
        all_params = {}
        if params: all_params.update(params)
        if data: all_params.update(data)
        if json_body: all_params.update(json_body)
        if not all_params and method == "POST":
            print(f"[injector] POST sans paramètres pour {url}, ajout de paramètres de test")
            all_params = {"test": "1", "id": "1", "action": "test", "data": "test"}
        if not all_params and not headers and not cookies:
            print(f"[injector] Aucun point d'injection pour {url}")
            return
        # NOUVEAU: Vérifier si l'endpoint vaut la peine d'être testé
        if not self.vector_filter.should_test_endpoint(url, method):
            print(f"[injector] Skip endpoint statique: {url}")
            self.filter_stats.record_skip()
            return
        # Remplacer la boucle des vecteurs par:
        all_vectors = self.loader.list_vectors()
        # NOUVEAU: Pré-filtrer les vecteurs pour les params
        param_vectors = []
        if all_params:
            dummy_point = f"{method} param"
            param_vectors = self.vector_filter.filter_vectors(
                url, dummy_point, all_vectors, content_type
            )
            print(f"[injector] Vecteurs pour params: {param_vectors} (sur {len(all_vectors)})")
            self.filter_stats.record_filtering(len(all_vectors), len(param_vectors))
        # Tester uniquement les vecteurs filtrés pour les params
        for vector in param_vectors:
            print(f"[injector] Test vector: {vector} sur {url}")
            self.heartbeat.send_string("heartbeat")
            engine_candidates = self.stack_map.get(url, []) + ["generic"]
            found = False
            for engine in engine_candidates:
                file = self.loader.get_payload_file(vector, engine)
                if not file:
                    continue
                payloads = self.loader.load_payloads(file)
                if not payloads:
                    continue
                if self.oast_manager is not None:
                    payloads = self.oast_manager.replace_in_payloads(payloads, info={
                        'url': url, 'method': method, 'headers': headers, 'params': params, 'data': data, 'json': json_body
                    })
                print(f"[injector] Test engine: {engine} avec {len(payloads)} payloads")
                self.heartbeat.send_string("heartbeat")
                for param in all_params:
                    for payload in payloads:
                        combination = f"{vector}:{engine}:{param}:{payload}"
                        if combination in self.tested_combinations:
                            continue
                        self.tested_combinations.add(combination)
                        print(f"[injector] Test payload: {payload} sur {param}")
                        if payloads.index(payload) % 5 == 0:
                            self.heartbeat.send_string("heartbeat")
                        new_params = params.copy() if params else None
                        new_data = data.copy() if data else None
                        new_json = json_body.copy() if json_body else None
                        if new_params and param in new_params:
                            new_params[param] = payload
                        if new_data and param in new_data:
                            new_data[param] = payload
                        if new_json and param in new_json:
                            new_json[param] = payload
                        info = self._send(
                            method, url,
                            params=new_params, data=new_data, json_body=new_json,
                            headers=headers, cookies=cookies
                        )
                        self.last_message_time = time.time()
                        self.heartbeat.send_string("heartbeat")
                        print(f"[injector] Réponse: {info.get('status_code')} - {info.get('response_snippet')}")
                        result = {
                            "url": url, "vector": vector, "engine": engine,
                            "injection_point": f"log-proxy param `{param}`", "payload": payload,
                            **info
                        }
                        result = self._maybe_attach_oast(result, payload)
                        self.sender.send_json(result)
                        self.stats['sent'] += 1
                        try:
                            self._sent_ts.append(time.time())
                        except Exception:
                            pass
                        if is_blocked(info):
                            print(f"[injector] Blocage détecté, tentative avec bypass WAf")
    
                            # Variables pour éviter la confusion
                            injection_point = f"log-proxy param `{param}`"
                            bypass_success = False
    
                            # Tentatives de bypass
                            for bypass_attempt in range(3):
                                # Préparer les paramètres pour le bypass
                                bypass_params = new_params.copy() if new_params else None
                                bypass_data = new_data.copy() if new_data else None
                                bypass_json = new_json.copy() if new_json else None
        
                                # Réinjecter le payload original
                                if bypass_params and param in bypass_params:
                                    bypass_params[param] = payload
                                if bypass_data and param in bypass_data:
                                    bypass_data[param] = payload
                                if bypass_json and param in bypass_json:
                                    bypass_json[param] = payload
        
                                # Tenter avec bypass
                                info_bypass = self._send_with_bypass(
                                    method, url,
                                    params=bypass_params, data=bypass_data, json_body=bypass_json,
                                    headers=headers, cookies=cookies,
                                    apply_bypass=True
                                )
        
                                # Si le bypass fonctionne
                                if not is_blocked(info_bypass):
                                    print(f"[injector] ✓ Bypass WAF réussi !")
                                    result_bypass = {
                                        "url": url, "vector": vector, "engine": engine,
                                        "injection_point": f"[BYPASS] {injection_point}", 
                                        "payload": payload,
                                        **info_bypass
                                    }
                                    self.sender.send_json(result_bypass)  # Pas self._log !
                                    self.stats['sent'] += 1
                                    try:
                                        self._sent_ts.append(time.time())
                                    except Exception:
                                        pass
                                    bypass_success = True
                                    break
                                else:
                                    print(f"[injector] Bypass attempt {bypass_attempt + 1} failed")
    
                                # Mutations seulement si bypass échoue
                            if not bypass_success:
                                for mutated in mutate(payload, context="param", family=vector):
                                    mutation_combination = f"{vector}:{engine}:{param}:{mutated}"
                                    if mutation_combination in self.tested_combinations:
                                        continue
                                    self.tested_combinations.add(mutation_combination)
                                    if new_params and param in new_params:
                                        new_params[param] = mutated
                                    if new_data and param in new_data:
                                        new_data[param] = mutated
                                    if new_json and param in new_json:
                                        new_json[param] = mutated
                                    info2 = self._send(
                                        method, url,
                                        params=new_params, data=new_data, json_body=new_json,
                                        headers=headers, cookies=cookies
                                    )
                                    self.last_message_time = time.time()
                                    self.heartbeat.send_string("heartbeat")
                                    result2 = {
                                        "url": url, "vector": vector, "engine": engine,
                                        "injection_point": f"[MUT] log-proxy param `{param}`", "payload": mutated,
                                        **info2
                                    }
                                    self.sender.send_json(result2)
                                    self.stats['sent'] += 1
                                    try:
                                        self._sent_ts.append(time.time())
                                    except Exception:
                                        pass
                    found = True
            if not found:
                file = self.loader.get_payload_file(vector)
                if file:
                    payloads = self.loader.load_payloads(file)
                    if self.oast_manager is not None:
                        payloads = self.oast_manager.replace_in_payloads(payloads, info={
                            'url': url, 'method': method, 'headers': headers, 'params': params, 'data': data, 'json': json_body
                        })
                    for param in all_params:
                        for payload in payloads:
                            combination = f"{vector}:root:{param}:{payload}"
                            if combination in self.tested_combinations:
                                continue
                            self.tested_combinations.add(combination)
                            if payloads.index(payload) % 5 == 0:
                                self.heartbeat.send_string("heartbeat")
                            new_params = params.copy() if params else None
                            new_data = data.copy() if data else None
                            new_json = json_body.copy() if json_body else None
                            if new_params and param in new_params:
                                new_params[param] = payload
                            if new_data and param in new_data:
                                new_data[param] = payload
                            if new_json and param in new_json:
                                new_json[param] = payload
                            info = self._send(
                                method, url,
                                params=new_params, data=new_data, json_body=new_json,
                                headers=headers, cookies=cookies
                            )
                            self.last_message_time = time.time()
                            self.heartbeat.send_string("heartbeat")
                            result = {
                                "url": url, "vector": vector, "engine": "root",
                                "injection_point": f"log-proxy param `{param}`", "payload": payload,
                                **info
                            }
                            result = self._maybe_attach_oast(result, payload)
                            self.sender.send_json(result)
                            self.stats['sent'] += 1
                            try:
                                self._sent_ts.append(time.time())
                            except Exception:
                                pass
        # NOUVEAU: Filtrage pour les headers
        for hdr, val in headers.items():
            if hdr.lower() in ("host", "content-length", "connection"):
                continue
            injection_point = f"header `{hdr}`"
            header_vectors = self.vector_filter.filter_vectors(
                url, injection_point, all_vectors, content_type
            )
            if not header_vectors:
                print(f"[injector] Skip header {hdr} - aucun vecteur pertinent")
                continue
            print(f"[injector] Vecteurs pour {hdr}: {header_vectors}")
            self.filter_stats.record_filtering(len(all_vectors), len(header_vectors))
            for vector in header_vectors:
                self.heartbeat.send_string("heartbeat")
                engine_candidates = self.stack_map.get(url, []) + ["generic"]
                for engine in engine_candidates:
                    file = self.loader.get_payload_file(vector, engine)
                    if not file:
                        continue
                    payloads = self.loader.load_payloads(file)
                    if not payloads:
                        continue
                    if self.oast_manager is not None:
                        payloads = self.oast_manager.replace_in_payloads(payloads, info={
                            'url': url, 'method': method, 'headers': headers, 'params': params, 'data': data, 'json': json_body
                        })
                    for payload in payloads:
                        combination = f"{vector}:{engine}:header:{hdr}:{payload}"
                        if combination in self.tested_combinations:
                            continue
                        self.tested_combinations.add(combination)
                        if payloads.index(payload) % 5 == 0:
                            self.heartbeat.send_string("heartbeat")
                        new_headers = headers.copy()
                        new_headers[hdr] = payload
                        info = self._send(
                            method, url,
                            params=params, data=data, json_body=json_body,
                            headers=new_headers, cookies=cookies
                        )
                        self.last_message_time = time.time()
                        self.heartbeat.send_string("heartbeat")
                        result = {
                            "url": url, "vector": vector, "engine": engine,
                            "injection_point": f"log-proxy header `{hdr}`", "payload": payload,
                            **info
                        }
                        result = self._maybe_attach_oast(result, payload)
                        self.sender.send_json(result)
                        self.stats['sent'] += 1
                        try:
                            self._sent_ts.append(time.time())
                        except Exception:
                            pass
                        if is_blocked(info):
                            for mutated in mutate(payload, context="header", family=vector):
                                mutation_combination = f"{vector}:{engine}:header:{hdr}:{mutated}"
                                if mutation_combination in self.tested_combinations:
                                    continue
                                self.tested_combinations.add(mutation_combination)
                                new_headers2 = new_headers.copy()
                                new_headers2[hdr] = mutated
                                info2 = self._send(
                                    method, url,
                                    params=params, data=data, json_body=json_body,
                                    headers=new_headers2, cookies=cookies
                                )
                                self.last_message_time = time.time()
                                self.heartbeat.send_string("heartbeat")
                                result2 = {
                                    "url": url, "vector": vector, "engine": engine,
                                    "injection_point": f"[MUT] log-proxy header `{hdr}`", "payload": mutated,
                                    **info2
                                }
                                self.sender.send_json(result2)
                                self.stats['sent'] += 1
                                try:
                                    self._sent_ts.append(time.time())
                                except Exception:
                                    pass
        # NOUVEAU: Filtrage pour les cookies
        for ck, val in cookies.items():
            injection_point = f"cookie `{ck}`"
            cookie_vectors = self.vector_filter.filter_vectors(
                url, injection_point, all_vectors, content_type
            )
            if not cookie_vectors:
                print(f"[injector] Skip cookie {ck} - aucun vecteur pertinent")
                continue
            print(f"[injector] Vecteurs pour cookie {ck}: {cookie_vectors}")
            self.filter_stats.record_filtering(len(all_vectors), len(cookie_vectors))
            for vector in cookie_vectors:
                self.heartbeat.send_string("heartbeat")
                engine_candidates = self.stack_map.get(url, []) + ["generic"]
                for engine in engine_candidates:
                    file = self.loader.get_payload_file(vector, engine)
                    if not file:
                        continue
                    payloads = self.loader.load_payloads(file)
                    if not payloads:
                        continue
                    if self.oast_manager is not None:
                        payloads = self.oast_manager.replace_in_payloads(payloads, info={
                            'url': url, 'method': method, 'headers': headers, 'params': params, 'data': data, 'json': json_body
                        })
                    for payload in payloads:
                        combination = f"{vector}:{engine}:cookie:{ck}:{payload}"
                        if combination in self.tested_combinations:
                            continue
                        self.tested_combinations.add(combination)
                        if payloads.index(payload) % 5 == 0:
                            self.heartbeat.send_string("heartbeat")
                        new_cookies = cookies.copy()
                        new_cookies[ck] = payload
                        info = self._send(
                            method, url,
                            params=params, data=data, json_body=json_body,
                            headers=headers, cookies=new_cookies
                        )
                        self.last_message_time = time.time()
                        self.heartbeat.send_string("heartbeat")
                        result = {
                            "url": url, "vector": vector, "engine": engine,
                            "injection_point": f"log-proxy cookie `{ck}`", "payload": payload,
                            **info
                        }
                        result = self._maybe_attach_oast(result, payload)
                        self.sender.send_json(result)
                        self.stats['sent'] += 1
                        try:
                            self._sent_ts.append(time.time())
                        except Exception:
                            pass
                        if is_blocked(info):
                            for mutated in mutate(payload, context="cookie", family=vector):
                                mutation_combination = f"{vector}:{engine}:cookie:{ck}:{mutated}"
                                if mutation_combination in self.tested_combinations:
                                    continue
                                self.tested_combinations.add(mutation_combination)
                                new_cookies2 = new_cookies.copy()
                                new_cookies2[ck] = mutated
                                info2 = self._send(
                                    method, url,
                                    params=params, data=data, json_body=json_body,
                                    headers=headers, cookies=new_cookies2
                                )
                                self.last_message_time = time.time()
                                self.heartbeat.send_string("heartbeat")
                                result2 = {
                                    "url": url, "vector": vector, "engine": engine,
                                    "injection_point": f"[MUT] log-proxy cookie `{ck}`", "payload": mutated,
                                    **info2
                                }
                                self.sender.send_json(result2)
                                self.stats['sent'] += 1
                                try:
                                    self._sent_ts.append(time.time())
                                except Exception:
                                    pass
                
        self.stats['processed'] += 1
        if self.stats['processed'] % 100 == 0:
            print(f"[*] Injector - Traité: {self.stats['processed']}, Envoyé: {self.stats['sent']}")

    def cleanup(self):
        """Méthode cleanup dans StreamingInjector"""
        self.running = False
        if hasattr(self, 'receiver'):
            self.receiver.close()
        if hasattr(self, 'sender'):
            self.sender.close()
        if hasattr(self, 'heartbeat'):
            self.heartbeat.close()
        if hasattr(self, 'context'):
            self.context.term()
        if hasattr(self, 'filter_stats'):
            self.filter_stats.print_stats()

def main():
    parser = argparse.ArgumentParser(description="Injector en mode streaming")
    parser.add_argument("--payloads", required=True, help="Répertoire des payloads (un .txt par vecteur)")
    parser.add_argument("--threads", type=int, default=10, help="Nb de threads")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout HTTP")
    parser.add_argument("--user-agents", required=True, help="Fichier user-agents.txt")
    parser.add_argument("--oast", action="store_true", help="Active l'OAST/Interactsh si disponible")
    args = parser.parse_args()
    
    # Mode streaming
    injector = StreamingInjector(
        args.payloads, 
        args.timeout, 
        args.user_agents,
        use_oast=args.oast
    )
    injector.run_streaming()

if __name__ == "__main__":
    main()
