#!/usr/bin/env python3
#!/usr/bin/env python3
import argparse
import subprocess
import sys
import time
import atexit
from pathlib import Path
import os
import signal
import zmq
import multiprocessing

def kill_process_on_port(port):
    import subprocess
    try:
        out = subprocess.check_output(["lsof", "-t", f"-i:{port}"])
        pids = set(int(pid) for pid in out.decode().split())
        for pid in pids:
            os.kill(pid, signal.SIGKILL)
    except Exception:
        pass

def run_step(cmd: list[str], name: str):
    print(f"[+] Lancement de {name}: {' '.join(str(c) for c in cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur durant l'étape {name} (code {e.returncode}).", file=sys.stderr)
        sys.exit(e.returncode)

def check_components_activity():
    """Vérifie si injector/analyzer traitent encore des messages"""
    context = zmq.Context()
    
    # Socket pour monitorer l'activité
    monitor = context.socket(zmq.SUB)
    monitor.connect("tcp://localhost:5557")  # Port de monitoring (analyzer)
    monitor.setsockopt_string(zmq.SUBSCRIBE, "")
    
    # Socket pour vérifier la queue d'injection
    queue_check = context.socket(zmq.REQ)
    queue_check.connect("tcp://localhost:5558")  # Port pour status de l'injector
    
    # Créer un poller pour les deux sockets
    poller = zmq.Poller()
    poller.register(monitor, zmq.POLLIN)
    poller.register(queue_check, zmq.POLLIN)
    
    try:
        # Vérifier heartbeat de l'analyzer
        socks = dict(poller.poll(1000))  # 1 seconde timeout
        if monitor in socks:
            monitor.recv_string()
            return True
            
        # Vérifier si des messages sont en attente dans l'injector
        try:
            queue_check.send_string("STATUS")
            if queue_check in socks:
                status = queue_check.recv_json()
                return status.get("pending", 0) > 0
        except zmq.error.ZMQError:
            # Si l'injector n'est pas prêt à répondre, on considère qu'il n'y a pas d'activité
            pass
            
        return False
    except Exception as e:
        print(f"[!] Erreur lors de la vérification d'activité: {str(e)}")
        return False
    finally:
        monitor.close()
        queue_check.close()
        context.term()

def main():
    parser = argparse.ArgumentParser(
        description="Orchestre le scan complet : reconnaissance → injection → analyse"
    )
    # Fichiers d'entrée / sortie
    parser.add_argument("--urls", default="urls.txt", help="Liste d'URLs à scanner")
    parser.add_argument("--payloads", default="payloads", help="Répertoire des payloads")
    parser.add_argument("--stack-out", default="reco/stack.json", help="Fichier JSON de stack techno")
    parser.add_argument("--raw-results", default="results/results_raw.jsonl",
                        help="Fichier JSONL brut généré par l'injecteur")
    parser.add_argument("--interesting-out", default="results/results_filtered.jsonl",
                        help="JSONL des résultats intéressants")
    parser.add_argument("--uninteresting-out", default="results/results_uninteresting.jsonl",
                        help="JSONL des résultats non-intéressants")
    # Paramètres d'injection
    parser.add_argument("--timeout", type=int, default=15, help="Timeout HTTP (sec)")
    parser.add_argument("--user-agent", default="ScannerBot/1.0", help="User-Agent par défaut")
    parser.add_argument("--user-agents", default=None, help="Fichier avec une liste de user-agents à utiliser (rotation)")
    parser.add_argument("--proxy", default=None, help="Proxy HTTP(S) (ex. http://127.0.0.1:8080)")
    parser.add_argument("--json-injection", action="store_true", help="Activer l'injection JSON")
    parser.add_argument("--headers-injection", nargs="*", default=[], help="Liste d'en-têtes à injecter")

    # Paramètres d'analyse
    parser.add_argument("--latency-factor", type=float, default=2.0, help="Facteur pour le seuil de latence")
    parser.add_argument("--watch-status", nargs="*", type=int,
                        default=[500, 501, 502, 503, 504, 403],
                        help="Codes HTTP à surveiller")

    args = parser.parse_args()

    # Crée le répertoire results/ si besoin
    Path(args.raw_results).parent.mkdir(parents=True, exist_ok=True)

    # 1) RECONNAISSANCE
    run_step([
        sys.executable, "reco.py", args.urls
    ], name="reco.py")

    # 2) LANCER LES COMPOSANTS STREAMING
    # Lancer analyzer en arrière-plan
    analyzer_proc = subprocess.Popen([
        sys.executable, "analyzer.py",
        "--streaming"
    ])
    
    # Lancer injector en arrière-plan
    injector_proc = subprocess.Popen([
        sys.executable, "injector.py",
        "--payloads", args.payloads,
        "--timeout", str(args.timeout),
        "--oast",
        "--user-agents", args.user_agents or "useragents.txt",
    ])
    
    # Attendre que les sockets soient prêts
    time.sleep(5)
    
    # 3) LANCER MITMPROXY + BOT
    kill_process_on_port(8080)
    try:
        os.remove("reco/proxy_scans.jsonl")
    except Exception:
        pass
        
    mitmproxy_cmd = [
        "mitmdump",
        "-s", "logscan.py"
    ]
    mitmproxy_proc = subprocess.Popen(mitmproxy_cmd)
    
    # Attendre que mitmproxy soit prêt
    time.sleep(3)

    # Lancer le crawling avec bot (UNE SEULE FOIS)
    with open(args.urls, "r") as fin:
        for url in fin:
            url = url.strip()
            if not url: continue
            bot_cmd = [
                sys.executable, "bot.py",
                "--start-url", url,
                "--user-agents", args.user_agents or "useragents.txt",
                "--depth", "0",
                "--proxy", "http://127.0.0.1:8080"
            ]
            run_step(bot_cmd, name=f"bot.py ({url})")
    
    # Attendre que l'injection commence
    print("[*] Attente que l'injection commence...")
    time.sleep(10)  # Laisser le temps à l'injector de démarrer
    
    # Attendre un peu pour que tout soit traité
    print("[*] Attente de la fin du traitement...")

    # Attendre que les composants finissent
    last_activity = time.time()
    while True:
        # Vérifier si les processus sont vivants
        if injector_proc.poll() is not None and analyzer_proc.poll() is not None:
            print("[!] Composants à l'arrêt")
            break
            
        # Vérifier s'il y a de l'activité
        if check_components_activity():
            last_activity = time.time()
            print(".", end="", flush=True)
        else:
            # Pas d'activité depuis X secondes
            if time.time() - last_activity > 120:  # 120 secondes de timeout
                print("\n[+] Plus d'activité détectée depuis 120s, fin du traitement")
                break
                
        time.sleep(1)
    
    # Terminer proprement
    print("\n[*] Arrêt des composants...")
    
    # 1. Terminer gracieusement
    mitmproxy_proc.terminate()
    injector_proc.terminate()
    analyzer_proc.terminate()
    
    # 2. Attendre un peu
    time.sleep(2)
    
    # 3. Forcer l'arrêt si nécessaire
    if mitmproxy_proc.poll() is None:
        print("[!] Force l'arrêt de mitmproxy")
        mitmproxy_proc.kill()
    
    if injector_proc.poll() is None:
        print("[!] Force l'arrêt de l'injector")
        injector_proc.kill()
        
    if analyzer_proc.poll() is None:
        print("[!] Force l'arrêt de l'analyzer")
        analyzer_proc.kill()
    
    # 4. Attendre la fin définitive
    mitmproxy_proc.wait()
    injector_proc.wait()
    analyzer_proc.wait()
    
    # 5. Nettoyer les ports
    kill_process_on_port(8080)
    kill_process_on_port(5555)
    kill_process_on_port(5556)
    kill_process_on_port(5557)
    
    # 6. Attendre que les fichiers soient bien écrits
    time.sleep(1)
    
    # 7. Afficher les résultats finaux
    results_dir = Path("results")
    interesting_file = results_dir / "results_filtered.jsonl"
    
    interesting_count = 0
    
    if interesting_file.exists():
        with open(interesting_file, 'r') as f:
            interesting_count = sum(1 for _ in f)
    
    print("\n" + "="*50)
    print("[✔] Pipeline terminé avec succès !")
    print(f"[✔] Résultats intéressants: {interesting_count}")
    print(f"[✔] Fichier sauvegardé dans: {results_dir}")
    print("="*50)
    
    # 8. Forcer la sortie du programme
    sys.exit(0)

if __name__ == "__main__":
    main()
