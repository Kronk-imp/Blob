#!/usr/bin/env python3
'''
Ultra-light tech reconnaissance script (patched for techM4 parity):
Scans URLs from a file (urls.txt) using WhatWeb, Webanalyze (Wappalyzer CLI) and Wafw00f,
normalizes technology names to slugs, validates against payloads/ directory,
and produces a stack.json mapping each URL → list of tech slugs (or "generic").
Keeps the original output format used by the home-made scanner.
'''

import sys
import os
import re
import json
import argparse
import logging
import subprocess
import tempfile
import unittest

# timeout for each scanner subprocess (seconds)
SCAN_TIMEOUT = 30

# set up logger to write detailed scan info to reco.log
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
os.makedirs('reco', exist_ok=True)
fh = logging.FileHandler('reco/reco.log')
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(fh)

# ------------- SLUGIFY (unchanged) -------------
SLUG_MAP = {
    # JS front
    "react": "react", "reactjs": "react", "react.js": "react",
    "vue": "vue", "vuejs": "vue", "vue.js": "vue",
    "angular": "angular", "angularjs": "angular", "angular.js": "angular",
    "ember": "ember", "emberjs": "ember", "ember.js": "ember",
    "backbone": "backbone", "backbonejs": "backbone", "backbone.js": "backbone",
    "jquery": "jquery", "jqueryui": "jquery", "jquery.ui": "jquery",
    # Frameworks python
    "django": "django", "flask": "flask", "fastapi": "fastapi", "bottle": "bottle", "pyramid": "pyramid", "tornado": "tornado",
    # NodeJS, Express, etc.
    "express": "express", "expressjs": "express", "express.js": "express",
    "nodejs": "nodejs", "node.js": "nodejs", "node": "nodejs",
    "koa": "koa", "koajs": "koa", "koa.js": "koa",
    "sails": "sails", "sailsjs": "sails", "sails.js": "sails",
    # Ruby, Rails
    "rails": "rails", "ruby on rails": "rails", "ror": "rails", "sinatra": "sinatra",
    # PHP
    "php": "php", "laravel": "laravel", "symfony": "symfony", "cakephp": "cakephp", "codeigniter": "codeigniter", "yii": "yii", "zend": "zend",
    # Java / JVM
    "spring": "spring", "springboot": "spring", "spring boot": "spring",
    "playframework": "play", "play": "play", "struts": "struts", "struts2": "struts",
    "jsp": "jsp", "servlet": "servlet",
    # .NET / C#
    "aspnet": "aspnet", "asp.net": "aspnet", "asp": "aspnet", ".net": "aspnet", "dotnet": "aspnet",
    "iis": "iis",
    # Databases
    "mysql": "mysql", "mariadb": "mysql", "postgresql": "postgres", "postgres": "postgres",
    "mongodb": "mongodb", "mongo": "mongodb",
    "mssql": "mssql", "sqlserver": "mssql", "sqlite": "sqlite", "oracle": "oracle",
    # Static sites
    "jekyll": "jekyll", "hugo": "hugo", "gatsby": "gatsby",
    # CMS
    "wordpress": "wordpress", "wp": "wordpress",
    "joomla": "joomla", "drupal": "drupal", "typo3": "typo3",
    "prestashop": "prestashop", "magento": "magento", "shopify": "shopify", "wix": "wix",
    # Servers / WAF / CDN
    "tomcat": "tomcat", "jboss": "jboss", "wildfly": "wildfly", "glassfish": "glassfish",
    "nginx": "nginx", "apache": "apache", "caddy": "caddy", "litespeed": "litespeed", "openresty": "nginx",
    "waf": "waf", "cloudflare": "cloudflare", "akamai": "akamai", "incapsula": "incapsula", "imperva": "imperva",
    # Fallback
    "generic": "generic"
}

PAYLOADS_ROOT = os.getenv("PAYLOADS_DIR", "payloads")
if os.path.isdir(PAYLOADS_ROOT):
    for name in os.listdir(PAYLOADS_ROOT):
        nslug = re.sub(r"[^a-z0-9]", "", name.lower())
        if nslug and nslug not in SLUG_MAP:
            SLUG_MAP[nslug] = nslug

def slugify_technology(tech):
    tech_l = tech.lower().replace(" ", "")
    tech_l = tech_l.replace("-", "").replace("_", "").replace(".", "")
    if tech_l in SLUG_MAP:
        return SLUG_MAP[tech_l]
    for k, v in SLUG_MAP.items():
        if tech_l.startswith(k):
            return v
    slug = re.sub(r"[^a-z0-9]", "", tech_l)
    if slug not in SLUG_MAP:
        print(f"[slugify_technology] ⚠️ Inconnu (ajoute-le dans SLUG_MAP !): {tech} → {slug}")
    return slug
# ------------- END SLUGIFY -------------

def load_urls(file_path):
    if not os.path.isfile(file_path):
        logger.error(f"URLs file not found: {file_path}")
        sys.exit(1)
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        logger.info(f"Loaded {len(urls)} URLs from {file_path}")
        return urls
    except Exception as e:
        logger.error(f"Failed to read URLs file {file_path}: {e}")
        sys.exit(1)

def run_json(cmd):
    logger.debug(f"Running command: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        if proc.returncode != 0:
            logger.warning(f"Command {' '.join(cmd)} returned non-zero (code {proc.returncode}), continuing")
            logger.debug(f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.debug(f"Non-JSON output from {' '.join(cmd)}, returning empty dict")
            return {}
    except subprocess.TimeoutExpired:
        logger.error(f"Command {' '.join(cmd)} timed out after {SCAN_TIMEOUT}s")
        return {}

def run_text(cmd):
    logger.debug(f"Running command: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        if proc.returncode != 0:
            logger.warning(f"Command {' '.join(cmd)} returned non-zero (code {proc.returncode}), continuing")
            logger.debug(f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        return proc.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"Command {' '.join(cmd)} timed out after {SCAN_TIMEOUT}s")
        return ""

# ---------------------
# Scanners (MÊMES OUTILS QUE techM4.sh)
# ---------------------

def scan_with_whatweb(url):
    """
    Retourne une liste de noms de plugins/techs détectés par WhatWeb.
    On parse la sortie texte (robuste aux versions). 
    """
    out = run_text(['whatweb', '--no-errors', '--aggressive', url])
    names = []
    # Exemples de sorties: "https://site [200 OK] Country[XX], Title[Home], X-Powered-By[PHP/8.1], jQuery"
    for token in out.split(','):
        token = token.strip()
        # récupère Title[...], X-Powered-By[...], Server[...] etc.
        m = re.match(r'([A-Za-z0-9\.\+/_-]+)(\[.*\])?$', token)
        if m:
            key = m.group(1)
            # on ignore clairement les champs non-tech évidents
            if key.lower() in {'title', 'country', 'cookies', 'httpserver'}:
                continue
            names.append(key)
    return list(set(names))

def scan_with_webanalyze(url):
    apps = []
    apps_path = os.path.expanduser("~/.config/webanalyze/technologies.json")
    cmd = ['webanalyze', '-host', url]
    if os.path.isfile(apps_path):
        cmd += ['-apps', apps_path]

    # Lancer la commande (texte)
    out = run_text(cmd)
    if not out:
        return apps

    # Essai extraction via regex (chaque techno est au début de ligne, suivi de virgule)
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith('::') or line.startswith('http'):
            continue
        # Exemple: "PHP,  (Programming languages)"
        tech = line.split(',')[0].strip()
        if tech:
            apps.append(tech)

    return list(set(apps))



def scan_with_wafw00f(url):
    """
    Essaie JSON d'abord (nouvelles versions), sinon parse la sortie texte:
    'is behind <WAF> WAF.'
    """
    # tentative JSON (nouvelles versions)
    data = run_json(['wafw00f', '-a', '-o', '-', '--format', 'json', url])
    names = []
    if data:
        if isinstance(data, list):
            for item in data:
                fw = item.get('firewall') or item.get('firewall_name')
                if fw: names.append(fw)
        elif isinstance(data, dict):
            fw = data.get('firewall') or data.get('firewall_name')
            if fw: names.append(fw)
        if names:
            return list(set(names))

    # fallback: texte brut (versions plus anciennes)
    out = run_text(['wafw00f', '-a', url])
    m = re.search(r'is behind ([^.]+)', out, flags=re.IGNORECASE)
    if m:
        names.append(m.group(1).strip())
    return list(set(names))


class TechnologyManager:
    def __init__(self, payloads_dir):
        self.payloads_dir = payloads_dir

    def exists_in_payloads(self, slug):
        for vec in os.listdir(self.payloads_dir):
            vecpath = os.path.join(self.payloads_dir, vec)
            if os.path.isdir(os.path.join(vecpath, slug)):
                return True
        return False

    def format_technologies(self, raw_names):
        seen = set()
        generic_needed = False
        for name in raw_names:
            slug = slugify_technology(name)
            if not slug:
                continue
            if self.exists_in_payloads(slug):
                seen.add(slug)
            else:
                generic_needed = True
        if generic_needed:
            seen.add('generic')
        return sorted(seen)

    # L’API existante (headers/body) reste intacte pour compat ascendante
    def get_technology_stack(self, url, headers, body):
        techs = []
        server = headers.get('Server', '')
        if server:
            techs.append(server.split()[0])
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            techs.extend(powered_by.split())
        if body:
            bl = body.lower()
            if 'django' in bl: techs.append('django')
            if 'laravel' in bl: techs.append('laravel')
            if 'rails' in bl: techs.append('rails')
            if 'mysql' in bl or 'mysqli' in bl: techs.append('mysql')
            if 'postgresql' in bl: techs.append('postgresql')
            if 'php' in bl or '.php' in bl: techs.append('php')
            if '.py' in bl: techs.append('python')
            if '.rb' in bl: techs.append('ruby')
        return self.format_technologies(techs)

# Wrappers compat
def exists_in_payloads(slug, payloads_dir):
    return TechnologyManager(payloads_dir).exists_in_payloads(slug)

def format_technologies(raw_names, payloads_dir):
    return TechnologyManager(payloads_dir).format_technologies(raw_names)

def save_stack(stack_map, output_file):
    try:
        with open(output_file, 'w') as f:
            json.dump(stack_map, f, indent=2)
        logger.info(f"Saved stack to {output_file}")
    except Exception as e:
        logger.error(f"Failed to write {output_file}: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Tech reconnaissance and stack generator (WhatWeb + Webanalyze + Wafw00f)')
    parser.add_argument('urls_file', help='Path to file with list of URLs (one per line)')
    args = parser.parse_args()

    payloads_dir = 'payloads'
    if not os.path.isdir(payloads_dir):
        logger.error(f"Payloads directory not found: {payloads_dir}")
        sys.exit(1)

    urls = load_urls(args.urls_file)
    stack = {}

    for url in urls:
        logger.info(f"=== Scanning {url} ===")
        raw = []
        # Même trio d’outils que techM4.sh
        raw += scan_with_whatweb(url)
        raw += scan_with_webanalyze(url)
        raw += scan_with_wafw00f(url)
        raw_unique = list(set(raw))
        slugs = format_technologies(raw_unique, payloads_dir)
        if not slugs:
            slugs = ['generic']
        stack[url] = slugs
        logger.info(f"{url} → {slugs}")

    os.makedirs('reco', exist_ok=True)
    save_stack(stack, 'reco/stack.json')
    print("Results saved to stack.json", file=sys.stderr)

if __name__ == '__main__':
    main()

# ----------------------
# Unit tests (kept as-is for slug/format)
# ----------------------
class TestReco(unittest.TestCase):
    def test_slugify_technology(self):
        self.assertEqual(slugify_technology('jQuery'), 'jquery')
        # note: if you had 'aspnetmvc' before, slug now defaults to 'aspnetmvc' only if present in SLUG_MAP/payloads
        self.assertEqual(slugify_technology('Node.js'), 'nodejs')
        self.assertEqual(slugify_technology('ReactJS'), 'react')
        self.assertEqual(slugify_technology('Express.JS'), 'express')
        self.assertEqual(slugify_technology('Spring Boot'), 'spring')
        self.assertEqual(slugify_technology('UnknownFramework42'), 'unknownframework42')

    def test_format_technologies_known_and_unknown(self):
        with tempfile.TemporaryDirectory() as tempdir:
            vec1 = os.path.join(tempdir, 'vec1')
            vec2 = os.path.join(tempdir, 'vec2')
            os.makedirs(os.path.join(vec1, 'jquery'), exist_ok=True)
            os.makedirs(os.path.join(vec2, 'react'), exist_ok=True)
            techs = ['jQuery', 'Django', 'React']
            slugs = format_technologies(techs, tempdir)
            self.assertIn('jquery', slugs)
            self.assertIn('react', slugs)
            self.assertIn('generic', slugs)
            self.assertEqual(slugs.count('generic'), 1)

    def test_load_urls(self):
        with tempfile.NamedTemporaryFile('w+', delete=False) as f:
            f.write('http://a.com\n\nhttp://b.com\n')
            f.flush()
            urls = load_urls(f.name)
            self.assertEqual(urls, ['http://a.com', 'http://b.com'])

    def test_save_stack(self):
        stack = {'http://a.com': ['nginx'], 'http://b.com': []}
        with tempfile.NamedTemporaryFile('r+', delete=False) as f:
            out = f.name
        save_stack(stack, out)
        with open(out, 'r') as f2:
            data = json.load(f2)
        self.assertEqual(data, stack)
