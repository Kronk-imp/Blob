import sys
import os 
import time
import random
import argparse
from pathlib import Path
from urllib.parse import urlparse, urljoin

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
import json

# Visited URLs to avoid loops
VISITED = set()

def human_delay(a=0.1, b=0.6):
    time.sleep(random.uniform(a, b))

def auto_load_cookie():
    cookie_dir = "cookies"
    # Cherche le PREMIER fichier dans le dossier cookies
    if not os.path.exists(cookie_dir):
        return None
    for fname in os.listdir(cookie_dir):
        if fname.endswith(".txt"):
            with open(os.path.join(cookie_dir, fname), "r") as f:
                cookies = {}
                for pair in f.read().strip().split(";"):
                    if "=" in pair:
                        name, value = pair.strip().split("=", 1)
                        cookies[name.strip()] = value.strip()
                return cookies
    return None

def is_dangerous(text):
    """
    Empêche le clic sur les éléments de déconnexion/suppression
    """
    txt = (text or "").lower()
    danger = ['logout', 'log out', 'se déconnecter', 'delete', 'supprimer', 'désactiver', 'remove', 'sign out']
    return any(word in txt for word in danger)

def close_modals(page):
    """
    Essaie de fermer les modals, overlays, cookie bars...
    """
    selectors = [
        '[aria-label*="close"]', '[class*="close"]', '[class*="dismiss"]', '[id*="close"]',
        '[aria-label*="fermer"]', '[data-dismiss]', '[data-close]', '[class*="overlay"] [role="button"]'
    ]
    for sel in selectors:
        try:
            elems = page.locator(sel)
            count = elems.count()
            for i in range(count):
                elem = elems.nth(i)
                if elem.is_visible():
                    elem.click(timeout=900)
                    human_delay(0.1, 0.5)
        except Exception:
            pass

def accept_cookies(page):
    """
    Accepte/refuse automatiquement les cookies (plusieurs langues)
    """
    cookies_btn = [
        'button:has-text("Accepter")', 'button:has-text("Refuser")',
        'button:has-text("Accepter tout")', 'button:has-text("Tout refuser")',
        'button:has-text("Accept")', 'button:has-text("Deny")', 'button:has-text("Accept all")',
        '[id*="cookie"]', '[class*="cookie"]', '[aria-label*="cookie"]'
    ]
    for sel in cookies_btn:
        try:
            btns = page.locator(sel)
            count = btns.count()
            for i in range(count):
                btn = btns.nth(i)
                if btn.is_visible():
                    btn.click(timeout=1200)
                    human_delay(0.1, 0.4)
        except Exception:
            pass

def open_menus_tabs(page):
    """
    Essaie d'ouvrir des menus déroulants, tabs, accordéons…
    """
    selectors = [
        '[role="tab"]', '[role="menuitem"]', '[class*="menu"]', '[class*="dropdown"]',
        '[class*="tab"]', '[class*="accordion"]', '[data-toggle]', '[aria-expanded="false"]',
        '[data-bs-toggle]', '[data-menu]', '[data-accordion]', '[class*="expand"]',
        '[class*="collapse"]', '[class*="open"]', '[class*="nav"]', '[id*="menu"]', '[id*="nav"]'
    ]
    for sel in selectors:
        try:
            elems = page.locator(sel)
            count = elems.count()
            for i in range(count):
                elem = elems.nth(i)
                if elem.is_visible() and not is_dangerous(elem.inner_text()):
                    elem.click(timeout=900)
                    human_delay(0.2, 0.8)
        except Exception:
            pass

def click_all_menus(page):
    """
    Clique sur tout ce qui ressemble à des menus DANS LA PAGE
    """
    try:
        # Limiter aux éléments dans body ou main
        container = page.locator("body").first
    except:
        return
        
    selectors = [
        '[role="menuitem"]', '[role="tab"]', '[role="button"]', '[class*="menu"]',
        '[class*="dropdown"]', '[class*="tab"]', '[class*="accordion"]', '[data-toggle]', '[aria-expanded]',
        '[data-bs-toggle]', '[data-menu]', '[data-accordion]', '[class*="expand"]', '[class*="collapse"]',
        '[class*="open"]', '[class*="nav"]', '[id*="menu"]', '[id*="nav"]'
    ]
    for sel in selectors:
        try:
            # Chercher DANS le container, pas globalement
            elements = container.locator(sel)
            count = elements.count()
            for i in range(count):
                elem = elements.nth(i)
                elem_text = (elem.inner_text() or "") + (elem.get_attribute("aria-label") or "")
                if elem.is_visible() and not is_dangerous(elem_text):
                    elem.click(timeout=1500)
                    human_delay(0.2, 0.8)
        except Exception:
            pass

def hover_all(page):
    """
    Simule un hover sur tous les éléments interactifs DANS LA PAGE
    """
    try:
        container = page.locator("body").first
    except:
        return
        
    selectors = [
        '[role="menuitem"]', '[role="tab"]', '[class*="menu"]', '[class*="dropdown"]',
        '[class*="tab"]', '[class*="accordion"]', '[data-toggle]', '[aria-expanded]',
        '[data-bs-toggle]', '[data-menu]', '[data-accordion]', '[class*="expand"]', '[class*="collapse"]',
        '[class*="open"]', '[class*="nav"]', '[id*="menu"]', '[id*="nav"]', '[tabindex]', '[data-hover]', '[data-trigger]'
    ]
    for sel in selectors:
        try:
            elems = container.locator(sel)
            count = elems.count()
            for i in range(count):
                elem = elems.nth(i)
                if elem.is_visible():
                    elem.hover()
                    human_delay(0.1, 0.4)
        except Exception:
            pass

def interact_widgets(page):
    """
    Remplit/interagit avec sliders, datepickers, toggles, switchs DANS LA PAGE
    """
    try:
        container = page.locator("body").first
    except:
        return
        
    selectors = [
        'input[type="range"]', '[role="slider"]', '[class*="slider"]',
        'input[type="date"]', '[class*="datepicker"]', '[role="switch"]', '[class*="switch"]',
        'input[type="checkbox"]', '[role="checkbox"]', '[class*="toggle"]'
    ]
    for sel in selectors:
        try:
            elems = container.locator(sel)
            count = elems.count()
            for i in range(count):
                elem = elems.nth(i)
                if elem.is_visible():
                    elem.click(timeout=800)
                    human_delay(0.15, 0.4)
        except Exception:
            pass

def send_keyboard_actions(page):
    """
    Simule pressions clavier importantes (Entrée, Espace, flèches)
    """
    try:
        page.keyboard.press("Tab")
        human_delay(0.1, 0.3)
        page.keyboard.press("Enter")
        human_delay(0.1, 0.2)
        page.keyboard.press("ArrowDown")
        page.keyboard.press("ArrowUp")
        page.keyboard.press("ArrowLeft")
        page.keyboard.press("ArrowRight")
    except Exception:
        pass

def fill_all_inputs(page):
    """
    Remplit TOUS les champs input/textarea/select de la page, dans ou hors formulaires.
    """
    # Valeurs de test simples
    test_values = {
        "email": "GoodFinger@injectics.com",
        "mail": "GoodFinger@injectics.com",
        "user": "GoodFinger",
        "login": "GoodFinger",
        "username": "GoodFinger",
        "name": "GoodFinger",
        "password": "GoodFinger",
        "pass": "GoodFinger",
        "pwd": "GoodFinger",
        "q": "GoodFinger",
        "search": "GoodFinger",
        "token": "GoodFinger",
        "phone": "0610203040",
        "date": "2022-01-01",
        "address": "1337 rue X",
        "default": "GoodFingerTest"
    }
    
    # NOUVEAU : Chercher TOUS les inputs visibles de la page
    print("[DEBUG] Recherche de TOUS les inputs de la page...")
    
    try:
        # Sélectionner tous les inputs, textareas et selects VISIBLES
        all_inputs = page.locator("input:visible, textarea:visible, select:visible")
        total_count = all_inputs.count()
        print(f"[DEBUG] Trouvé {total_count} input(s) au total")
        
        filled_count = 0
        for i in range(total_count):
            try:
                inp = all_inputs.nth(i)
                
                # Vérifier que l'élément est vraiment interactif
                if not inp.is_enabled():
                    continue
                    
                inp_type = (inp.get_attribute("type") or "").lower()
                
                # Skip certains types
                if inp_type in ["submit", "button", "reset", "image", "file"]:
                    continue
                    
                name = (inp.get_attribute("name") or inp.get_attribute("id") or "").lower()
                placeholder = (inp.get_attribute("placeholder") or "").lower()
                
                # Déterminer la valeur à utiliser
                value = None
                
                # Chercher dans l'ordre : name, placeholder, type
                for key in [name, placeholder, inp_type]:
                    if key in test_values:
                        value = test_values[key]
                        break
                
                # Valeur par défaut si rien trouvé
                if not value:
                    value = test_values["default"]
                
                # Cas spéciaux pour les types
                if inp_type == "email":
                    value = test_values["email"]
                elif inp_type == "tel":
                    value = test_values["phone"]
                elif inp_type == "date":
                    value = test_values["date"]
                elif inp_type == "password":
                    value = test_values["password"]
                elif inp_type == "number":
                    value = "42"
                elif inp_type == "checkbox" or inp_type == "radio":
                    inp.check()
                    filled_count += 1
                    continue
                
                # Remplir l'input
                inp.fill(value, timeout=3000)
                filled_count += 1
                print(f"[DEBUG] Rempli input {i}: type={inp_type}, name={name}, value={value}")
                human_delay(0.1, 0.3)
                
            except Exception as e:
                print(f"[DEBUG] Erreur sur input {i}: {e}")
                continue
        
        print(f"[DEBUG] {filled_count}/{total_count} inputs remplis")
        
    except Exception as e:
        print(f"[DEBUG] Erreur générale fill_all_inputs: {e}")
    
    # BONUS : Après avoir rempli, chercher et cliquer sur les boutons submit
    try:
        submit_buttons = page.locator('button[type="submit"], input[type="submit"], button:has-text("Submit"), button:has-text("Login"), button:has-text("Send"), button:has-text("Go")')
        submit_count = submit_buttons.count()
        
        if submit_count > 0:
            print(f"[DEBUG] {submit_count} bouton(s) submit trouvé(s)")
            for i in range(submit_count):
                try:
                    btn = submit_buttons.nth(i)
                    if btn.is_visible() and btn.is_enabled():
                        print(f"[DEBUG] Clic sur bouton submit: {btn.text_content() or btn.get_attribute('value')}")
                        btn.click(timeout=2400)
                        # Ne cliquer que sur le premier bouton visible
                        break
                except:
                    continue
    except Exception as e:
        print(f"[DEBUG] Erreur boutons submit: {e}")


def click_all_nonstandard(page):
    """
    Clique sur tous les <div>, <span>, <svg> interactifs DANS LA PAGE
    """
    try:
        container = page.locator("body").first
    except:
        return
        
    selectors = [
        'div[onclick]', 'span[onclick]', 'svg[onclick]', '[data-action]', '[data-click]',
        '[class*="clickable"]', '[role="button"]', 'div[tabindex]', 'span[tabindex]'
    ]
    for sel in selectors:
        try:
            elems = container.locator(sel)
            count = elems.count()
            for i in range(count):
                elem = elems.nth(i)
                if elem.is_visible():
                    elem.click(timeout=1600)
                    human_delay(0.1, 0.3)
        except Exception:
            pass

def recursive_explore_iframes(page, base_url, max_depth, depth, ua_file, proxy_addr, playwright_ref):
    """
    Explore tous les iframes de la page, y compris ceux générés dynamiquement ou imbriqués.
    """
    try:
        frames = page.frames
    except Exception:
        return
    for frame in frames:
        try:
            if frame != page.main_frame:
                print(f"[*] Exploring iframe: {frame.url}")
                explore(frame, base_url, max_depth, depth+1, ua_file, proxy_addr, playwright_ref)
        except Exception:
            pass

def fill_hidden_inputs(page):
    """
    Remplit même les inputs cachés (pour les tests de sécurité)
    """
    try:
        # Sélectionner TOUS les inputs, même cachés
        all_inputs = page.locator("input, textarea, select")
        hidden_count = 0
        
        for i in range(all_inputs.count()):
            inp = all_inputs.nth(i)
            
            # Si c'est caché mais qu'on peut quand même le remplir
            if not inp.is_visible():
                try:
                    inp_type = (inp.get_attribute("type") or "").lower()
                    if inp_type not in ["submit", "button", "reset"]:
                        inp.fill("GoodFingerHidden", force=True)
                        hidden_count += 1
                except:
                    pass
        
        if hidden_count > 0:
            print(f"[DEBUG] {hidden_count} inputs cachés remplis")
            
    except Exception:
        pass

def wait_for_ajax_completion(page, timeout=10000):
    """
    Attend que toutes les requêtes AJAX soient terminées
    Utilise plusieurs stratégies pour détecter la fin du chargement
    """
    try:
        # Stratégie 1: Attendre que jQuery soit inactif
        page.wait_for_function(
            """() => {
                // jQuery
                if (typeof jQuery !== 'undefined' && jQuery.active !== undefined) {
                    return jQuery.active === 0;
                }
                // Angular
                if (typeof angular !== 'undefined') {
                    var injector = angular.element(document.body).injector();
                    if (injector) {
                        var $http = injector.get('$http');
                        return $http.pendingRequests.length === 0;
                    }
                }
                return true;
            }""",
            timeout=timeout
        )
    except:
        pass
    
    try:
        # Stratégie 2: Attendre que les fetch soient terminés
        page.wait_for_function(
            """() => {
                if (window.__ajaxCount === undefined) {
                    // Intercepter fetch
                    window.__ajaxCount = 0;
                    const originalFetch = window.fetch;
                    window.fetch = function(...args) {
                        window.__ajaxCount++;
                        return originalFetch.apply(this, args).finally(() => {
                            window.__ajaxCount--;
                        });
                    };
                    
                    // Intercepter XMLHttpRequest
                    const originalOpen = XMLHttpRequest.prototype.open;
                    const originalSend = XMLHttpRequest.prototype.send;
                    
                    XMLHttpRequest.prototype.open = function(...args) {
                        this.__requestStarted = false;
                        return originalOpen.apply(this, args);
                    };
                    
                    XMLHttpRequest.prototype.send = function(...args) {
                        if (!this.__requestStarted) {
                            this.__requestStarted = true;
                            window.__ajaxCount++;
                            
                            this.addEventListener('loadend', () => {
                                window.__ajaxCount--;
                            });
                        }
                        return originalSend.apply(this, args);
                    };
                }
                return window.__ajaxCount === 0;
            }""",
            timeout=timeout
        )
    except:
        pass

def wait_for_spa_navigation(page, timeout=5000):
    """
    Attend la navigation dans une SPA (Single Page Application)
    """
    try:
        # Détecter les changements d'URL sans rechargement
        page.wait_for_function(
            """() => {
                if (window.__lastUrl === undefined) {
                    window.__lastUrl = window.location.href;
                    window.__urlChanged = false;
                    
                    // Observer les changements d'URL
                    const pushState = history.pushState;
                    const replaceState = history.replaceState;
                    
                    history.pushState = function(...args) {
                        window.__urlChanged = true;
                        window.__lastUrl = window.location.href;
                        return pushState.apply(history, args);
                    };
                    
                    history.replaceState = function(...args) {
                        window.__urlChanged = true;
                        window.__lastUrl = window.location.href;
                        return replaceState.apply(history, args);
                    };
                    
                    window.addEventListener('popstate', () => {
                        window.__urlChanged = true;
                        window.__lastUrl = window.location.href;
                    });
                }
                
                // Retourner true si l'URL a changé et se stabilise
                if (window.__urlChanged) {
                    window.__urlChanged = false;
                    return false;
                }
                return true;
            }""",
            timeout=timeout
        )
    except:
        pass

def inject_ajax_interceptor(page):
    """
    Injecte un intercepteur pour traquer toutes les requêtes AJAX
    """
    page.evaluate("""() => {
        window.__ajaxRequests = [];
        window.__pendingRequests = new Set();
        
        // Intercepter Fetch
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            const requestId = Date.now() + Math.random();
            const url = args[0];
            
            window.__pendingRequests.add(requestId);
            window.__ajaxRequests.push({
                id: requestId,
                type: 'fetch',
                url: url,
                timestamp: Date.now(),
                status: 'pending'
            });
            
            return originalFetch.apply(this, args)
                .then(response => {
                    window.__pendingRequests.delete(requestId);
                    const index = window.__ajaxRequests.findIndex(r => r.id === requestId);
                    if (index !== -1) {
                        window.__ajaxRequests[index].status = 'completed';
                        window.__ajaxRequests[index].statusCode = response.status;
                    }
                    return response;
                })
                .catch(error => {
                    window.__pendingRequests.delete(requestId);
                    const index = window.__ajaxRequests.findIndex(r => r.id === requestId);
                    if (index !== -1) {
                        window.__ajaxRequests[index].status = 'error';
                        window.__ajaxRequests[index].error = error.message;
                    }
                    throw error;
                });
        };
        
        // Intercepter XMLHttpRequest
        const XHR = XMLHttpRequest.prototype;
        const originalOpen = XHR.open;
        const originalSend = XHR.send;
        
        XHR.open = function(method, url) {
            this.__requestId = Date.now() + Math.random();
            this.__method = method;
            this.__url = url;
            return originalOpen.apply(this, arguments);
        };
        
        XHR.send = function() {
            const requestId = this.__requestId;
            
            window.__pendingRequests.add(requestId);
            window.__ajaxRequests.push({
                id: requestId,
                type: 'xhr',
                method: this.__method,
                url: this.__url,
                timestamp: Date.now(),
                status: 'pending'
            });
            
            this.addEventListener('loadend', () => {
                window.__pendingRequests.delete(requestId);
                const index = window.__ajaxRequests.findIndex(r => r.id === requestId);
                if (index !== -1) {
                    window.__ajaxRequests[index].status = 'completed';
                    window.__ajaxRequests[index].statusCode = this.status;
                }
            });
            
            return originalSend.apply(this, arguments);
        };
    }""")

def get_ajax_requests(page):
    """
    Récupère la liste de toutes les requêtes AJAX effectuées
    """
    return page.evaluate("() => window.__ajaxRequests || []")

def has_pending_requests(page):
    """
    Vérifie si il y a des requêtes en cours
    """
    return page.evaluate("() => window.__pendingRequests ? window.__pendingRequests.size > 0 : false")

def smart_wait_for_load(page, max_wait=30000):
    """
    Attente intelligente qui combine plusieurs stratégies
    """
    start_time = time.time()
    
    # 1. Attendre le chargement initial
    try:
        page.wait_for_load_state("networkidle", timeout=10000)
    except:
        pass
    
    # 2. Attendre que le DOM soit stable
    last_dom_size = 0
    stable_count = 0
    while (time.time() - start_time) * 1000 < max_wait:
        current_dom_size = page.evaluate("() => document.body.innerHTML.length")
        
        if current_dom_size == last_dom_size:
            stable_count += 1
            if stable_count >= 3:  # DOM stable pendant 3 vérifications
                break
        else:
            stable_count = 0
            
        last_dom_size = current_dom_size
        time.sleep(0.5)
    
    # 3. Attendre les requêtes AJAX
    wait_for_ajax_completion(page, timeout=5000)
    
    # 4. Attendre un peu plus si des requêtes sont en cours
    if has_pending_requests(page):
        time.sleep(2)
        wait_for_ajax_completion(page, timeout=5000)

def detect_infinite_scroll(page):
    """
    Détecte si la page utilise un scroll infini
    """
    return page.evaluate("""() => {
        const scrollHeight = document.documentElement.scrollHeight;
        const clientHeight = document.documentElement.clientHeight;
        
        // Vérifier si on peut scroller
        if (scrollHeight <= clientHeight) {
            return false;
        }
        
        // Chercher des indices de pagination infinie
        const indicators = [
            'infinite', 'endless', 'load-more', 'show-more',
            'lazy-load', 'pagination', 'next-page'
        ];
        
        const bodyText = document.body.innerText.toLowerCase();
        const bodyHTML = document.body.innerHTML.toLowerCase();
        
        return indicators.some(indicator => 
            bodyText.includes(indicator) || bodyHTML.includes(indicator)
        );
    }""")

def handle_infinite_scroll(page, max_scrolls=5):
    """
    Gère le scroll infini en chargeant du contenu supplémentaire
    """
    if not detect_infinite_scroll(page):
        return
        
    print("[*] Scroll infini détecté, chargement du contenu...")
    
    for i in range(max_scrolls):
        # Hauteur avant scroll
        height_before = page.evaluate("() => document.documentElement.scrollHeight")
        
        # Scroller vers le bas
        page.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight)")
        
        # Attendre que du nouveau contenu se charge
        time.sleep(1)
        wait_for_ajax_completion(page, timeout=3000)
        
        # Vérifier si du nouveau contenu a été chargé
        height_after = page.evaluate("() => document.documentElement.scrollHeight")
        
        if height_after == height_before:
            print(f"[*] Plus de contenu à charger après {i+1} scrolls")
            break
            
        print(f"[*] Scroll {i+1}/{max_scrolls} - Nouveau contenu chargé")

def explore_enhanced(page, base_url, max_depth=3, depth=0, ua_file="useragents.txt", proxy_addr=None, playwright_ref=None):
    """Version améliorée de explore avec support JavaScript avancé"""
    if depth > max_depth:
        return
    current_url = page.url
    if current_url in VISITED:
        return
    VISITED.add(current_url)
    print(f"[+] Visiting: {current_url}")
    
    # Injecter l'intercepteur AJAX dès le début
    inject_ajax_interceptor(page)
    
    # Attente intelligente pour le chargement complet
    smart_wait_for_load(page)
    
    # Gérer le scroll infini si présent
    handle_infinite_scroll(page)
    
    # Détecter le type d'application
    app_info = page.evaluate("""() => {
        return {
            isReact: !!(window.React || document.querySelector('[data-reactroot]')),
            isVue: !!(window.Vue || window.__VUE__),
            isAngular: !!(window.angular || document.querySelector('[ng-app]')),
            isEmber: !!(window.Ember),
            isjQuery: !!(window.jQuery || window.$),
            hasFetch: typeof window.fetch === 'function',
            hasWebSocket: typeof window.WebSocket === 'function'
        };
    }""")
    
    print(f"[*] App détectée: {json.dumps(app_info, indent=2)}")
    
    # Actions standards du bot
    human_delay(1, 2)
    fill_all_inputs(page)
    fill_hidden_inputs(page)
    
    if depth >= max_depth:
        print(f"[+] Profondeur max atteinte, pas d'exploration supplémentaire")
        # Afficher les requêtes AJAX capturées
        ajax_requests = get_ajax_requests(page)
        if ajax_requests:
            print(f"[*] {len(ajax_requests)} requêtes AJAX capturées:")
            for req in ajax_requests[:10]:  # Afficher max 10
                print(f"    - {req['type'].upper()} {req['url']} ({req['status']})")
        return
    
    # Suite de l'exploration...
    close_modals(page)
    accept_cookies(page)
    human_delay()
    open_menus_tabs(page)
    click_all_menus(page)
    
    # Attendre après les interactions
    wait_for_ajax_completion(page, timeout=3000)
    
    hover_all(page)
    interact_widgets(page)
    send_keyboard_actions(page)
    human_delay()
    click_all_nonstandard(page)
    
    # Attendre après les clics
    wait_for_ajax_completion(page, timeout=3000)
    
    human_delay()
    recursive_explore_iframes(page, base_url, max_depth, depth, ua_file, proxy_addr, playwright_ref)
    
    # Navigation avec gestion SPA
    try:
        links = page.locator("a[href]")
        count = links.count()
        for i in range(count):
            link = links.nth(i)
            href = link.get_attribute("href")
            if not href or href.startswith("javascript:"):
                continue
            full_url = urljoin(current_url, href)
            if urlparse(full_url).netloc != urlparse(base_url).netloc:
                continue
            if full_url not in VISITED:
                try:
                    # Capturer l'URL avant le clic (pour les SPA)
                    url_before = page.url
                    
                    link.click(timeout=2000)
                    
                    # Attendre la navigation SPA
                    wait_for_spa_navigation(page)
                    smart_wait_for_load(page)
                    
                    explore_enhanced(page, base_url, max_depth, depth+1, ua_file, proxy_addr, playwright_ref)
                    
                    # Retour arrière avec gestion SPA
                    if page.url != url_before:
                        page.go_back()
                        wait_for_spa_navigation(page)
                        smart_wait_for_load(page)
                except Exception as e:
                    print(f"[!] Erreur navigation: {e}")
    except Exception as e:
        print(f"[!] Erreur exploration liens: {e}")

def get_random_user_agent(ua_file):
    with open(ua_file, "r") as f:
        agents = [ua.strip() for ua in f if ua.strip()]
    return random.choice(agents)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-url", required=True)
    parser.add_argument("--user-agents", required=True)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--proxy", default=None)
    args = parser.parse_args()

    start_url = args.start_url
    user_agents_file = args.user_agents
    max_depth = args.depth
    proxy = args.proxy

    with sync_playwright() as p:
        browser_args = {
            "headless": True,
            "args": [
                "--disable-extensions",
                "--disable-default-apps",
                "--disable-component-update",
                "--disable-sync",
                "--disable-translate",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-background-timer-throttling",
                "--disable-client-side-phishing-detection",
                "--disable-popup-blocking",
                "--metrics-recording-only",
                "--disable-hang-monitor",
                "--disable-prompt-on-repost",
                "--disable-features=AutofillServerCommunication",
                "--no-sandbox",
            ]
        }
        if proxy:
            browser_args["proxy"] = {"server": proxy}
        browser = p.chromium.launch(**browser_args)
        context_args = {
            "ignore_https_errors": True,
            "java_script_enabled": True,
            "permissions": [],
            "user_agent": get_random_user_agent(user_agents_file),
        }
        context = browser.new_context(**context_args)
        page = context.new_page()
        cookies = auto_load_cookie()
        if cookies:
            cookie_list = []
            # On doit connaître le domaine du start_url pour les cookies !
            domain = urlparse(start_url).netloc
            for name, value in cookies.items():
                cookie_list.append({
                    "name": name,
                    "value": value,
                    "domain": domain,
                    "path": "/"
                })
            context.add_cookies(cookie_list)
        try:
            page.goto(start_url, timeout=30000)
            explore_enhanced(page, start_url, max_depth=max_depth, ua_file=user_agents_file, proxy_addr=proxy, playwright_ref=p)
        except Exception as e:
            print(f"[!] Erreur exploration: {e}")
        finally:
            browser.close()

if __name__ == "__main__":
    main()
