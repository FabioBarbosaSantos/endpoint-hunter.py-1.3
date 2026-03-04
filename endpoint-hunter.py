#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import logging
import re
import sys
import time
from urllib.parse import urlparse, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.exceptions import RequestException
from playwright.sync_api import sync_playwright
import tldextract
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.logging import RichHandler

console = Console()
logging.basicConfig(level=logging.INFO, format="%(message)s", handlers=[RichHandler(console=console, rich_tracebacks=True)])
logger = logging.getLogger("endpoint-hunter")

STATIC_EXTENSIONS = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.otf'}

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Endpoint Hunter v1.3 - Caça endpoints com interceptação dinâmica",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Exemplos:\n  python endpoint_hunter.py -u https://example.com --delay 0.2"
    )
    parser.add_argument("-u", "--url", required=True, help="URL alvo")
    parser.add_argument("-t", "--threads", type=int, default=15, help="Threads simultâneas (padrão: 15)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay em segundos entre requisições (anti-WAF/DoS). Use 0.1~0.5 em produção")
    parser.add_argument("--output", type=str, help="Salvar resultados (txt)")
    parser.add_argument("--aggressive", action="store_true", help="Aumenta para 40 threads")
    parser.add_argument("--timeout", type=int, default=12, help="Timeout por requisição")
    parser.add_argument("--retries", type=int, default=2, help="Retries em caso de falha")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--scope", action="append", help="Domínio extra permitido (pode repetir)")

    return parser.parse_args()


def normalize_url(raw_url: str) -> str:
    """Força HTTPS, valida, remove fragmento e limpa."""
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url.lstrip("/")
    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Esquema inválido: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("URL sem domínio válido")

    clean = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        ""  # remove #fragment
    ))
    return clean.rstrip("/")


def get_registered_domain(url: str) -> str:
    return tldextract.extract(url).registered_domain


def looks_like_endpoint(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return False
    if re.search(r'/(api|rest|v[0-9]|graphql|auth|login|user|admin|dashboard|callback|oauth)', path, re.I):
        return True
    return bool(parsed.query) or len(path) > 3


def fetch_js_content(url: str, timeout: int) -> str:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EndpointHunter/1.3"}
    try:
        r = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        if r.status_code == 200 and "javascript" in r.headers.get("content-type", "").lower():
            return r.text
    except:
        pass
    return ""


def extract_endpoints_from_js(js_content: str, base_url: str, allowed: set) -> set:
    endpoints = set()
    patterns = [
        r'(?:"|\')(/api/[^"\')]+?)(?:"|\')',
        r'(?:"|\')(/v[0-9][^"\')]+?)(?:"|\')',
        r'fetch\(["\']([^"\')]+?)["\']',
        r'axios\.(get|post|put|delete|patch)\(["\']([^"\')]+?)["\']',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, js_content, re.IGNORECASE):
            candidate = match.group(1) if len(match.groups()) == 1 else match.group(2)
            if candidate.startswith("//"):
                candidate = "https:" + candidate
            full = urljoin(base_url, candidate)
            if get_registered_domain(full) in allowed and full.startswith("http"):
                endpoints.add(full)
    return endpoints


def check_endpoint(url: str, timeout: int, retries: int, delay: float) -> tuple[str, int | str]:
    time.sleep(delay)  # Controle de taxa
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EndpointHunter/1.3"}

    for attempt in range(retries + 1):
        try:
            resp = requests.head(url, timeout=timeout, headers=headers, allow_redirects=True)
            return url, resp.status_code
        except RequestException as e:
            if attempt == retries:
                return url, f"ERROR ({type(e).__name__})"
    return url, "TIMEOUT"


def get_status_color(status):
    if isinstance(status, str):
        return "red"
    if 200 <= status < 300:
        return "green"
    if 300 <= status < 400:
        return "cyan"
    if status == 404:
        return "dim"
    if 400 <= status < 500:
        return "yellow"   # 401, 403, 405 = úteis
    if status >= 500:
        return "red"
    return "red"


def main():
    args = parse_arguments()
    if args.no_color:
        console.no_color = True
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if args.aggressive:
        args.threads = max(args.threads, 40)

    try:
        base_url = normalize_url(args.url)
    except ValueError as e:
        console.print(f"[bold red]URL inválida: {e}[/bold red]")
        sys.exit(1)

    base_domain = get_registered_domain(base_url)
    allowed_domains = {base_domain}
    if args.scope:
        allowed_domains.update(get_registered_domain(s) for s in args.scope)

    logger.info(f"[bold]Iniciando Endpoint Hunter v1.3[/bold] → {base_url}")
    logger.info(f"Domínios permitidos: {', '.join(allowed_domains)} | Delay: {args.delay}s")

    # ================== COLETA COM INTERCEPTAÇÃO DINÂMICA ==================
    endpoints: set[str] = set()
    js_urls: set[str] = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) EndpointHunter/1.3",
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800}
        )
        page = context.new_page()

        def handle_request(req):
            try:
                u = req.url
                if not u.startswith(("http://", "https://")):
                    return
                parsed = urlparse(u)
                if get_registered_domain(u) not in allowed_domains:
                    return

                path_lower = parsed.path.lower()
                if any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
                    if path_lower.endswith('.js'):
                        js_urls.add(u)
                    return

                if looks_like_endpoint(u):
                    endpoints.add(u)
            except:
                pass

        page.on("request", handle_request)

        try:
            page.goto(base_url, wait_until="networkidle", timeout=60000)
            page.wait_for_timeout(4000)  # espera JS dinâmico
        except Exception as e:
            logger.warning(f"Erro ao carregar página: {e}")

        browser.close()

    # Processa conteúdo dos .js (regex extra)
    logger.info(f"Baixando {len(js_urls)} arquivos .js para análise estática...")
    for js_url in js_urls:
        content = fetch_js_content(js_url, args.timeout)
        if content:
            found = extract_endpoints_from_js(content, js_url, allowed_domains)
            endpoints.update(found)

    logger.info(f"Total de endpoints únicos capturados: [bold]{len(endpoints)}[/bold]")

    # ================== VALIDAÇÃO COM RATE LIMIT ==================
    results = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  BarColumn(), "[progress.percentage]{task.percentage:>3.0f}%", TimeElapsedColumn()) as progress:
        task = progress.add_task("[cyan]Validando endpoints...", total=len(endpoints))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_url = {
                executor.submit(check_endpoint, url, args.timeout, args.retries, args.delay): url
                for url in sorted(endpoints)
            }

            for future in as_completed(future_to_url):
                url, status = future.result()
                results.append((url, status))
                progress.advance(task)

                color = get_status_color(status)
                console.print(f"  • {url:<95} → [{color}]{status}[/{color}]")

    # ================== SALVAR ==================
    if args.output:
        path = Path(args.output)
        with path.open("w", encoding="utf-8") as f:
            for url, status in sorted(results, key=lambda x: (isinstance(x[1], str), x[1] if isinstance(x[1], int) else 999)):
                f.write(f"{url} → {status}\n")
        logger.info(f"[green]Resultados salvos em:[/green] {path.resolve()}")

    console.print("[bold green]Caça finalizada![/bold green]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrompido pelo usuário.[/bold red]")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"Erro fatal: {e}")
        sys.exit(1)
