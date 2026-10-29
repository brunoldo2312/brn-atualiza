"""main.py — Entrypoint unificado do nó BRN (v13.7.8)
================================================================
v13.7.8 (2026-10-29):
  [NEW] Boot de checkpoints multi-sig carregados do disco.
  [NEW] Broadcast de checkpoints para blocos minerados localmente.
        Antes, apenas blocos recebidos via P2P disparavam o broadcast.
  [KEEP] Verificação de integridade do código (v13.7.7).
  [KEEP] OfframpManager (v13.7.5).
  [KEEP] Migração Flask→FastAPI via WSGIMiddleware.
================================================================
"""
from __future__ import annotations

import os
import sys
import signal
import argparse
import threading
import time
import json
import subprocess
import urllib.request
import hashlib
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def _bootstrap_env() -> None:
    env_file = BASE_DIR / "brn_network.env"
    if not env_file.exists():
        return
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k and k not in os.environ:
                os.environ[k] = v
    except Exception as e:
        print("[boot] aviso: falha lendo " + str(env_file) + ": " + str(e))


_HARDCODED_DEFAULTS = {
    "BRN_BOOTSTRAP_PEERS":     "",
    "BRN_IS_ORIGIN":           "0",
    "BRN_HTTPS":               "0",
    "BRN_AUDIT_ENABLED":       "1",
    "BRN_AUDIT_LOG":           "audit.log",
    "BRN_P2P_AUTH":            "optional",
    "BRN_P2P_AUTH_WINDOW":     "30",
    "BRN_P2P_NONCE_CACHE":     "10000",
    "BRN_SKIP_VERIFY":         "0",
    "BRN_VERIFY_STRICT":       "0",
    "BRN_TRACKER":             "",
    "MONGO_USER":              "",
    "MONGO_PASS":              "",
    "MONGO_HOST":              "",
    "MONGO_DB":                "brn_analytics",
    "TS_AUTH_KEY":             "",
    "TS_API_KEY":              "",
    "TS_TAILNET":              "",
    "TS_HOSTNAME_PREFIX":      "brn-node",
    "BRN_POOL_ENABLED":        "1",
    "BRN_POOL_URL_LOCAL":      "http://127.0.0.1:5000",
    "BRN_WEB_PASS":            "",
    "BRN_FORCE_HEADLESS":      "0",
    "BRN_UVICORN_WORKERS":     "1",
}


def _apply_hardcoded_defaults() -> int:
    aplicados = 0
    for k, v in _HARDCODED_DEFAULTS.items():
        if k not in os.environ or os.environ[k] == "":
            os.environ[k] = v
            aplicados += 1
    return aplicados


_bootstrap_env()
_applied = _apply_hardcoded_defaults()
if _applied:
    print(f"[boot] defaults não-sensíveis aplicados: {_applied} variáveis")


# ============================================================
# [SECURITY] Verificação de integridade do código
# ============================================================
def _verificar_integridade_codigo() -> None:
    HASHES_OFICIAIS = {
        "blockchain.py":    "COLE_O_HASH_SHA256_AQUI",
        "trust_network.py": "COLE_O_HASH_SHA256_AQUI",
    }
    for arquivo, hash_esperado in HASHES_OFICIAIS.items():
        if hash_esperado == "COLE_O_HASH_SHA256_AQUI":
            continue
        caminho = BASE_DIR / arquivo
        if not caminho.exists():
            print(f"[ALERTA CRÍTICO] Arquivo crítico {arquivo} não encontrado! Abortando.")
            sys.exit(1)
        try:
            with open(caminho, "rb") as f:
                hash_real = hashlib.sha256(f.read()).hexdigest()
            if hash_real != hash_esperado:
                print("=" * 64)
                print(f"[ALERTA CRÍTICO] O arquivo {arquivo} foi MODIFICADO!")
                print(f"Esperado: {hash_esperado}")
                print(f"Real:     {hash_real}")
                print("=" * 64)
                sys.exit(1)
        except Exception as e:
            print(f"[ERRO] Falha ao verificar {arquivo}: {e}")
            sys.exit(1)


from brn_config import Config
from brn_logger import setup_logger, get_logger
from version import VERSION, BUILD_DATE, GITHUB_USER, GITHUB_REPO

try:
    from trust_network import TrustNetwork
    _HAS_TRUST = True
except ImportError:
    TrustNetwork = None
    _HAS_TRUST = False

_shutdown = threading.Event()

NODE_ID_PATH        = BASE_DIR / "node_identity.enc"
CLIENT_BOOT_TIMEOUT = int(os.environ.get("BRN_CLIENT_BOOT_TIMEOUT", "120"))
WEB_HOST            = os.environ.get("BRN_WEB_HOST",      "127.0.0.1")
EXPLORER_HOST       = os.environ.get("BRN_EXPLORER_HOST", "127.0.0.1")
AUTO_MINE           = os.environ.get("BRN_AUTO_MINE", "0") == "1"

_running_services: list = []
_services_lock = threading.Lock()


def _register_service(name: str, svc) -> None:
    with _services_lock:
        _running_services.append((name, svc))


def _thread_excepthook(args):
    try:
        log = get_logger("thread")
        thread_name = args.thread.name if args.thread else "?"
        log.error(
            "Thread '" + str(thread_name) + "' morreu: " + str(args.exc_value),
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        )
    except Exception:
        pass


threading.excepthook = _thread_excepthook


def _thread_wrap(name: str, fn):
    def runner():
        try:
            fn()
        except Exception as e:
            try:
                get_logger(name).exception("thread " + name + " caiu: " + str(e))
            except Exception:
                pass
    return runner


def _check_required_modules() -> list:
    required = [
        "brn_config", "brn_logger", "version",
        "blockchain", "db", "crypto", "wallet", "bech32",
        "secure_store", "chain_validator", "checkpoints",
        "p2p_auth", "p2p_cipher", "p2p_secure", "p2p_unified",
        "discovery_v2", "miner_loop", "trust_network",
        "server_fastapi", "fastapi", "uvicorn"
    ]
    missing = []
    for m in required:
        try:
            __import__(m)
        except Exception:
            missing.append(m)
    return missing


# ============================================================
# L2
# ============================================================
L2_ENABLED = False
btc_config = None
BTCWatcher = None
L2Manager = None
OfframpManager = None
BTCSender = None

try:
    import btc_config
    from btc_watcher import BTCWatcher
    from l2_manager import L2Manager
    from offramp_manager import OfframpManager
    from btc_sender import BTCSender
    L2_ENABLED = True
    print("[L2] Módulos BTC (Onramp + Offramp) carregados OK")
except Exception as _e:
    print("[AVISO] Módulos L2 indisponíveis: " + str(_e))


def _l2_disponivel() -> bool:
    return bool(
        L2_ENABLED
        and btc_config is not None
        and BTCWatcher is not None
        and L2Manager is not None
        and OfframpManager is not None
        and BTCSender is not None
    )


# ============================================================
# POOL
# ============================================================
POOL_ENABLED = os.environ.get("BRN_POOL_ENABLED", "1") == "1"
PoolManager = None
PoolClient = None

try:
    from miner_pool_client import PoolClient
    print("[Pool] PoolClient carregado OK")
except Exception as _e:
    print("[AVISO] miner_pool_client indisponível: " + str(_e))

if POOL_ENABLED:
    try:
        from mining_pool import PoolManager
        print("[Pool] PoolManager carregado OK")
    except Exception as _e:
        print("[AVISO] mining_pool indisponível: " + str(_e))
        POOL_ENABLED = False


def _pool_disponivel() -> bool:
    return bool(POOL_ENABLED and PoolManager is not None)


# ============================================================
# AUDIT
# ============================================================
def _audit(event: str, data: dict = None) -> None:
    try:
        from security import audit_log
        audit_log(event, data or {})
    except Exception:
        pass


def _close_audit() -> None:
    try:
        from security import close_audit
        close_audit()
    except Exception:
        pass


def _setup_tailscale_auto(log) -> bool:
    auth_key = os.environ.get("TS_AUTH_KEY", "").strip()
    if not auth_key:
        log.info("Tailscale: desabilitado (TS_AUTH_KEY vazia)")
        return True
    setup_path = BASE_DIR / "brn_tailscale_setup.py"
    if not setup_path.exists():
        return True
    try:
        r = subprocess.run(
            [sys.executable, str(setup_path), "--auto"],
            capture_output=True, text=True, timeout=180,
            cwd=str(BASE_DIR),
        )
        return r.returncode == 0
    except Exception:
        return False


def parse_args():
    p = argparse.ArgumentParser(prog="main.py", description="BRN Node v13")
    p.add_argument("--status", action="store_true")
    p.add_argument("--headless", action="store_true")
    p.add_argument("--read-only", action="store_true")
    p.add_argument("--version", action="store_true")
    p.add_argument("--check-update", action="store_true")
    p.add_argument("--config", default="config.json")
    p.add_argument("--log-level", default=None)
    p.add_argument("--log-file", default=None)
    p.add_argument("--password-file", default=None)
    p.add_argument("--rotate-node-id", action="store_true")
    p.add_argument("--client-mode", action="store_true")
    p.add_argument("--discover", action="store_true")
    p.add_argument("--l2", action="store_true")
    p.add_argument("--l2-stats", action="store_true")
    p.add_argument("--mine", action="store_true")
    p.add_argument("--no-p2p", action="store_true")
    p.add_argument("--relay", dest="relay", action="store_true", default=None)
    p.add_argument("--no-relay", dest="relay", action="store_false")
    p.add_argument("--verify-only", action="store_true")
    p.add_argument("--skip-verify", action="store_true")
    p.add_argument("--no-tailscale", action="store_true")
    p.add_argument("--no-sync", action="store_true")
    p.add_argument("--no-pool", action="store_true")
    p.add_argument("--pool-client", action="store_true")
    p.add_argument("--no-pool-client", action="store_true")
    p.add_argument("--pool-stats", action="store_true")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--no-gui", action="store_true")
    return p.parse_args()


def _validate_required_secrets(log, is_origin: bool, wants_mining: bool) -> bool:
    critical = {
        "BRN_NODE_PASSWORD": "senha da identidade Ed25519 do no",
        "BRN_NETWORK_SECRET": "segredo HMAC da rede P2P",
    }
    if wants_mining:
        critical["BRN_WALLET_SESSION_PASS"] = "senha da carteira local (para minerar)"
    OLD_DEFAULTS = (
        "senha-no-temp-123", "senha-temp-123",
        "senha-forte-da-carteira-2026",
        "9226edea8ba62bc1c6ae36883c0536c95b4c85642195465d6c4d9456abef20f9",
    )
    missing, weak = [], []
    for k, desc in critical.items():
        val = os.environ.get(k, "").strip()
        if not val:
            missing.append(f"  - {k}  ({desc})")
        elif val in OLD_DEFAULTS:
            weak.append(f"  - {k}  ({desc})")
    if missing:
        log.error("=" * 64)
        log.error(" SEGREDOS OBRIGATORIOS AUSENTES")
        log.error("=" * 64)
        for m in missing:
            log.error(m)
        log.error(" O no NAO VAI INICIAR sem esses segredos.")
        log.error("=" * 64)
        return False
    if weak:
        log.warning("=" * 64)
        log.warning(" SEGREDOS FRACOS (defaults antigos) - continuando")
        log.warning("=" * 64)
        for w in weak:
            log.warning(w)
        log.warning("=" * 64)
    return True


def _resolve_password(args) -> str:
    if args.password_file:
        p = Path(args.password_file)
        if not p.exists():
            raise SystemExit("--password-file não encontrado")
        return p.read_text(encoding="utf-8").rstrip("\r\n")
    env = os.environ.get("BRN_NODE_PASSWORD")
    if env:
        return env
    if sys.stdin.isatty():
        import getpass
        return getpass.getpass("Senha do nó (identidade Ed25519): ")
    raise SystemExit("Senha do nó não informada.")


def _resolve_wallet_password() -> str:
    return (
        os.environ.get("BRN_WALLET_SESSION_PASS", "").strip()
        or os.environ.get("BRN_NODE_PASSWORD", "").strip()
    )


def _load_validator_sk():
    try:
        from secure_store import load_current_wallet
        from wallet import Wallet
        pass_wd = _resolve_wallet_password()
        if not pass_wd:
            return None
        w = load_current_wallet(pass_wd)
        if not w or not w.get("ok"):
            return None
        sk_hex = w.get("private_key", "") or w.get("priv_hex", "")
        if not sk_hex:
            return None
        return Wallet(private_key_hex=sk_hex)
    except Exception:
        return None


def _make_sign_collector(p2p, trust_net):
    def _collect(block: dict) -> list:
        if p2p is None or trust_net is None:
            return []
        try:
            validators = trust_net.get_top_validators(count=5)
        except Exception:
            return []
        if len(validators) <= 1:
            return []
        if not hasattr(p2p, "request_block_signature"):
            return []
        sigs = []
        try:
            peers = p2p.discovery.listar_peers()
        except Exception:
            return sigs
        for peer in peers:
            if ":" not in peer:
                continue
            try:
                ip, port_s = peer.rsplit(":", 1)
                port = int(port_s)
            except Exception:
                continue
            try:
                resp = p2p.request_block_signature(ip, port, block)
                if resp and resp.get("pubkey") and resp.get("signature"):
                    sigs.append({"pubkey": resp["pubkey"], "signature": resp["signature"]})
            except Exception:
                continue
        return sigs
    return _collect


def load_or_create_node_identity(password: str, rotate: bool = False):
    from crypto import Ed25519PrivateKey
    from secure_store import save_wallet, load_wallet
    log = get_logger("identity")
    if rotate and NODE_ID_PATH.exists():
        backup = NODE_ID_PATH.with_suffix(".enc.bak")
        NODE_ID_PATH.replace(backup)
        log.warning("Identidade rotacionada. Backup em " + str(backup))
    if NODE_ID_PATH.exists():
        data = load_wallet(password, str(NODE_ID_PATH))
        if not data:
            raise SystemExit("Falha ao decifrar " + str(NODE_ID_PATH))
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["sk"]))
        pub_hex = data["pub"]
    else:
        sk = Ed25519PrivateKey.generate()
        pub_hex = sk.public_key().public_bytes_raw().hex()
        save_wallet(
            {"sk": sk.private_bytes_raw().hex(), "pub": pub_hex},
            password, str(NODE_ID_PATH),
        )
        log.info("Identidade nova criada: " + pub_hex[:16] + "... (" + str(NODE_ID_PATH) + ")")
    try:
        from ab_test import get_variant, get_node_id_hash
        from security import set_node_id_hash, audit_log
        node_hash = get_node_id_hash(pub_hex)
        set_node_id_hash(node_hash)
        variant = get_variant(node_hash)
        audit_log("exposure_log", {"variant": variant, "node_id": node_hash})
        log.info(f"Teste A/B: Variante atribuída -> {variant}")
    except Exception as e:
        log.warning(f"Falha ao registrar A/B test: {e}")
    return sk, pub_hex


def _read_role() -> str:
    try:
        p = BASE_DIR / "brn_role.txt"
        if p.exists():
            return p.read_text(encoding="utf-8").strip().lower()
    except Exception:
        pass
    return "auto"


def _is_origin(client_mode: bool) -> bool:
    if client_mode:
        return False
    if os.environ.get("BRN_IS_ORIGIN", "0") == "1":
        return True
    return _read_role() in ("origin", "hub", "servidor")


VERIFY_OK      = "ok"
VERIFY_INVALID = "invalid"
VERIFY_ERROR   = "error"


def _verify_chain(chain) -> str:
    try:
        from chain_validator import verify_chain
    except ImportError:
        get_logger("verify").info("chain_validator.py não disponível")
        return VERIFY_ERROR
    log = get_logger("verify")
    log.info("Verificando integridade da cadeia...")
    t0 = time.time()
    try:
        r = verify_chain(chain)
    except Exception as e:
        log.exception("validador falhou: " + str(e))
        return VERIFY_ERROR
    dt = time.time() - t0
    valid = getattr(r, "valid", None)
    if valid is None:
        valid = bool(r)
    summary_fn = getattr(r, "summary", None)
    blocks = getattr(r, "blocks_checked", 0)
    warns = getattr(r, "warnings", []) or []
    errs = getattr(r, "errors", []) or []
    if valid:
        if callable(summary_fn):
            log.info(f"OK {summary_fn()} ({dt:.2f}s)")
        else:
            log.info(f"OK cadeia íntegra ({dt:.2f}s, {blocks} blocos)")
        for w in warns[:5]:
            log.warning("  " + str(w))
        return VERIFY_OK
    log.error(f"CADEIA INVÁLIDA ({len(errs)} erros)")
    for e in errs[:10]:
        log.error("  - " + str(e))
    return VERIFY_INVALID


def _inject_into_server(what: str, obj, log) -> bool:
    setter_name = {
        "p2p":     "set_p2p_manager",
        "sync":    "set_sync_manager",
        "pool":    "set_pool_manager",
        "trust":   "set_trust_network",
        "offramp": "set_offramp_manager",
    }.get(what)
    if setter_name is None:
        log.warning(f"[inject] tipo desconhecido: {what}")
        return False
    try:
        import server as _srv
        setter = getattr(_srv, setter_name, None)
        if setter is None:
            log.warning(f"[inject] server.py NAO tem {setter_name}()")
            return False
        setter(obj)
        log.info(f"[inject] {what} injetado em server.py")
        return True
    except ImportError as e:
        log.warning(f"[inject] server.py indisponível ({what}): {e}")
        return False
    except Exception as e:
        log.warning(f"[inject] {what} falhou: {e}")
        return False


def _init_http_server(chain, log):
    try:
        from server import set_chain, auto_registrar_carteira_atual
        from server_fastapi import app as http_app
    except Exception as e:
        log.error("Falha importando servidores: " + str(e))
        return None
    try:
        set_chain(chain)
        log.info("server.py: chain injetada")
    except Exception as e:
        log.error("Falha set_chain: " + str(e))
        return None
    try:
        reg = auto_registrar_carteira_atual()
        if reg.get("ok"):
            log.info("auto-registro pubkey: " + str(reg.get("msg")))
        else:
            log.info("auto-registro pubkey: pulado (" + str(reg.get("msg")) + ")")
    except Exception as e:
        log.warning("auto-registro pubkey falhou: " + str(e))
    return http_app


def run_http(app_instance):
    log = get_logger("http")
    port = int(os.environ.get("BRN_WEB_PORT", "5000"))
    try:
        workers = max(1, int(os.environ.get("BRN_UVICORN_WORKERS", "1")))
    except (TypeError, ValueError):
        workers = 1
    try:
        import uvicorn
        if workers > 1:
            log.info(f"HTTP Uvicorn ({workers} workers) - http://{WEB_HOST}:{port}")
            uvicorn.run("server_fastapi:app", host=WEB_HOST, port=port,
                        workers=workers, log_level="warning", proxy_headers=True)
        else:
            log.info(f"HTTP Uvicorn - http://{WEB_HOST}:{port}")
            uvicorn.run(app_instance, host=WEB_HOST, port=port,
                        log_level="warning", proxy_headers=True)
    except ImportError:
        log.warning("Uvicorn nao instalado. Caindo para Waitress...")
        try:
            from waitress import serve
            serve(app_instance, host=WEB_HOST, port=port, threads=256)
        except ImportError:
            app_instance.run(host=WEB_HOST, port=port, threaded=True)


def run_explorer():
    from explorer import app as explorer_app
    log = get_logger("explorer")
    port = int(os.environ.get("BRN_EXPLORER_PORT", "8080"))
    log.info("Explorer http://" + EXPLORER_HOST + ":" + str(port))
    explorer_app.run(host=EXPLORER_HOST, port=port, threaded=True,
                     debug=False, use_reloader=False, ssl_context=None)


def run_status_loop(chain, p2p, sync=None, pool=None, pool_client=None,
                    trust_net=None, node_id_short=""):
    log = get_logger("status")
    last_peers_hb = 0.0
    PEERS_HB_INTERVAL = 60.0
    _already_warned_no_endereco = [False]
    while not _shutdown.is_set():
        time.sleep(30)
        try:
            peer_count = 0
            if p2p:
                try:
                    peer_count = p2p.get_status().get("peer_count", 0)
                except Exception:
                    pass
            mempool_n = len(chain.db.all_mempool(limit=1000))
            utxos_n = chain.db.count_utxos()
            msg = ("Altura=" + str(chain.db.height())
                   + " Peers=" + str(peer_count)
                   + " Mempool=" + str(mempool_n)
                   + " UTXOs=" + str(utxos_n))
            if sync:
                try:
                    s = sync.get_status()
                    msg += " Sync=" + str(s.get("progress", 0)) + "%"
                except Exception:
                    pass
            if trust_net:
                try:
                    ts = trust_net.get_network_stats()
                    msg += " Trust[Nodes=" + str(ts.get("total_nodes", 0)) + "]"
                except Exception:
                    pass
            log.info(msg)
            agora = time.time()
            if agora - last_peers_hb >= PEERS_HB_INTERVAL:
                last_peers_hb = agora
                try:
                    from update_peers import update_local_timestamp
                    update_local_timestamp(height=chain.db.height(),
                                            node_id=node_id_short or "")
                except Exception:
                    pass
        except Exception as e:
            log.warning("status loop: " + str(e))


def run_wallet_main_thread():
    try:
        if not os.environ.get("BRN_WEB_PASS"):
            get_logger("wallet").error("BRN_WEB_PASS não definida")
            return False
        from app_wallet_v3 import WalletApi
        import webview
        log = get_logger("wallet")
        index_path = BASE_DIR / "index_wallet.html"
        if not index_path.exists():
            log.error("index_wallet.html não encontrado: " + str(index_path))
            return False
        api = WalletApi()
        webview.create_window(
            "BRN RWA — Carteira Digital",
            url=index_path.resolve().as_uri(),
            js_api=api,
            width=1020, height=880,
            min_size=(820, 640),
            background_color="#0d1117",
        )
        webview.start(debug=False)
        return True
    except Exception as e:
        get_logger("wallet").error("Falha: " + str(e))
        return False


def _setup_pool_client_local(chain, pool, log, disabled: bool, is_origin: bool):
    if disabled:
        log.info("PoolClient: desativado")
        return None
    if PoolClient is None:
        log.info("PoolClient: miner_pool_client indisponível")
        return None
    wallet_pass = _resolve_wallet_password()
    if not wallet_pass:
        log.warning("PoolClient: senhas vazias")
        return None
    addr = ""
    pub = ""
    try:
        from secure_store import load_current_wallet
        w = load_current_wallet(wallet_pass)
        if w and w.get("ok"):
            addr = (w.get("address") or "").strip()
            pub = (w.get("public_key") or w.get("pub_hex") or w.get("pubkey") or "").strip()
    except Exception as e:
        log.warning("PoolClient: falha lendo current_wallet: " + str(e))
    if not addr.startswith("brn1") or not pub:
        log.warning("PoolClient: current_wallet.enc sem address/public_key")
        return None
    if is_origin:
        pool_url = os.environ.get("BRN_POOL_URL_LOCAL", "http://127.0.0.1:5000")
    else:
        pool_url = os.environ.get("BRN_POOL_URL", "http://127.0.0.1:5000")
    try:
        pc = PoolClient(addr, pub, pool_url=pool_url)
        ok, msg = pc.start_mining()
        if not ok:
            log.warning("PoolClient: start_mining falhou: " + str(msg))
            return None
        log.info("PoolClient iniciado (is_origin=" + str(is_origin) + " pool=" + pool_url + ")")
        return pc
    except Exception as e:
        log.warning("PoolClient: exceção: " + str(e))
        return None


# ============================================================
# [FIX v13.7.8] Broadcast local → P2P + Checkpoint
# ============================================================
def _setup_local_miner_broadcast(chain, p2p, log):
    """
    Encadeia on_block_mined para:
      1. Broadcast do bloco via P2P
      2. Broadcast do checkpoint (se este bloco gerou um) via P2P
      3. Notificar ForkGuard
    """
    prev_cb = getattr(chain, "on_block_mined", None)

    def _on_local_block(block):
        h = int(block.get("height", -1))

        # 1. Broadcast do bloco
        if p2p is not None:
            try:
                p2p.broadcast_block(block)
                log.info("miner local: bloco #" + str(h) + " propagado via P2P")
            except Exception as e:
                log.debug("broadcast_block falhou: " + str(e))

        # 2. [NEW v13.7.8] Broadcast do checkpoint
        #    Só o nó que MINEROU precisa fazer isso, porque os outros
        #    vão gerar o próprio checkpoint ao receber o bloco.
        if p2p is not None:
            try:
                from checkpoints import load_checkpoints
                cp = load_checkpoints().get(str(h))
                if cp:
                    p2p.broadcast_checkpoint(cp)
                    log.info("[CHECKPOINT] #%d propagado via P2P (local)", h)
            except Exception as e:
                log.debug("[CHECKPOINT] broadcast local falhou: " + str(e))

        # 3. ForkGuard
        try:
            from fork_guard import get_fork_guard
            fg = get_fork_guard()
            if fg is not None:
                fg.on_block_accepted(block)
        except Exception as e:
            log.debug("fork_guard.on_block_accepted falhou: " + str(e))

        # 4. Preserva callback anterior
        if prev_cb is not None and prev_cb is not _on_local_block:
            try:
                prev_cb(block)
            except Exception as e:
                log.debug("prev on_block_mined falhou: " + str(e))

    chain.on_block_mined = _on_local_block
    if p2p is not None:
        log.info("chain.on_block_mined ligado ao P2P + Checkpoint + ForkGuard")
    else:
        log.info("chain.on_block_mined ligado ao ForkGuard (P2P off)")
    return True


def _stop_with_timeout(name: str, svc, timeout: float = 5.0, log=None) -> None:
    try:
        if hasattr(svc, "stop"):
            fn = svc.stop
        elif hasattr(svc, "stop_mining"):
            fn = svc.stop_mining
        elif callable(svc):
            fn = svc
        else:
            return
    except Exception:
        return
    t = threading.Thread(target=fn, daemon=True, name="stop-" + name)
    t.start()
    t.join(timeout)
    if t.is_alive() and log is not None:
        log.warning("Serviço " + name + " não parou em " + str(timeout) + "s")


def _graceful_shutdown(log, trust_net=None) -> None:
    log.info("Encerrando serviços...")
    try:
        from fork_guard import stop_fork_guard
        if stop_fork_guard():
            log.info("ForkGuard parado")
    except Exception:
        pass
    with _services_lock:
        services = list(_running_services)
    for name, svc in reversed(services):
        _stop_with_timeout(name, svc, timeout=5.0, log=log)
    try:
        from wallet import WalletManager
        WalletManager.lock_session()
    except Exception:
        pass
    try:
        from mongo_client import mongo
        mongo.close()
    except Exception:
        pass
    if trust_net is not None:
        try:
            trust_net.shutdown()
            log.info("TrustNetwork salva com sucesso.")
        except Exception as e:
            log.warning("Falha salvando TrustNetwork: " + str(e))
    _audit("node_stop", {})
    _close_audit()


def main():
    _verificar_integridade_codigo()

    args = parse_args()
    cfg = Config(args.config)

    if args.read_only: cfg.data["read_only"] = True
    if args.headless or args.no_gui: cfg.data["headless"] = True
    if args.gui: cfg.data["headless"] = False
    if args.log_level: cfg.data["log_level"] = args.log_level
    if args.log_file: cfg.data["log_file"] = args.log_file
    if os.environ.get("BRN_FORCE_HEADLESS", "0") == "1": cfg.data["headless"] = True

    cfg.apply_to_env()
    log = setup_logger(level=cfg["log_level"], log_file=cfg["log_file"] or None)
    is_origin = _is_origin(args.client_mode)

    log.info("=" * 60)
    log.info(" BRN Node v" + VERSION + " (" + BUILD_DATE + ")")

    if args.l2 and _l2_disponivel():
        l2_mode = "ON"
    elif not args.l2:
        l2_mode = "off"
    else:
        l2_mode = "INDISPONÍVEL"

    pool_mode = ("off" if args.no_pool
                 else ("ON" if _pool_disponivel() else "off"))

    log.info(" Config: " + cfg.source
             + " | Modo: " + ("ORIGEM" if is_origin else "CLIENTE")
             + " | L2: " + l2_mode
             + " | Pool: " + pool_mode)
    log.info(" HTTPS: " + ("ON" if os.environ.get("BRN_HTTPS") == "1" else "off")
             + " | Auto-mine: " + ("ON" if AUTO_MINE else "off"))
    log.info(" GUI: " + ("headless" if cfg["headless"] else "pywebview"))
    log.info(" Checkpoint: a cada %d blocos" % int(os.environ.get("BRN_CHECKPOINT_INTERVAL", "100")))
    log.info("=" * 60)

    if args.version:
        print(VERSION); return 0
    if args.status:
        print("=" * 64)
        print(" BRN Node — Diagnóstico (v" + VERSION + ")")
        print("=" * 64)
        print(" Config    : " + cfg.source)
        print(" Web       : " + WEB_HOST + ":" + str(cfg["web_port"]))
        print(" Explorer  : " + EXPLORER_HOST + ":" + str(cfg["explorer_port"]))
        print(" P2P       : " + str(cfg["p2p_port"]))
        print(" Pool      : " + ("SIM" if _pool_disponivel() else "não"))
        print(" L2        : " + ("SIM" if _l2_disponivel() else "não"))
        print(" Role      : " + ("ORIGEM" if is_origin else "CLIENTE"))
        print("=" * 64)
        return 0
    if args.check_update:
        print('{"ok": false, "msg": "check_update simplificado"}'); return 0

    missing = _check_required_modules()
    if missing:
        log.error("Módulos obrigatórios faltando: " + ", ".join(missing))
        return 1

    wants_mining = bool(args.mine or AUTO_MINE or (not args.no_pool))
    if not _validate_required_secrets(log, is_origin, wants_mining):
        return 1

    if not args.no_tailscale:
        _setup_tailscale_auto(log)

    try:
        node_password = _resolve_password(args)
    except SystemExit as e:
        log.error(str(e)); return 1

    try:
        node_sk, node_pub = load_or_create_node_identity(node_password, rotate=args.rotate_node_id)
    except SystemExit as e:
        log.error(str(e)); return 1
    except Exception as e:
        log.exception("Falha ao carregar identidade: " + str(e)); return 1

    log.info("Nó ID: " + node_pub[:16] + "...")

    # ---- blockchain ----
    from blockchain import Blockchain
    chain = Blockchain(cfg["db_path"], auto_genesis=is_origin,
                        network_secret=cfg["network_secret"])
    chain._fork_signal = threading.Event()
    chain.is_origin = is_origin
    log.info("Blockchain pronta (altura=" + str(chain.db.height()) + ")")

    # ---- Trust Network ----
    trust_net = None
    if _HAS_TRUST:
        try:
            trust_net = TrustNetwork(
                str(BASE_DIR / "trust_network.json"),
                is_origin=is_origin,
                node_sk=node_sk,
            )
            try:
                chain.set_trust_net(trust_net)
            except AttributeError:
                chain.trust_net = trust_net
            log.info("TrustNetwork: " + str(len(trust_net.nodes)) + " nós carregados")
        except Exception as e:
            log.warning("TrustNetwork desativada: " + str(e)); trust_net = None

    # ---- [NEW v13.7.8] Checkpoints ----
    if is_origin:
        try:
            from checkpoints import load_checkpoints
            from blockchain import set_checkpoints
            cps = load_checkpoints()
            set_checkpoints(cps)
            if cps:
                log.info("Checkpoints carregados do disco: %d", len(cps))
            log.info(
                "Checkpoints MULTI-SIG ativos (a cada %d blocos, quorum=%.2f)",
                int(os.environ.get("BRN_CHECKPOINT_INTERVAL", "100")),
                float(os.environ.get("BRN_VALIDATOR_QUORUM", "0.66")),
            )
        except Exception as e:
            log.warning("Checkpoints desativados: %s", e)
    else:
        # Cliente também carrega localmente para validar blocos recebidos
        try:
            from checkpoints import load_checkpoints
            from blockchain import set_checkpoints
            cps = load_checkpoints()
            set_checkpoints(cps)
            if cps:
                log.info("Checkpoints locais carregados: %d", len(cps))
        except Exception as e:
            log.debug("Checkpoints (client) falhou: %s", e)

    # ---- verify ----
    if args.verify_only:
        st = _verify_chain(chain)
        try: chain.db.close()
        except Exception: pass
        return 0 if st == VERIFY_OK else 2

    if not args.skip_verify and os.environ.get("BRN_SKIP_VERIFY", "0") != "1":
        strict = os.environ.get("BRN_VERIFY_STRICT", "0") == "1"
        st = _verify_chain(chain)
        if st == VERIFY_INVALID and strict:
            log.error("Abortando: cadeia inválida (BRN_VERIFY_STRICT=1)")
            try: chain.db.close()
            except Exception: pass
            return 2
        if st == VERIFY_ERROR:
            log.warning("Verificação não conclusiva — seguindo com cautela")

    # ---- P2P ----
    p2p = None
    if not args.no_p2p:
        try:
            from p2p_unified import P2PManager
            p2p = P2PManager(chain, node_sk,
                             tcp_port=cfg["p2p_port"],
                             enable_upnp=cfg["upnp"])
            p2p.start()
            _register_service("p2p", p2p)
            log.info("P2P iniciado na porta " + str(cfg["p2p_port"]))
            try: chain.set_p2p(p2p)
            except AttributeError: chain.p2p = p2p
        except Exception as e:
            log.error("Falha ao iniciar P2P: " + str(e)); p2p = None

    # ---- Validator SK ----
    validator_sk = _load_validator_sk()
    if validator_sk is not None:
        try:
            chain.set_local_validator_sk(validator_sk)
            log.info(f"Validator SK carregada: {validator_sk.pub_hex[:16]}...")
            if p2p is not None:
                try:
                    if hasattr(p2p, "broadcast_validator_registration"):
                        p2p.broadcast_validator_registration(
                            pubkey=validator_sk.pub_hex,
                            address=validator_sk.address,
                        )
                        log.info("Auto-registro P2P: announce_validator enviado")
                except Exception as e:
                    log.warning("Auto-registro P2P falhou: " + str(e))
        except AttributeError:
            chain._local_validator_sk = validator_sk
        except Exception as e:
            log.warning(f"Falha injetando SK: {e}")
    else:
        log.info("Validator SK não carregada — nó não vai assinar blocos")

    if p2p is not None and trust_net is not None:
        try:
            collector = _make_sign_collector(p2p, trust_net)
            chain.set_sign_collector(collector)
            log.info("Coletor de assinaturas P2P configurado")
        except AttributeError:
            chain._sign_collector = _make_sign_collector(p2p, trust_net)
        except Exception as e:
            log.warning(f"Falha configurando coletor: {e}")

    # ---- Sync ----
    sync = None
    if not args.no_sync and p2p is not None:
        try:
            from sync_manager import ChainSyncManager
            sync = ChainSyncManager(chain, chain.db, p2p)
            try: sync.set_sync_mode("full")
            except Exception: pass
            sync.start_sync_loop()
            _register_service("sync", sync)
            log.info("Sync iniciado (full mode)")
        except ImportError as e:
            log.warning("sync_manager indisponível: " + str(e)); sync = None
        except Exception as e:
            log.warning("Falha ao iniciar Sync: " + str(e)); sync = None
    elif args.no_sync:
        log.info("Sync: pulado por --no-sync")

    # ---- ForkGuard ----
    fork_guard_started = False
    if sync is not None or p2p is not None:
        try:
            from fork_guard import get_fork_guard
            fg = get_fork_guard(chain, sync, p2p)
            if fg is not None:
                fg.start()
                _register_service("fork_guard", fg)
                log.info("ForkGuard iniciado")
                fork_guard_started = True
        except Exception as e:
            log.warning("ForkGuard indisponível: " + str(e))

    # ---- Pool ----
    pool = None
    if not args.no_pool and _pool_disponivel():
        try:
            pool = PoolManager(chain)
            _register_service("pool", pool)
            log.info("PoolManager iniciado")
        except Exception as e:
            log.warning("Falha ao iniciar PoolManager: " + str(e)); pool = None
    elif args.no_pool:
        log.info("Pool: desativado")

    # ---- Offramp ----
    offramp = None
    if L2_ENABLED and btc_config is not None and getattr(btc_config, "BTC_WIF", "").strip():
        try:
            log.info("Iniciando OfframpManager (BRN -> BTC)...")
            btc_sender = BTCSender(btc_config.BTC_WIF, network=btc_config.BTC_NETWORK)
            offramp = OfframpManager(
                db=chain.db, blockchain=chain, btc_sender=btc_sender,
                rate_brn_per_btc=btc_config.BRN_PER_BTC,
                fee_pct=btc_config.FEE_PERCENT,
                min_brn_sats=btc_config.MIN_OFFRAMP_BRN_SATS,
                max_brn_sats=btc_config.MAX_OFFRAMP_BRN_SATS,
                min_btc_sats=btc_config.MIN_OFFRAMP_BTC_SATS,
                ttl_s=btc_config.OFFRAMP_TTL_S,
                treasury_brn=btc_config.BRN_TREASURY_ADDRESS,
            )
            offramp.start()
            _register_service("offramp", offramp)
            log.info("OfframpManager ativado. Cofre BTC: %s", btc_sender.get_address())
        except Exception as e:
            log.error(f"Falha OfframpManager: {e}"); offramp = None
    else:
        log.info("OfframpManager: desativado")

    # ---- HTTP ----
    http_app = _init_http_server(chain, log)
    if http_app is not None:
        threading.Thread(target=_thread_wrap("HTTP", lambda: run_http(http_app)),
                         daemon=True, name="HTTP").start()
    else:
        log.error("HTTP não pôde ser inicializado")

    # ---- Injeções ----
    if p2p is not None: _inject_into_server("p2p", p2p, log)
    else: log.warning("Sem P2PManager")
    if sync is not None: _inject_into_server("sync", sync, log)
    if pool is not None: _inject_into_server("pool", pool, log)
    if trust_net is not None: _inject_into_server("trust", trust_net, log)
    if offramp is not None: _inject_into_server("offramp", offramp, log)

    # ---- Pool Client ----
    disabled_pool_client = args.no_pool_client
    if args.pool_client:
        disabled_pool_client = False
    pool_client = _setup_pool_client_local(chain, pool, log,
                                            disabled=disabled_pool_client,
                                            is_origin=is_origin)
    if pool_client is not None:
        _register_service("pool_client", pool_client)

    # ---- Broadcast ----
    _setup_local_miner_broadcast(chain, p2p, log)

    # ---- Miner ----
    quer_miner_local = bool(args.mine or AUTO_MINE)
    if quer_miner_local and (pool is not None or pool_client is not None):
        log.warning("Miner local IGNORADO: pool/pool_client ativo")
        quer_miner_local = False
    if quer_miner_local:
        try:
            from miner_loop import get_miner
            miner = get_miner(chain)
            wallet_pass = _resolve_wallet_password()
            w = {"address": "", "pubkey": ""}
            try:
                from secure_store import load_current_wallet
                wd = load_current_wallet(wallet_pass)
                if wd.get("ok"):
                    w = {"address": wd.get("address", ""),
                         "pubkey": (wd.get("public_key") or wd.get("pubkey") or wd.get("pub_hex") or "")}
            except Exception as e:
                log.warning("Miner: falha carteira: " + str(e))
            if w.get("address") and w.get("pubkey"):
                ok, msg = miner.start(w["address"], w["pubkey"], is_origin=is_origin)
                log.info(f"Miner auto-start: {msg}")
                _register_service("miner", miner)
            else:
                log.warning("Miner: sem carteira ativa")
        except Exception as e:
            log.warning("Miner local falhou: " + str(e))

    # ---- Status loop ----
    node_id_short = node_pub[:16]
    threading.Thread(target=_thread_wrap("StatusLoop",
                     lambda: run_status_loop(chain, p2p, sync, pool, pool_client,
                                             trust_net, node_id_short=node_id_short)),
                     daemon=True, name="StatusLoop").start()

    # ---- Aguarda genesis ----
    if not is_origin and chain.db.height() < 0:
        log.info("Aguardando genesis (timeout " + str(CLIENT_BOOT_TIMEOUT) + "s)...")
        t0 = time.time()
        while (chain.db.height() < 0 and (time.time() - t0) < CLIENT_BOOT_TIMEOUT
               and not _shutdown.is_set()):
            time.sleep(1)

    # ---- AUDIT ----
    _audit("node_start", {
        "mode": "origin" if is_origin else "client",
        "height": chain.db.height(),
        "node_id": node_pub[:16],
        "p2p": bool(p2p), "sync": bool(sync), "pool": bool(pool),
        "trust": bool(trust_net), "offramp": bool(offramp),
    })

    log.info("Nó pronto. Ctrl+C para encerrar.")

    # ---- Loop ----
    try:
        if not cfg["headless"]:
            log.info("Abrindo carteira desktop (pywebview)...")
            gui_ok = run_wallet_main_thread()
            if not gui_ok:
                log.warning("GUI falhou — caindo para headless")
                while not _shutdown.is_set(): time.sleep(1)
        else:
            log.info("Modo headless. Ctrl+C para encerrar.")
            while not _shutdown.is_set(): time.sleep(1)
    except KeyboardInterrupt:
        log.info("Encerrando por Ctrl+C...")

    # ---- Shutdown ----
    log.info("Encerrando...")
    _shutdown.set()
    _graceful_shutdown(log, trust_net)
    try: chain.db.close()
    except Exception: pass
    try: del node_password
    except Exception: pass
    return 0


_signal_count = 0

def _on_signal(signum, frame):
    global _signal_count
    _signal_count += 1
    if _signal_count >= 2:
        print("\n[!] Forçando saída.", file=sys.stderr)
        os._exit(1)
    _shutdown.set()


if __name__ == "__main__":
    signal.signal(signal.SIGINT,  _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _on_signal)
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        try:
            log = get_logger("main")
            log.exception("Erro fatal: " + str(e))
            try: _graceful_shutdown(log)
            except Exception: pass
        except Exception:
            print("Erro fatal: " + str(e), file=sys.stderr)
        sys.exit(1)