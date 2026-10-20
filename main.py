"""main.py — Entrypoint unificado do nó BRN (v13.6.1)
================================================================
v13.6.1 (2026-10-20):
  [SECURITY CRÍTICO] Removidos _HARDCODED_DEFAULTS sensíveis
                     (BRN_NODE_PASSWORD, BRN_NETWORK_SECRET,
                     BRN_WALLET_SESSION_PASS, BRN_WEB_PASS).
                     Agora FALHA FECHADO se faltarem — antes qualquer
                     clone do repo decifrava current_wallet.enc com
                     "senha-forte-da-carteira-2026".
  [FIX] _l2_disponivel() retornava módulo (truthy). Agora bool().
  [FIX] _inject_into_server silenciava ImportError. Agora loga warning.
  [FIX CRÍTICO] chain.is_origin = is_origin após criar chain.
        server.py v9.9.12 lê esse atributo em /api/miner/start
        para passar is_origin ao miner. Sem isso, --client-mode
        ficava sem efeito no miner via HTTP.
  [FIX] miner.start(..., is_origin=is_origin) explícito. Antes
        dependia da env var BRN_IS_ORIGIN (bug).
  [NEW] Heartbeat em peers.json dentro do run_status_loop (a cada 60s).
        update_peers.py v3 nunca era chamado — o arquivo peers.json
        ficava estático desde o boot. Timeout isolado.
v13.6:
  [NEW] --pool-client e --no-pool-client.
v13.5:
  [FIX] PoolClient importável independente de PoolManager.
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


# ============================================================
# [SECURITY v13.6.1] APENAS defaults NÃO-SENSÍVEIS
# ============================================================
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
try:
    import btc_config
    from btc_watcher import BTCWatcher
    from l2_manager import L2Manager
    L2_ENABLED = True
    print("[L2] Módulos BTC carregados OK")
except Exception as _e:
    print("[AVISO] btc_watcher/l2_manager indisponível: " + str(_e))


def _l2_disponivel() -> bool:
    # [FIX v13.6.1] Retornava módulo (truthy). Agora bool() real.
    return bool(
        L2_ENABLED
        and btc_config is not None
        and BTCWatcher is not None
        and L2Manager is not None
    )


# ============================================================
# POOL
# ============================================================
POOL_ENABLED = os.environ.get("BRN_POOL_ENABLED", "1") == "1"
PoolManager = None
PoolClient = None

# [v13.5] PoolClient é importado independente de POOL_ENABLED
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
# AUDIT / TAILSCALE / ARGS
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
    p.add_argument("--pool-stats", action="store_true")
    p.add_argument("--gui", action="store_true")
    p.add_argument("--no-gui", action="store_true")
    p.add_argument("--pool-client", action="store_true")
    p.add_argument("--no-pool-client", action="store_true")
    return p.parse_args()


# ============================================================
# [SECURITY v13.6.1] VALIDAÇÃO DE SEGREDOS — FALHA FECHADO
# ============================================================
def _validate_required_secrets(log, is_origin: bool, wants_mining: bool) -> bool:
    critical = {
        "BRN_NODE_PASSWORD": "senha da identidade Ed25519 do nó",
        "BRN_NETWORK_SECRET": "segredo HMAC da rede P2P",
    }
    if wants_mining:
        critical["BRN_WALLET_SESSION_PASS"] = "senha da carteira local (para minerar)"

    missing = []
    for k, desc in critical.items():
        val = os.environ.get(k, "").strip()
        if not val or val in (
            "senha-no-temp-123", "senha-temp-123",
            "senha-forte-da-carteira-2026",
            "9226edea8ba62bc1c6ae36883c0536c95b4c85642195465d6c4d9456abef20f9",
        ):
            missing.append(f"  - {k}  ({desc})")

    if not missing:
        return True

    log.error("=" * 64)
    log.error(" SEGREDOS OBRIGATÓRIOS AUSENTES OU FRACOS")
    log.error("=" * 64)
    for m in missing:
        log.error(m)
    log.error("")
    log.error(" O nó NÃO VAI INICIAR sem esses segredos.")
    log.error("")
    log.error(" Crie 'brn_network.env' em:")
    log.error("   " + str(BASE_DIR / "brn_network.env"))
    log.error("")
    log.error(" Com o conteúdo (substitua pelos seus valores):")
    log.error("   BRN_NODE_PASSWORD=<string-aleatória-forte>")
    log.error("   BRN_NETWORK_SECRET=<64-hex-aleatórios>")
    if wants_mining:
        log.error("   BRN_WALLET_SESSION_PASS=<string-aleatória-forte>")
    log.error("")
    log.error(" Gere valores com:")
    log.error("   python -c \"import secrets;print(secrets.token_hex(32))\"")
    log.error("=" * 64)
    return False


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


# ============================================================
# IDENTIDADE + A/B TEST
# ============================================================
def load_or_create_node_identity(password: str, rotate: bool = False):
    from crypto import Ed25519PrivateKey
    from secure_store import save_wallet, load_wallet
    log = get_logger("identity")

    if rotate and NODE_ID_PATH.exists():
        NODE_ID_PATH.replace(NODE_ID_PATH.with_suffix(".enc.bak"))

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
        log.info("Identidade nova criada: " + pub_hex[:16] + "...")

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


VERIFY_OK, VERIFY_INVALID, VERIFY_ERROR = "ok", "invalid", "error"


def _verify_chain(chain) -> str:
    try:
        from chain_validator import verify_chain
    except ImportError:
        return VERIFY_ERROR
    log = get_logger("verify")
    try:
        r = verify_chain(chain)
        valid = getattr(r, "valid", bool(r))
        if valid:
            return VERIFY_OK
        return VERIFY_INVALID
    except Exception:
        return VERIFY_ERROR


def _inject_into_server(what: str, obj, log) -> bool:
    setter_name = {
        "p2p": "set_p2p_manager",
        "sync": "set_sync_manager",
        "pool": "set_pool_manager",
        "trust": "set_trust_network",
    }.get(what)
    if setter_name is None:
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
        # [FIX v13.6.1] Loga ImportError (antes silenciava)
        log.warning(f"[inject] server.py indisponível ({what}): {e}")
        return False
    except Exception as e:
        log.warning(f"[inject] {what} falhou: {e}")
        return False


def _init_http_server(chain, log):
    try:
        from server import app as http_app, set_chain, auto_registrar_carteira_atual
    except Exception as e:
        log.error("Falha importando server.py: " + str(e))
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
    ssl_ctx = None
    if os.environ.get("BRN_HTTPS", "0") == "1":
        try:
            from security import ensure_self_signed_cert
            cert, key = ensure_self_signed_cert()
            ssl_ctx = (cert, key)
        except Exception:
            ssl_ctx = None
    log.info("HTTP http://" + WEB_HOST + ":" + str(port))
    app_instance.run(
        host=WEB_HOST, port=port, threaded=True,
        debug=False, use_reloader=False, ssl_context=ssl_ctx,
    )


def run_explorer():
    from explorer import app as explorer_app
    log = get_logger("explorer")
    port = int(os.environ.get("BRN_EXPLORER_PORT", "8080"))
    ssl_ctx = None
    log.info("Explorer http://" + EXPLORER_HOST + ":" + str(port))
    explorer_app.run(
        host=EXPLORER_HOST, port=port, threaded=True,
        debug=False, use_reloader=False, ssl_context=ssl_ctx,
    )


# ============================================================
# STATUS LOOP — [NEW v13.6.1] heartbeat em peers.json
# ============================================================
def run_status_loop(chain, p2p, sync=None, pool=None, pool_client=None,
                    trust_net=None, node_id_short=""):
    log = get_logger("status")

    # [NEW v13.6.1] Heartbeat em peers.json a cada 60s
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
            if pool_client:
                try:
                    pcs = pool_client.status()
                    if pcs.get("running"):
                        msg += (" PoolClient["
                                + str(round(pcs.get("hashrate_khs", 0), 1))
                                + " kH/s]")
                except Exception:
                    pass
            if trust_net:
                try:
                    ts = trust_net.get_network_stats()
                    msg += " Trust[Nodes=" + str(ts.get("total_nodes", 0)) + "]"
                except Exception:
                    pass
            log.info(msg)

            # [NEW v13.6.1] Heartbeat em peers.json
            agora = time.time()
            if agora - last_peers_hb >= PEERS_HB_INTERVAL:
                last_peers_hb = agora
                try:
                    from update_peers import update_local_timestamp
                    update_local_timestamp(
                        height=chain.db.height(),
                        node_id=node_id_short or "",
                    )
                except TimeoutError as _te:
                    log.warning("update_peers: lock timeout (" + str(_te) + ")")
                except RuntimeError as _re:
                    if not _already_warned_no_endereco[0]:
                        _already_warned_no_endereco[0] = True
                        log.info("update_peers: " + str(_re))
                except Exception as _ue:
                    log.debug("update_peers falhou: " + str(_ue))

        except Exception as e:
            log.warning("status loop: " + str(e))


def run_wallet_main_thread():
    try:
        if not os.environ.get("BRN_WEB_PASS"):
            return
        from app_wallet_v3 import WalletApi
        import webview
        api = WalletApi()
        webview.create_window(
            "BRN RWA — Carteira Digital",
            url=(BASE_DIR / "index_wallet.html").resolve().as_uri(),
            js_api=api, width=1020, height=880,
        )
        webview.start(debug=False)
    except Exception as e:
        get_logger("wallet").error("Falha: " + str(e))


# ============================================================
# POOL CLIENT
# ============================================================
def _setup_pool_client_local(chain, pool, log, disabled: bool, is_origin_node: bool):
    if disabled:
        return None
    if PoolClient is None:
        return None

    wallet_pass = _resolve_wallet_password()
    if not wallet_pass:
        return None

    addr, pub = "", ""
    try:
        from secure_store import load_current_wallet
        w = load_current_wallet(wallet_pass)
        if w and w.get("ok"):
            addr = (w.get("address") or "").strip()
            pub = (w.get("public_key") or w.get("pub_hex")
                   or w.get("pubkey") or "").strip()
    except Exception as e:
        log.warning("PoolClient: falha lendo current_wallet: " + str(e))

    if not addr.startswith("brn1") or not pub:
        return None

    if is_origin_node:
        pool_url = os.environ.get("BRN_POOL_URL_LOCAL", "http://127.0.0.1:5000")
    else:
        pool_url = os.environ.get("BRN_POOL_URL",
                                   os.environ.get("BRN_POOL_URL_LOCAL",
                                                  "http://127.0.0.1:5000"))

    try:
        pc = PoolClient(addr, pub, pool_url=pool_url)
        ok, msg = pc.start_mining()
        if not ok:
            log.warning("PoolClient: start_mining falhou: " + str(msg))
            return None
        log.info("PoolClient iniciado (is_origin=" + str(is_origin_node)
                 + " pool=" + pool_url + ")")
        return pc
    except Exception as e:
        log.warning("PoolClient: exceção: " + str(e))
        return None


def _setup_local_miner_broadcast(chain, p2p, log):
    if p2p is None:
        return False
    try:
        def _on_local_block(block):
            try:
                p2p.broadcast_block(block)
            except Exception:
                pass
        chain.on_block_mined = _on_local_block
        return True
    except Exception:
        return False


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
        t = threading.Thread(target=fn, daemon=True)
        t.start()
        t.join(timeout)
    except Exception:
        pass


def _graceful_shutdown(log, trust_net=None) -> None:
    with _services_lock:
        services = list(_running_services)
    for name, svc in reversed(services):
        _stop_with_timeout(name, svc)
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
        except Exception:
            pass
    _audit("node_stop", {})
    _close_audit()


# ============================================================
# MAIN
# ============================================================
def main():
    args = parse_args()
    cfg = Config(args.config)

    if args.read_only:
        cfg.data["read_only"] = True
    if args.headless or args.no_gui:
        cfg.data["headless"] = True
    if args.gui:
        cfg.data["headless"] = False
    if args.log_level:
        cfg.data["log_level"] = args.log_level
    if args.log_file:
        cfg.data["log_file"] = args.log_file

    cfg.apply_to_env()
    log = setup_logger(level=cfg["log_level"],
                       log_file=cfg["log_file"] or None)
    is_origin = _is_origin(args.client_mode)

    log.info("=" * 60)
    log.info(" BRN Node v" + VERSION + " (" + BUILD_DATE + ")")
    log.info(" Modo: " + ("ORIGEM" if is_origin else "CLIENTE"))
    log.info("=" * 60)

    if args.version:
        print(VERSION)
        return 0
    if args.status:
        print(f"BRN Node v{VERSION} | Modo: {'ORIGEM' if is_origin else 'CLIENTE'}")
        return 0

    missing = _check_required_modules()
    if missing:
        log.error("Módulos faltando: " + ", ".join(missing))
        return 1

    # [SECURITY v13.6.1] Segredos — FALHA FECHADO
    wants_mining = bool(args.mine or AUTO_MINE or (not args.no_pool))
    if not _validate_required_secrets(log, is_origin, wants_mining):
        return 1

    if not args.no_tailscale:
        _setup_tailscale_auto(log)

    try:
        node_password = _resolve_password(args)
    except SystemExit as e:
        log.error(str(e))
        return 1

    try:
        node_sk, node_pub = load_or_create_node_identity(
            node_password, rotate=args.rotate_node_id)
    except SystemExit as e:
        log.error(str(e))
        return 1
    except Exception as e:
        log.exception("Falha identidade")
        return 1

    log.info("Nó ID: " + node_pub[:16] + "...")

    from blockchain import Blockchain
    chain = Blockchain(
        cfg["db_path"],
        auto_genesis=is_origin,
        network_secret=cfg["network_secret"],
    )
    chain._fork_signal = threading.Event()

    # [FIX v13.6.1] server.py v9.9.12 lê chain.is_origin em /api/miner/start
    chain.is_origin = is_origin

    log.info("Blockchain pronta (altura=" + str(chain.db.height()) + ")")

    trust_net = None
    if _HAS_TRUST:
        try:
            trust_net = TrustNetwork(str(BASE_DIR / "trust_network.json"))
            chain.trust_net = trust_net
        except Exception:
            pass

    if not args.skip_verify and os.environ.get("BRN_SKIP_VERIFY", "0") != "1":
        strict = os.environ.get("BRN_VERIFY_STRICT", "0") == "1"
        st = _verify_chain(chain)
        if st == VERIFY_INVALID and strict:
            return 2

    p2p = None
    if not args.no_p2p:
        try:
            from p2p_unified import P2PManager
            p2p = P2PManager(
                chain, node_sk,
                tcp_port=cfg["p2p_port"],
                enable_upnp=cfg["upnp"],
            )
            p2p.start()
            _register_service("p2p", p2p)
        except Exception as e:
            log.error("P2P falhou: " + str(e))

    sync = None
    if not args.no_sync and p2p is not None:
        try:
            from sync_manager import ChainSyncManager
            sync = ChainSyncManager(chain, chain.db, p2p)
            sync.set_sync_mode("full")
            sync.start_sync_loop()
            _register_service("sync", sync)
        except Exception:
            pass

    pool = None
    if not args.no_pool and _pool_disponivel():
        try:
            pool = PoolManager(chain)
            _register_service("pool", pool)
        except Exception:
            pass

    http_app = _init_http_server(chain, log)
    if http_app:
        threading.Thread(
            target=_thread_wrap("HTTP", lambda: run_http(http_app)),
            daemon=True,
        ).start()

    if p2p:
        _inject_into_server("p2p", p2p, log)
    if sync:
        _inject_into_server("sync", sync, log)
    if pool:
        _inject_into_server("pool", pool, log)
    if trust_net:
        _inject_into_server("trust", trust_net, log)

    # [v13.6] --pool-client força enable, --no-pool-client força disable
    disabled_pool_client = args.no_pool_client
    if args.pool_client:
        disabled_pool_client = False

    pool_client = _setup_pool_client_local(
        chain, pool, log,
        disabled=disabled_pool_client,
        is_origin_node=is_origin,
    )
    if pool_client:
        _register_service("pool_client", pool_client)

    _setup_local_miner_broadcast(chain, p2p, log)

    quer_miner_local = bool(args.mine or AUTO_MINE)
    if quer_miner_local and (pool is not None or pool_client is not None):
        log.warning("Miner local IGNORADO: pool/pool_client está ativo.")
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
                    w = {
                        "address": wd.get("address", ""),
                        "pubkey": (wd.get("public_key")
                                   or wd.get("pubkey")
                                   or wd.get("pub_hex")
                                   or ""),
                    }
            except Exception:
                pass

            if w["address"] and w["pubkey"]:
                # [FIX v13.6.1] Passa is_origin explícito
                ok, msg = miner.start(
                    w["address"], w["pubkey"],
                    is_origin=is_origin,
                )
                log.info(f"Miner auto-start: {msg}")
                _register_service("miner", miner)
            else:
                log.warning("Miner: sem carteira ativa para minerar.")
        except Exception as e:
            log.warning("Miner local falhou: " + str(e))

    # [FIX v13.6.1] Status loop recebe node_id_short para heartbeat
    node_id_short = node_pub[:16]
    threading.Thread(
        target=_thread_wrap(
            "StatusLoop",
            lambda: run_status_loop(
                chain, p2p, sync, pool, pool_client, trust_net,
                node_id_short=node_id_short,
            ),
        ),
        daemon=True,
    ).start()

    if not is_origin and chain.db.height() < 0:
        log.info("Aguardando genesis...")
        t0 = time.time()
        while (chain.db.height() < 0
               and (time.time() - t0) < CLIENT_BOOT_TIMEOUT
               and not _shutdown.is_set()):
            time.sleep(1)

    _audit("node_start", {
        "mode": "origin" if is_origin else "client",
        "height": chain.db.height(),
        "p2p": bool(p2p),
        "sync": bool(sync),
        "pool": bool(pool),
        "pool_client": bool(pool_client),
        "miner": bool(quer_miner_local),
    })
    log.info("Nó pronto. Ctrl+C para encerrar.")

    try:
        if not cfg["headless"]:
            run_wallet_main_thread()
        else:
            while not _shutdown.is_set():
                time.sleep(1)
    except KeyboardInterrupt:
        pass

    _shutdown.set()
    _graceful_shutdown(log, trust_net)
    try:
        chain.db.close()
    except Exception:
        pass
    return 0


_signal_count = 0


def _on_signal(signum, frame):
    global _signal_count
    _signal_count += 1
    if _signal_count >= 2:
        os._exit(1)
    _shutdown.set()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        try:
            get_logger("main").exception("Erro fatal: " + str(e))
        except Exception:
            print("Erro fatal: " + str(e), file=sys.stderr)
        sys.exit(1)
