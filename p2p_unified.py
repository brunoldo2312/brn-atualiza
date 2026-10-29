"""p2p_unified.py — BRN P2P Network v6.7.4
================================================================
v6.7.4 (2026-10-29):
  [NEW] Propagação de checkpoints multi-sig via P2P.
================================================================
"""
from __future__ import annotations

import os
import json
import time
import uuid
import socket
import hashlib
import logging
import threading
import urllib.request
import urllib.error
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from typing import Optional

log = logging.getLogger("p2p")

from p2p_auth import (
    auth_enabled, auth_required, build_auth, verify_auth,
    set_node_id_priv as _auth_set_priv,
)

try:
    from blockchain import block_hash, meets_difficulty, compute_merkle_root
    _HAS_BLOCKCHAIN_HELPERS = True
except ImportError:
    _HAS_BLOCKCHAIN_HELPERS = False
    block_hash = meets_difficulty = compute_merkle_root = None

try:
    from discovery_v2 import TOKEN as TOKEN_ESPERADO
except ImportError:
    _secret = os.environ.get("BRN_NETWORK_SECRET")
    if not _secret:
        raise RuntimeError("BRN_NETWORK_SECRET obrigatório")
    import hmac as _hmac
    TOKEN_ESPERADO = _hmac.new(_secret.encode(), b"brn-p2p-v1", hashlib.sha256).hexdigest()

MULTICAST_GROUP  = "239.255.42.99"
MULTICAST_PORT   = 50007
TCP_PORT_DEFAULT = 6001

DISCOVERY_INTERVAL_MIN = 2.0
DISCOVERY_INTERVAL_MAX = 30.0
PEER_TIMEOUT           = 60
PEER_CLEANUP_S         = 30
MAX_MSG_SIZE           = 8 * 1024 * 1024

PROTOCOL_VERSION = "BRN5/2.4-MultiSig+Checkpoint"
NETWORK_MAGIC    = b"BRN5"
CHAIN_ID         = os.environ.get("BRN_CHAIN_ID", "mainnet").strip()

PEER_SCORE_BAN_THRESHOLD = -100
PEER_SCORE_REWARD_GOOD   = 10
PEER_SCORE_PENALTY_BAD   = -50
RATE_LIMIT_MSGS_PER_SEC  = int(os.environ.get("BRN_RATE_LIMIT", "200"))
MAX_CONNECTIONS_PER_IP   = int(os.environ.get("BRN_MAX_CONNS_PER_IP", "5"))

MAX_DISCOVERED_PEERS = 500
MAX_PEERS_PER_PEX    = 50
HEIGHT_CACHE_TTL     = 120

PEERS_FILE     = "peers_discovered.json"
BOOTSTRAP_FILE = "bootstrap_peers.json"
BOOTSTRAP_ENV  = os.environ.get("BRN_BOOTSTRAP_PEERS", "")

BOOTSTRAP_PING_INTERVAL = 60

READ_ONLY              = os.environ.get("BRN_READ_ONLY", "0") == "1"
SYNC_BATCH_SIZE        = int(os.environ.get("BRN_SYNC_BATCH", "50"))
TCP_TIMEOUT_DEFAULT    = float(os.environ.get("BRN_TCP_TIMEOUT", "10.0"))
BLOCK_SIG_TIMEOUT_S    = float(os.environ.get("BRN_BLOCK_SIG_TIMEOUT", "5.0"))
CHECKPOINT_BATCH       = int(os.environ.get("BRN_CHECKPOINT_BATCH", "50"))


def _obter_ou_criar_uuid() -> str:
    port = os.environ.get("BRN_P2P_PORT", str(TCP_PORT_DEFAULT))
    uuid_file = f"node_uuid_{port}.txt"
    if os.path.exists(uuid_file):
        try:
            with open(uuid_file) as f:
                val = f.read().strip()
                if val:
                    return val
        except Exception:
            pass
    novo = str(uuid.uuid4())
    try:
        with open(uuid_file, "w") as f:
            f.write(novo)
    except Exception:
        pass
    return novo


def _get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _mesma_subnet(ip1: str, ip2: str) -> bool:
    try:
        return ip1.rsplit(".", 1)[0] == ip2.rsplit(".", 1)[0]
    except Exception:
        return False


def _carregar_bootstrap() -> set[str]:
    peers = set()
    if os.path.exists(BOOTSTRAP_FILE):
        try:
            with open(BOOTSTRAP_FILE) as f:
                data = json.load(f)
                if isinstance(data, list):
                    for p in data:
                        p = str(p).strip()
                        if p:
                            peers.add(p)
        except Exception:
            pass
    for p in BOOTSTRAP_ENV.split(","):
        p = p.strip()
        if p:
            peers.add(p)
    return peers


def _registrar_peer_no_db(blockchain, ip: str, port: int, peer_id: Optional[str] = None) -> None:
    if blockchain is None:
        return
    try:
        addr = f"{ip}:{port}"
        genesis = blockchain.db.get_meta("genesis_hash") or ""
        node_id = peer_id or f"peer-{ip}:{port}"
        blockchain.db.upsert_peer(
            node_id=node_id, address=addr, genesis_hash=genesis,
            version=PROTOCOL_VERSION, height=0, is_miner=False,
            public_key=peer_id or "",
        )
    except Exception:
        pass


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.start_time = time.time()
        self.data = {
            "messages_in": 0, "messages_out": 0,
            "bytes_in": 0, "bytes_out": 0,
            "blocks_accepted": 0, "blocks_rejected": 0,
            "block_sigs_requested": 0,
            "block_sigs_provided": 0,
            "block_sigs_invalid": 0,
            "checkpoints_broadcast": 0,
            "checkpoints_received": 0,
            "checkpoints_rejected": 0,
            "auth_ok": 0, "auth_failed": 0,
            "forks_detected": 0,
        }
        self.peer_metrics = defaultdict(lambda: {
            "last_seen": 0, "latency_ms": 0.0, "errors": 0,
        })

    def inc(self, key: str, n: int = 1) -> None:
        with self._lock:
            if key in self.data:
                self.data[key] += n

    def set(self, key: str, val) -> None:
        with self._lock:
            self.data[key] = val

    def peer_update(self, addr: str, **kwargs) -> None:
        with self._lock:
            for k, v in kwargs.items():
                if k in self.peer_metrics[addr]:
                    self.peer_metrics[addr][k] = v
            self.peer_metrics[addr]["last_seen"] = time.time()

    def snapshot(self) -> dict:
        with self._lock:
            d = dict(self.data)
            d["uptime_s"] = round(time.time() - self.start_time, 1)
            d["peers_tracked"] = len(self.peer_metrics)
            return d


# ============================================================
# SERVIDOR TCP
# ============================================================
class P2PServer(threading.Thread):
    def __init__(self, blockchain, port: int, metrics: Metrics,
                 on_new_block=None, on_new_tx=None, on_peer_bad=None,
                 on_peer_good=None, get_peers_callback=None):
        super().__init__(daemon=True, name="P2P-Server")
        self.bc = blockchain
        self.port = port
        self.metrics = metrics
        self.on_new_block = on_new_block
        self.on_new_tx = on_new_tx
        self.on_peer_bad = on_peer_bad
        self.on_peer_good = on_peer_good
        self.get_peers_callback = get_peers_callback

        self.node_uuid = ""
        self.running = False
        self.sock = None
        self._rate_counters = {}
        self._rate_lock = threading.Lock()
        self._active_conns_by_ip = defaultdict(int)

    def stop(self) -> None:
        self.running = False
        if self.sock:
            try: self.sock.close()
            except Exception: pass

    def _check_rate(self, addr: str) -> bool:
        agora = time.time()
        with self._rate_lock:
            janela = self._rate_counters.setdefault(addr, [])
            janela[:] = [t for t in janela if agora - t < 1.0]
            if len(janela) >= RATE_LIMIT_MSGS_PER_SEC:
                return False
            janela.append(agora)
            return True

    def _recv_message(self, conn: socket.socket, timeout: float = 30.0):
        conn.settimeout(timeout)
        raw = b""
        first = True
        while True:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                if first: return None
                first = False
                continue
            first = False
            if not chunk: break
            raw += chunk
            if len(raw) > MAX_MSG_SIZE: return None
            if raw.startswith(NETWORK_MAGIC):
                try:
                    json.loads(raw[len(NETWORK_MAGIC):].decode())
                    break
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
        return raw

    def run(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("0.0.0.0", self.port))
            self.sock.listen(20)
            log.info(f"Servidor TCP escutando na porta {self.port}")
            self.running = True
        except Exception as e:
            log.error(f"Erro abrindo porta {self.port}: {e}")
            return
        while self.running:
            try:
                self.sock.settimeout(1.0)
                conn, addr = self.sock.accept()
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log.error(f"accept: {e}")

    def _handle_conn(self, conn: socket.socket, addr) -> None:
        peer_ip = addr[0]
        peer_id = None

        with self._rate_lock:
            self._active_conns_by_ip[peer_ip] += 1
            if self._active_conns_by_ip[peer_ip] > MAX_CONNECTIONS_PER_IP:
                self._active_conns_by_ip[peer_ip] -= 1
                log.warning(f"[SECURITY] Limite conexões excedido para {peer_ip}")
                try: conn.close()
                except: pass
                return

        try:
            if not self._check_rate(peer_ip): return
            score = self.bc.db.get_peer_score(peer_ip)
            if score <= PEER_SCORE_BAN_THRESHOLD: return

            raw = self._recv_message(conn, timeout=30.0)
            if not raw or not raw.startswith(NETWORK_MAGIC): return

            self.metrics.inc("messages_in")
            self.metrics.inc("bytes_in", len(raw))
            msg = json.loads(raw[len(NETWORK_MAGIC):].decode())

            if msg.get("_chain") != CHAIN_ID: return

            _auth = msg.pop("_auth", None)
            if auth_enabled():
                if _auth:
                    ok, err = verify_auth(_auth, msg=msg)
                    if not ok:
                        self.metrics.inc("auth_failed")
                        return
                    peer_id = _auth.get("pub", "")[:64] or None
                    self.metrics.inc("auth_ok")
                elif auth_required():
                    self.metrics.inc("auth_failed")
                    return

            _registrar_peer_no_db(self.bc, peer_ip, int(msg.get("_port", 6001)), peer_id=peer_id)

            response = self._process_message(msg, addr, peer_id)
            if response:
                response["_chain"] = CHAIN_ID
                response["_uuid"] = self.node_uuid
                if auth_enabled():
                    try:
                        resp_sem = {k: v for k, v in response.items() if k != "_auth"}
                        response["_auth"] = build_auth(msg=resp_sem)
                    except Exception:
                        pass
                payload = NETWORK_MAGIC + json.dumps(response).encode()
                conn.sendall(payload)
                self.metrics.inc("messages_out")
                self.metrics.inc("bytes_out", len(payload))
        except Exception as e:
            log.warning(f"erro com {addr}: {e}")
        finally:
            with self._rate_lock:
                self._active_conns_by_ip[peer_ip] -= 1
            try: conn.close()
            except Exception: pass

    def _handle_sign_block(self, msg: dict, addr, peer_id) -> dict:
        block = msg.get("block")
        if not block or not isinstance(block, dict):
            return {"type": "sign_block_response", "pubkey": "", "signature": ""}

        trust = getattr(self.bc, "trust_net", None)
        local_sk = getattr(self.bc, "_local_validator_sk", None)

        if trust is None or local_sk is None:
            return {"type": "sign_block_response", "pubkey": "", "signature": ""}

        try:
            from wallet import Wallet
            from blockchain import block_hash as _bh, sign_block_as_validator

            if not isinstance(local_sk, Wallet):
                local_sk = Wallet(private_key_hex=str(local_sk))
            my_pub = local_sk.pub_hex

            validators = trust.get_top_validators(count=5)
            if my_pub not in validators:
                return {"type": "sign_block_response", "pubkey": "", "signature": ""}

            try:
                h_calc = _bh(block["prev_hash"], block["merkle"], block["timestamp"], block["nonce"], block["difficulty"])
                if h_calc != block["hash"]:
                    self.metrics.inc("block_sigs_invalid")
                    return {"type": "sign_block_response", "pubkey": "", "signature": ""}
            except KeyError:
                return {"type": "sign_block_response", "pubkey": "", "signature": ""}

            entry = sign_block_as_validator(block, local_sk)
            if not entry:
                return {"type": "sign_block_response", "pubkey": "", "signature": ""}

            self.metrics.inc("block_sigs_provided")
            return {"type": "sign_block_response", "pubkey": entry["pubkey"], "signature": entry["signature"]}
        except Exception:
            return {"type": "sign_block_response", "pubkey": "", "signature": ""}

    def _handle_get_checkpoints(self, msg: dict) -> dict:
        try:
            from checkpoints import load_checkpoints
        except ImportError:
            return {"type": "checkpoints", "checkpoints": {}}

        start = int(msg.get("start", 0))
        end = int(msg.get("end", start + CHECKPOINT_BATCH))
        end = min(end, start + CHECKPOINT_BATCH * 2)

        all_cps = load_checkpoints()
        filtered = {}
        for h_str, cp in all_cps.items():
            try:
                h = int(h_str)
                if start <= h <= end:
                    filtered[h_str] = cp
            except (ValueError, TypeError):
                continue
        return {"type": "checkpoints", "checkpoints": filtered}

    def _handle_new_checkpoint(self, msg: dict) -> dict:
        cp = msg.get("checkpoint")
        if not isinstance(cp, dict):
            return {"type": "ack", "ok": False}

        height = cp.get("height")
        if not isinstance(height, int):
            return {"type": "ack", "ok": False}

        try:
            from checkpoints import load_checkpoints, save_checkpoints, verify_checkpoint
        except ImportError:
            return {"type": "ack", "ok": False}

        if not verify_checkpoint(cp):
            self.metrics.inc("checkpoints_rejected")
            return {"type": "ack", "ok": False, "reason": "assinatura invalida"}

        local_block = self.bc.db.get_block(height)
        if local_block and local_block["hash"] != cp.get("hash"):
            self.metrics.inc("checkpoints_rejected")
            log.warning("[P2P] checkpoint #%d REJEITADO: hash mismatch", height)
            return {"type": "ack", "ok": False, "reason": "hash mismatch"}

        existing = load_checkpoints()
        if str(height) in existing:
            return {"type": "ack", "ok": True, "reason": "ja existe"}

        existing[str(height)] = cp
        if save_checkpoints(existing):
            self.metrics.inc("checkpoints_received")
            log.info("[P2P] checkpoint #%d recebido e salvo", height)
            try:
                from blockchain import set_checkpoints
                set_checkpoints(existing)
            except Exception:
                pass
            return {"type": "ack", "ok": True}
        return {"type": "ack", "ok": False}

    def _process_message(self, msg: dict, addr, peer_id: Optional[str]) -> Optional[dict]:
        mtype = msg.get("type")
        peer_ip = addr[0]
        try:
            if mtype == "ping":
                return {"type": "pong", "version": PROTOCOL_VERSION, "height": self.bc.db.height(), "work": self.bc.cumulative_work()}
            if mtype == "get_chain_height":
                return {"type": "chain_height", "height": self.bc.db.height(), "hash": self.bc.db.tip_hash(), "work": self.bc.cumulative_work()}
            if mtype == "get_block":
                return {"type": "block", "block": self.bc.db.get_block(int(msg.get("height", 0)))}
            if mtype == "get_blocks_range":
                start = int(msg.get("start", 0))
                end = min(int(msg.get("end", start + 50)), start + SYNC_BATCH_SIZE)
                return {"type": "blocks_range", "blocks": self.bc.db.get_blocks_range(start, end)}
            if mtype == "new_block":
                if READ_ONLY: return {"type": "ack", "ok": False, "reason": "read_only"}
                block_dict = msg.get("block")
                if block_dict and self.on_new_block:
                    ok = self.on_new_block(block_dict)
                    if ok and self.on_peer_good: self.on_peer_good(peer_ip, peer_id)
                    elif not ok and self.on_peer_bad: self.on_peer_bad(peer_ip, peer_id)
                    return {"type": "ack", "ok": bool(ok)}
                return {"type": "ack", "ok": False}
            if mtype == "new_tx":
                if READ_ONLY: return {"type": "ack", "ok": False}
                tx_dict = msg.get("tx")
                if tx_dict and self.on_new_tx:
                    ok = self.on_new_tx(tx_dict)
                    if ok and self.on_peer_good: self.on_peer_good(peer_ip, peer_id)
                    return {"type": "ack", "ok": bool(ok)}
                return {"type": "ack", "ok": False}
            if mtype == "get_mempool":
                return {"type": "mempool", "txs": self.bc.db.all_mempool(limit=200)}
            if mtype == "get_peers":
                peers = []
                if self.get_peers_callback:
                    try: peers = self.get_peers_callback()
                    except Exception: pass
                return {"type": "peers", "peers": peers[:MAX_PEERS_PER_PEX]}
            if mtype == "sign_block":
                self.metrics.inc("block_sigs_requested")
                return self._handle_sign_block(msg, addr, peer_id)
            if mtype == "get_checkpoints":
                return self._handle_get_checkpoints(msg)
            if mtype == "new_checkpoint":
                return self._handle_new_checkpoint(msg)
            if mtype == "announce_validator":
                pub = (msg.get("pubkey") or "").strip()
                addr_v = (msg.get("address") or "").strip()
                if pub and addr_v:
                    try:
                        trust = getattr(self.bc, "trust_net", None)
                        if trust is not None and hasattr(trust, "register_node"):
                            trust.register_node(pub, addr_v, pub)
                    except Exception:
                        pass
                return {"type": "ack", "ok": True}
        except Exception as e:
            return {"type": "error", "message": str(e)}
        return {"type": "error", "message": "Tipo desconhecido"}


# ============================================================
# CLIENTE TCP
# ============================================================
class P2PClient:
    @staticmethod
    def send_message(ip: str, port: int, message: dict, timeout: Optional[float] = None):
        if timeout is None: timeout = TCP_TIMEOUT_DEFAULT
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            t0 = time.time()
            s.connect((ip, port))

            message = dict(message)
            message["_chain"] = CHAIN_ID
            message["_port"] = int(os.environ.get("BRN_P2P_PORT", "6001"))

            if auth_enabled():
                try:
                    msg_sem = {k: v for k, v in message.items() if k != "_auth"}
                    message["_auth"] = build_auth(msg=msg_sem)
                except Exception:
                    pass

            payload = NETWORK_MAGIC + json.dumps(message).encode()
            s.sendall(payload)

            raw = b""
            while True:
                try: chunk = s.recv(65536)
                except socket.timeout: break
                if not chunk: break
                raw += chunk
                if len(raw) > MAX_MSG_SIZE: break
                if raw.startswith(NETWORK_MAGIC):
                    try:
                        json.loads(raw[len(NETWORK_MAGIC):].decode())
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue

            latency_ms = (time.time() - t0) * 1000
            s.close()

            if raw.startswith(NETWORK_MAGIC):
                resp = json.loads(raw[len(NETWORK_MAGIC):].decode())
                if resp.get("_chain") != CHAIN_ID:
                    return None, latency_ms
                if auth_enabled():
                    _rauth = resp.pop("_auth", None)
                    if _rauth:
                        ok, err = verify_auth(_rauth, msg=resp)
                        if not ok: return None, latency_ms
                    elif auth_required(): return None, latency_ms
                return resp, latency_ms
            return None, latency_ms
        except Exception:
            return None, 0.0

    @staticmethod
    def ping(ip, port, timeout=None):
        return P2PClient.send_message(ip, port, {"type": "ping"}, timeout=timeout)

    @staticmethod
    def get_chain_height(ip, port, timeout=None):
        return P2PClient.send_message(ip, port, {"type": "get_chain_height"}, timeout=timeout)

    @staticmethod
    def get_blocks_range(ip, port, s, e, timeout=None):
        return P2PClient.send_message(ip, port, {"type": "get_blocks_range", "start": s, "end": e}, timeout=timeout)

    @staticmethod
    def send_block(ip, port, block, timeout=None):
        return P2PClient.send_message(ip, port, {"type": "new_block", "block": block}, timeout=timeout)

    @staticmethod
    def send_tx(ip, port, tx, timeout=None):
        return P2PClient.send_message(ip, port, {"type": "new_tx", "tx": tx}, timeout=timeout)

    @staticmethod
    def get_peers(ip, port, timeout=None):
        return P2PClient.send_message(ip, port, {"type": "get_peers"}, timeout=timeout)

    @staticmethod
    def announce_validator(ip, port, pubkey, address, timeout=None):
        return P2PClient.send_message(ip, port, {"type": "announce_validator", "pubkey": pubkey, "address": address}, timeout=timeout)

    @staticmethod
    def request_block_signature(ip: str, port: int, block: dict, timeout: Optional[float] = None) -> Optional[dict]:
        if timeout is None: timeout = BLOCK_SIG_TIMEOUT_S
        resp, _ = P2PClient.send_message(ip, port, {"type": "sign_block", "block": block}, timeout=timeout)
        if not resp or resp.get("type") != "sign_block_response":
            return None
        pubkey = (resp.get("pubkey") or "").strip()
        signature = (resp.get("signature") or "").strip()
        if not pubkey or not signature: return None
        return {"pubkey": pubkey, "signature": signature}

    @staticmethod
    def send_checkpoint(ip: str, port: int, cp: dict, timeout: Optional[float] = None):
        return P2PClient.send_message(ip, port, {"type": "new_checkpoint", "checkpoint": cp}, timeout=timeout)

    @staticmethod
    def get_checkpoints(ip: str, port: int, start: int, end: int, timeout: Optional[float] = None):
        return P2PClient.send_message(ip, port, {"type": "get_checkpoints", "start": start, "end": end}, timeout=timeout)


# ============================================================
# DISCOVERY
# ============================================================
class PeerDiscovery:
    def __init__(self, tcp_port: int, node_uuid: str, on_peer_found=None, blockchain=None):
        self.tcp_port = tcp_port
        self.node_uuid = node_uuid
        self.on_peer_found = on_peer_found
        self.bc = blockchain
        self.discovered_peers = {}
        self.peers_lock = threading.Lock()
        self.peers_respondidos = set()
        self.running = False
        self.server_socket = None
        self.client_socket = None
        self._threads = []
        self.uuid_to_addr = {}
        self.uuid_lock = threading.Lock()
        self._height_cache = {}
        self._height_cache_lock = threading.Lock()
        self._carregar_peers()

    def _salvar_peers(self) -> None:
        try:
            with self.peers_lock: lista = list(self.discovered_peers.keys())
            with open(PEERS_FILE, "w") as f: json.dump(lista, f)
        except Exception: pass

    def _carregar_peers(self) -> None:
        try:
            if os.path.exists(PEERS_FILE):
                with open(PEERS_FILE) as f:
                    for addr in json.load(f): self.discovered_peers[addr] = 0
        except Exception: pass
        for p in _carregar_bootstrap(): self.discovered_peers.setdefault(p, 0)

    def _add_peer(self, addr: str, ts: Optional[float] = None) -> bool:
        with self.peers_lock:
            is_new = addr not in self.discovered_peers
            if not is_new:
                if ts is not None: self.discovered_peers[addr] = ts
                return False
            if len(self.discovered_peers) >= MAX_DISCOVERED_PEERS:
                try:
                    oldest = min(self.discovered_peers.items(), key=lambda kv: kv[1])
                    del self.discovered_peers[oldest[0]]
                except ValueError: pass
            self.discovered_peers[addr] = ts if ts is not None else time.time()
            return True

    def register_uuid(self, uuid_hex: str, ip: str, port: int) -> None:
        if not uuid_hex or not ip: return
        with self.uuid_lock: self.uuid_to_addr[uuid_hex] = (ip, int(port), time.time())

    def _start_server(self) -> None:
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError): pass
            self.server_socket.bind(("", MULTICAST_PORT))
            mreq = socket.inet_aton(MULTICAST_GROUP) + socket.inet_aton("0.0.0.0")
            self.server_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            local_ip = _get_local_ip()
            log.info(f"Discovery multicast ativo — local={local_ip}")
            while self.running:
                try:
                    self.server_socket.settimeout(2.0)
                    data, addr = self.server_socket.recvfrom(2048)
                    remote_ip = addr[0]
                    if not _mesma_subnet(remote_ip, local_ip): continue
                    msg = data.decode("utf-8", errors="ignore")
                    if not self._token_valido(msg): continue
                    if msg.startswith("BRN_NODE_PING:"): self._processar_ping(msg, remote_ip, addr)
                except socket.timeout: continue
                except OSError: break
                except Exception: pass
        except Exception as e:
            log.error(f"falha no discovery multicast: {e}")

    def _token_valido(self, msg: str) -> bool:
        try: return msg.split(":")[-1] == TOKEN_ESPERADO
        except Exception: return False

    def _processar_ping(self, msg: str, remote_ip: str, addr) -> None:
        try:
            partes = msg.split(":")
            if len(partes) < 4: return
            remote_port = int(partes[1])
            remote_uuid = partes[2]
            if remote_uuid == self.node_uuid: return
            peer_address = f"{remote_ip}:{remote_port}"
            self.register_uuid(remote_uuid, remote_ip, remote_port)
            novo = self._add_peer(peer_address)
            if novo:
                log.info(f"Novo peer LAN: {peer_address}")
                self._salvar_peers()
                if self.on_peer_found:
                    try: self.on_peer_found(remote_ip, remote_port)
                    except Exception: pass
            if remote_ip not in self.peers_respondidos:
                self.peers_respondidos.add(remote_ip)
                response = f"BRN_NODE_PONG:{self.tcp_port}:{self.node_uuid}:{TOKEN_ESPERADO}"
                try: self.server_socket.sendto(response.encode("utf-8"), addr)
                except Exception: pass
        except Exception: pass

    def _start_client(self) -> None:
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self.client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            self.client_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            while self.running:
                try:
                    msg = f"BRN_NODE_PING:{self.tcp_port}:{self.node_uuid}:{TOKEN_ESPERADO}"
                    self.client_socket.sendto(msg.encode("utf-8"), (MULTICAST_GROUP, MULTICAST_PORT))
                    with self.peers_lock: n = len(self.discovered_peers)
                    intervalo = DISCOVERY_INTERVAL_MIN if n < 2 else (10.0 if n < 5 else DISCOVERY_INTERVAL_MAX)
                    time.sleep(intervalo)
                except OSError: break
                except Exception: time.sleep(5)
        except Exception: pass

    def _ping_bootstrap_loop(self) -> None:
        while self.running:
            try:
                for peer in _carregar_bootstrap():
                    if not self.running: break
                    try:
                        ip, port = peer.split(":")
                        port = int(port)
                        resp, _ = P2PClient.ping(ip, port)
                        if resp:
                            novo = self._add_peer(peer)
                            if resp.get("_uuid"): self.register_uuid(resp["_uuid"], ip, port)
                            if novo and self.on_peer_found:
                                try: self.on_peer_found(ip, port)
                                except Exception: pass
                    except Exception: pass
            except Exception: pass
            time.sleep(BOOTSTRAP_PING_INTERVAL)

    def _limpar_peers_mortos(self) -> None:
        while self.running:
            try:
                time.sleep(PEER_CLEANUP_S)
                agora = time.time()
                with self.peers_lock:
                    for addr, ts in list(self.discovered_peers.items()):
                        if ts > 0 and (agora - ts) > PEER_TIMEOUT: del self.discovered_peers[addr]
                self._salvar_peers()
            except Exception: pass

    def run(self) -> None:
        if self.running: return
        self.running = True
        for fn in [self._start_server, self._start_client,
                   self._limpar_peers_mortos, self._ping_bootstrap_loop]:
            t = threading.Thread(target=fn, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        if not self.running: return
        self.running = False
        for sock in (self.server_socket, self.client_socket):
            if sock:
                try: sock.close()
                except Exception: pass
        self._salvar_peers()

    def listar_peers(self) -> list[str]:
        with self.peers_lock: return list(self.discovered_peers.keys())

    def listar_peers_com_altura(self) -> list[dict]:
        with self._height_cache_lock:
            now = time.time()
            return [
                {"address": a, "height": h, "work": w, "latency_ms": round(lat, 1), "age_s": round(now - ts, 1)}
                for a, (ts, h, w, lat) in self._height_cache.items() if now - ts < HEIGHT_CACHE_TTL
            ]


# ============================================================
# MANAGER
# ============================================================
class P2PManager:
    def __init__(self, blockchain, node_id_priv=None, tcp_port: int = TCP_PORT_DEFAULT, enable_upnp: bool = True):
        self.bc = blockchain
        self.node_id_priv = node_id_priv
        self.tcp_port = tcp_port
        self.enable_upnp = enable_upnp
        self.read_only = READ_ONLY
        self.node_uuid = _obter_ou_criar_uuid()
        self.metrics = Metrics()

        if node_id_priv is not None:
            _auth_set_priv(node_id_priv)

        self._broadcast_pool = ThreadPoolExecutor(max_workers=20, thread_name_prefix="p2p-bcast")

        self.server = P2PServer(
            blockchain, tcp_port, self.metrics,
            on_new_block=self._on_new_block,
            on_new_tx=self._on_new_tx,
            on_peer_bad=self._on_peer_bad,
            on_peer_good=self._on_peer_good,
            get_peers_callback=self._get_peers_for_pex,
        )
        self.server.node_uuid = self.node_uuid

        self.discovery = PeerDiscovery(tcp_port, self.node_uuid, on_peer_found=self._on_peer_found, blockchain=blockchain)

    def start(self) -> None:
        log.info(f"[P2P] iniciado node_id={self.node_uuid[:8]} chain={CHAIN_ID}")
        self.server.start()
        self.discovery.run()

    def stop(self) -> None:
        self.server.stop()
        self.discovery.stop()
        try: self._broadcast_pool.shutdown(wait=False, cancel_futures=True)
        except Exception: pass

    def add_peer(self, ip: str, port: int) -> None:
        try: self.discovery._add_peer(f"{ip}:{port}", ts=time.time())
        except Exception: pass
        self._on_peer_found(ip, port)

    def get_status(self) -> dict:
        return {
            "node_id": self.node_uuid, "port": self.tcp_port,
            "peer_count": len(self.discovery.listar_peers()),
            "peers": self.discovery.listar_peers(),
            "height": self.bc.db.height(),
            "work": self.bc.cumulative_work(),
            "protocol": PROTOCOL_VERSION,
        }

    def get_metrics(self) -> dict: return self.metrics.snapshot()
    def is_read_only(self) -> bool: return self.read_only

    def request_block_signature(self, ip: str, port: int, block: dict, timeout: Optional[float] = None) -> Optional[dict]:
        return P2PClient.request_block_signature(ip, port, block, timeout=timeout)

    def broadcast_validator_registration(self, pubkey: str, address: str) -> None:
        if self.read_only or not pubkey or not address: return
        payload = {"type": "announce_validator", "pubkey": pubkey, "address": address}
        for peer in self.discovery.listar_peers():
            try:
                ip, port_s = peer.rsplit(":", 1)
                self._broadcast_pool.submit(P2PClient.send_message, ip, int(port_s), payload)
            except Exception:
                continue

    def broadcast_checkpoint(self, checkpoint: dict) -> None:
        if self.read_only or not isinstance(checkpoint, dict): return
        height = checkpoint.get("height")
        if not isinstance(height, int): return
        enviados = 0
        for peer in self.discovery.listar_peers():
            try:
                ip, port_s = peer.rsplit(":", 1)
                self._broadcast_pool.submit(P2PClient.send_checkpoint, ip, int(port_s), checkpoint)
                enviados += 1
            except Exception:
                continue
        if enviados > 0:
            self.metrics.inc("checkpoints_broadcast")
            log.info("[P2P] checkpoint #%d broadcast para %d peers", height, enviados)

    def _get_peers_for_pex(self) -> list:
        try: return self.discovery.listar_peers_com_altura()[:MAX_PEERS_PER_PEX]
        except Exception: return []

    def _on_peer_found(self, ip: str, port: int) -> None:
        _registrar_peer_no_db(self.bc, ip, port)
        try:
            resp, latency = P2PClient.get_chain_height(ip, port)
            if not resp: return
            self.metrics.peer_update(f"{ip}:{port}", latency_ms=latency)
            if resp.get("_uuid"): self.discovery.register_uuid(resp["_uuid"], ip, port)
        except Exception:
            pass

    def broadcast_block(self, block_dict: dict) -> None:
        if self.read_only: return
        for peer in self.discovery.listar_peers():
            try:
                ip, port = peer.split(":")
                self._broadcast_pool.submit(P2PClient.send_block, ip, int(port), block_dict)
            except Exception: pass

    def broadcast_tx(self, tx_dict: dict) -> None:
        if self.read_only: return
        for peer in self.discovery.listar_peers():
            try:
                ip, port = peer.split(":")
                self._broadcast_pool.submit(P2PClient.send_tx, ip, int(port), tx_dict)
            except Exception: pass

    def _on_new_block(self, block_dict: dict) -> bool:
        try:
            h = int(block_dict.get("height", -1))
            local_h = self.bc.db.height()
            if h == local_h + 1:
                try:
                    from checkpoints import load_checkpoints
                    tinha_cp = str(h) in load_checkpoints()
                except Exception:
                    tinha_cp = True

                ok, msg = self.bc.accept_block(block_dict)
                if ok:
                    self.metrics.inc("blocks_accepted")
                    log.info(f"novo bloco aceito: #{h}")
                    try: self._broadcast_pool.submit(self.broadcast_block, block_dict)
                    except Exception: pass

                    if not tinha_cp:
                        try:
                            from checkpoints import load_checkpoints
                            novo_cp = load_checkpoints().get(str(h))
                            if novo_cp:
                                self.broadcast_checkpoint(novo_cp)
                        except Exception as e:
                            log.debug("[P2P] broadcast checkpoint falhou: %s", e)
                else:
                    self.metrics.inc("blocks_rejected")
                    log.warning(f"bloco #{h} rejeitado: {msg}")
                return ok
            if h <= local_h:
                try: local_blk = self.bc.db.get_block(h)
                except Exception: local_blk = None
                if local_blk and local_blk.get("hash") != block_dict.get("hash"):
                    self.metrics.inc("forks_detected")
                    log.warning(f"[P2P] FORK detectado em #{h}")
                return False
            return False
        except Exception: return False

    def _on_new_tx(self, tx_dict: dict) -> bool:
        try:
            ok, msg = self.bc.submit_tx(tx_dict)
            if ok:
                self.metrics.inc("txs_accepted")
                try: self._broadcast_pool.submit(self.broadcast_tx, tx_dict)
                except Exception: pass
            return ok
        except Exception: return False

    def _on_peer_bad(self, peer_ip: str, peer_id: Optional[str] = None) -> None:
        try: self.bc.db.add_peer_score(peer_ip, PEER_SCORE_PENALTY_BAD)
        except Exception: pass

    def _on_peer_good(self, peer_ip: str, peer_id: Optional[str] = None) -> None:
        try: self.bc.db.add_peer_score(peer_ip, PEER_SCORE_REWARD_GOOD)
        except Exception: pass