"""blockchain.py — Núcleo da Blockchain BRN
Versão: 9.4.7 | Data: 29/10/2026
================================================================
v9.4.7 (2026-10-29):
  [NEW] Checkpoints MULTI-SIG assinados pelos validadores.
        Cada checkpoint guarda as assinaturas que o bloco já possui.
        Nenhuma chave privada centralizada é necessária. Mesmo se
        o nó Origem for comprometido, reorg histórico é impossível
        sem controlar o quórum de validadores.
  [NEW] CHECKPOINT_INTERVAL configurável via BRN_CHECKPOINT_INTERVAL.
  [NEW] Helper _current_validators_snapshot() e ref global.
  [KEEP] Retrocompatível com checkpoints legados (Ed25519).
  [KEEP] Whitelist opcional via AUTHORIZED_VALIDATORS.
================================================================
"""
from __future__ import annotations

import os
import time
import math
import hmac
import json
import hashlib
import logging
from typing import Optional

import orjson

from crypto import double_sha256, sha256
from db import ChainDB


log = logging.getLogger("blockchain")

COIN_NAME       = "BrunoCoin"
TICKER          = "BRN"
DECIMALS        = 8
UNIT            = 10 ** DECIMALS
MAX_SUPPLY      = 21_000_000 * UNIT
INITIAL_REWARD  = 50 * UNIT
HALVING_INTERVAL = 210_000

BLOCK_TIME          = int(os.environ.get("BRN_BLOCK_TIME",       "30"))
DIFFICULTY_INTERVAL = int(os.environ.get("BRN_DIFF_INTERVAL",    "50"))
MAX_DIFFICULTY      = int(os.environ.get("BRN_MAX_DIFFICULTY",   "7"))
INITIAL_DIFFICULTY  = int(os.environ.get("BRN_MIN_DIFFICULTY",   "5"))
FORCE_DIFFICULTY    = os.environ.get("BRN_FORCE_DIFFICULTY", "").strip()

MAX_TX_PER_BLOCK   = 500
MIN_RELAY_FEE      = 1000
MAX_REORG_DEPTH    = 2000
HASH_BATCH_SIZE    = 5000
AUTH_TAG_START_HEIGHT = 6000

# [v9.4.7] Checkpoint interval configurável
CHECKPOINT_INTERVAL = int(os.environ.get("BRN_CHECKPOINT_INTERVAL", "100"))

MTP_WINDOW            = 50
FILA_MAX_MINERADORES  = 20

MAX_VALIDATORS       = int(os.environ.get("BRN_MAX_VALIDATORS", "5"))
REQUIRE_ALL_SIGS     = os.environ.get("BRN_REQUIRE_ALL_SIGS", "1") == "1"
VALIDATOR_QUORUM     = float(os.environ.get("BRN_VALIDATOR_QUORUM", "0.67"))
SIG_COLLECT_TIMEOUT  = float(os.environ.get("BRN_SIG_COLLECT_TIMEOUT", "10"))
MAX_MEMPOOL_SIZE     = int(os.environ.get("BRN_MAX_MEMPOOL_SIZE", "5000"))

if not (0.0 < VALIDATOR_QUORUM <= 1.0):
    VALIDATOR_QUORUM = 0.67
if SIG_COLLECT_TIMEOUT <= 0:
    SIG_COLLECT_TIMEOUT = 10.0

GENESIS_PREV      = "0" * 64
GENESIS_TIMESTAMP = 1700000000
GENESIS_REWARD    = INITIAL_REWARD
GENESIS_ADDRESS   = "brn1qxyzk7y0v2j4g0a8d9n5t2k7h4s6w8c9p2e"
GENESIS_PUBKEY    = ""

SIGNING_DOMAIN   = b"BRN-TX-v1|"
AUTH_TAG_DOMAIN  = b"BRN-BLOCK-AUTH-v1|"
BLOCK_SIG_DOMAIN = b"BRN-BLOCK-SIG-v1|"
_CORE_V          = 1
NETWORK_SECRET = os.environ.get("BRN_NETWORK_SECRET", "").strip()

try:
    import brn_miner as _brn_miner_c
    _HAS_C_MINER = _brn_miner_c.is_available()
    if _HAS_C_MINER:
        log.info("PoW C acceleration ATIVA (%s)", _brn_miner_c.library_path())
    else:
        log.info("PoW C acceleration indisponível — usando Python puro")
except Exception as _e:
    _brn_miner_c = None
    _HAS_C_MINER = False
    log.debug("brn_miner.py nao disponivel: %s", _e)


def miner_info() -> dict:
    if _HAS_C_MINER and _brn_miner_c is not None:
        return {"c_available": True, "path": str(_brn_miner_c.library_path()), "python_fallback": True}
    return {"c_available": False, "path": None, "python_fallback": True}


# ============================================================
# [v9.4.7] Referência à chain atual (para checkpoints multi-sig)
# ============================================================
_current_chain_ref = None


def _current_validators_snapshot() -> list:
    """Retorna lista de validadores ativos (via trust_net)."""
    chain = _current_chain_ref
    if chain is None:
        return []
    try:
        return chain._get_active_validators()
    except Exception:
        return []


# ============================================================
# Checkpoints
# ============================================================
_checkpoints: dict = {}
_checkpoint_priv = None


def set_checkpoints(d: dict) -> None:
    global _checkpoints
    _checkpoints = {str(k): v for k, v in (d or {}).items()}


def set_checkpoint_priv(priv) -> None:
    """Legacy: só usado por checkpoints antigos Ed25519. Ignorado em multi-sig."""
    global _checkpoint_priv
    _checkpoint_priv = priv


def get_checkpoints() -> dict:
    return dict(_checkpoints)


def _verify_checkpoint_for_block(block) -> tuple:
    """
    [v9.4.7] Verifica se o bloco bate com o checkpoint multi-sig.
    Aceita também checkpoints legados (Ed25519).
    """
    try:
        from checkpoints import load_checkpoints, verify_checkpoint
    except ImportError:
        return True, ""

    cps = _checkpoints or load_checkpoints()
    cp = cps.get(str(block["height"]))
    if not cp:
        return True, ""

    if cp.get("hash") != block["hash"]:
        return False, f"checkpoint mismatch em #{block['height']}"

    if not verify_checkpoint(cp):
        return False, f"checkpoint invalido em #{block['height']}"

    return True, ""


def _maybe_sign_checkpoint(block) -> None:
    """
    [v9.4.7] Salva checkpoint MULTI-SIG quando o bloco é múltiplo de
    CHECKPOINT_INTERVAL. Usa as assinaturas que o bloco já possui.
    Nenhuma chave privada adicional é necessária.
    """
    try:
        h = int(block["height"])
        if h == 0 or h % CHECKPOINT_INTERVAL != 0:
            return

        sigs = block.get("validators_sig") or []
        if not sigs:
            log.debug("[CHECKPOINT] #%d sem assinaturas — skip", h)
            return

        from checkpoints import (
            build_multisig_checkpoint, load_checkpoints,
            save_checkpoints, verify_checkpoint,
        )

        validators = _current_validators_snapshot()
        if not validators:
            log.debug("[CHECKPOINT] #%d sem validadores ativos — skip", h)
            return

        if REQUIRE_ALL_SIGS:
            quorum = len(validators)
        else:
            quorum = max(1, math.ceil(len(validators) * VALIDATOR_QUORUM))
        quorum = min(quorum, len(validators))

        cp = build_multisig_checkpoint(
            block=block,
            signatures=sigs,
            validators_at_time=validators,
            quorum_required=quorum,
        )

        if not verify_checkpoint(cp):
            log.warning(
                "[CHECKPOINT] #%d NAO foi salvo: %d/%d assinaturas (quorum %d)",
                h, len(sigs), len(validators), quorum,
            )
            return

        cps = load_checkpoints()
        cps[str(h)] = cp
        if save_checkpoints(cps):
            _checkpoints[str(h)] = cp
            log.info(
                "[CHECKPOINT] #%d salvo multi-sig (%d/%d validadores)",
                h, len(sigs), len(validators),
            )
    except Exception as e:
        log.debug("[CHECKPOINT] falha ao salvar #%s: %s", block.get("height"), e)


# ============================================================
# Assinatura de blocos (multi-sig)
# ============================================================
def signing_hash_block(block: dict) -> bytes:
    raw_msg = BLOCK_SIG_DOMAIN + block["hash"].encode()
    return sha256(raw_msg)


def sign_block_as_validator(block: dict, priv) -> dict:
    if priv is None:
        return {}
    try:
        from wallet import Wallet
        if not isinstance(priv, Wallet):
            if isinstance(priv, str):
                priv = Wallet(private_key_hex=priv.strip())
            else:
                return {}
        h = signing_hash_block(block)
        sig = priv.sign(h)
        return {"pubkey": priv.pub_hex, "signature": sig}
    except Exception as e:
        log.debug(f"sign_block falhou: {e}")
        return {}


def verify_block_signature(pubkey_hex: str, block: dict, sig_hex: str) -> bool:
    try:
        from wallet import Wallet
        h = signing_hash_block(block)
        return Wallet.verify(h, sig_hex, pubkey_hex)
    except Exception:
        return False


# ============================================================
# AUTH TAG
# ============================================================
def compute_auth_tag(height: int, block_hash_hex: str, secret: str = None) -> str:
    sec = secret if secret is not None else NETWORK_SECRET
    if not sec:
        return ""
    msg = AUTH_TAG_DOMAIN + f"{int(height)}:{block_hash_hex}".encode()
    return hmac.new(sec.encode(), msg, hashlib.sha256).hexdigest()


def verify_auth_tag(height: int, block_hash_hex: str, tag: str, secret: str = None) -> bool:
    expected = compute_auth_tag(height, block_hash_hex, secret)
    if not expected or not tag:
        return False
    return hmac.compare_digest(expected, tag)


# ============================================================
# PoW / helpers
# ============================================================
def block_hash(prev_hash, merkle, timestamp, nonce, difficulty) -> str:
    header = f"{prev_hash}{merkle}{timestamp}{nonce}{difficulty}"
    return double_sha256(header.encode()).hex()


def target_from_difficulty(difficulty: int) -> int:
    return int("0" * int(difficulty) + "f" * (64 - int(difficulty)), 16)


def meets_difficulty(h_hex: str, difficulty: int) -> bool:
    try:
        return int(h_hex, 16) <= target_from_difficulty(difficulty)
    except Exception:
        return False


def work_from_difficulty(difficulty) -> int:
    return 16 ** int(difficulty)


def compute_merkle_root(txids: list) -> str:
    if not txids:
        return "0" * 64
    layer = [bytes.fromhex(t) for t in txids]
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [sha256(layer[i] + layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0].hex()


def _tx_core(tx: dict) -> dict:
    inputs = [{"txid": i["txid"], "vout": i["vout"], "pubkey": i.get("pubkey", "")} for i in tx["inputs"]]
    outputs = [{"address": o["address"], "amount": o["amount"], "pubkey": o.get("pubkey", "")} for o in tx["outputs"]]
    core = {"v": _CORE_V, "inputs": inputs, "outputs": outputs, "timestamp": tx["timestamp"], "locktime": tx.get("locktime", 0), "nonce": tx.get("nonce", 0)}
    if "data" in tx and tx["data"] is not None:
        core["data"] = tx["data"]
    if "height" in tx:
        core["height"] = tx["height"]
    return core


def _serialize_core(tx: dict) -> bytes:
    return orjson.dumps(_tx_core(tx), option=orjson.OPT_SORT_KEYS)


def txid(tx: dict) -> str:
    return double_sha256(_serialize_core(tx)).hex()


def signing_hash(tx: dict) -> bytes:
    return double_sha256(SIGNING_DOMAIN + _serialize_core(tx))


# ============================================================
# PoW search
# ============================================================
def _pow_search_py(prev_hash, merkle, ts, diff, nonce_start=0, should_continue=None, progress_cb=None):
    prefix = f"{prev_hash}{merkle}{ts}".encode()
    diff_bytes = str(diff).encode()
    target_int = int("0" * int(diff) + "f" * (64 - int(diff)), 16)
    sha = hashlib.sha256
    nonce = nonce_start
    hashes_done = 0
    while True:
        for _ in range(HASH_BATCH_SIZE):
            data = prefix + str(nonce).encode() + diff_bytes
            h = sha(sha(data).digest()).digest()
            if int.from_bytes(h, "big") <= target_int:
                return nonce, h.hex(), hashes_done + 1
            nonce += 1
        hashes_done += HASH_BATCH_SIZE
        time.sleep(0)
        if should_continue is not None and not should_continue():
            return None, None, hashes_done
        if progress_cb is not None:
            try:
                progress_cb(nonce, hashes_done)
            except Exception:
                pass


def _pow_search_c(prev_hash, merkle, ts, diff, nonce_start, should_continue, progress_cb):
    prefix = f"{prev_hash}{merkle}{ts}"
    diff_str = str(int(diff))
    nonce = nonce_start
    hashes_done = 0
    while True:
        try:
            result = _brn_miner_c.pow_search(prefix, diff_str, int(diff), nonce_start=nonce, max_iters=HASH_BATCH_SIZE)
        except Exception:
            return _pow_search_py(prev_hash, merkle, ts, diff, nonce, should_continue, progress_cb)
        if result is None:
            return _pow_search_py(prev_hash, merkle, ts, diff, nonce, should_continue, progress_cb)
        found_nonce, found_hash, batch_hashes = result
        hashes_done += batch_hashes
        if found_nonce is not None:
            return found_nonce, found_hash, hashes_done
        nonce += batch_hashes
        if should_continue is not None and not should_continue():
            return None, None, hashes_done
        if progress_cb is not None:
            try:
                progress_cb(nonce, hashes_done)
            except Exception:
                pass


def _pow_search(prev_hash, merkle, ts, diff, nonce_start=0, should_continue=None, progress_cb=None):
    if _HAS_C_MINER and _brn_miner_c is not None:
        return _pow_search_c(prev_hash, merkle, ts, diff, nonce_start, should_continue, progress_cb)
    return _pow_search_py(prev_hash, merkle, ts, diff, nonce_start, should_continue, progress_cb)


# ============================================================
# Coinbase / Genesis
# ============================================================
def make_coinbase(address: str, pubkey_hex: str, height: int, reward: int, fila_mineracao: dict = None) -> dict:
    if not pubkey_hex:
        raise ValueError("make_coinbase: pubkey_hex é obrigatória")
    outputs = []
    if fila_mineracao and len(fila_mineracao) > 0:
        valor_validador = int(reward * 0.5)
        valor_restante = reward - valor_validador
        valor_por_cliente = valor_restante // len(fila_mineracao)
        outputs.append({"address": address, "amount": valor_validador, "pubkey": pubkey_hex})
        for cliente_addr, cliente_pub in fila_mineracao.items():
            outputs.append({"address": cliente_addr, "amount": valor_por_cliente, "pubkey": cliente_pub})
        total_pago = sum(o["amount"] for o in outputs)
        if total_pago < reward:
            outputs[0]["amount"] += (reward - total_pago)
    else:
        outputs.append({"address": address, "amount": int(reward), "pubkey": pubkey_hex})
    cb = {"txid": "", "inputs": [{"txid": "0" * 64, "vout": 0xFFFFFFFF, "pubkey": "", "signature": ""}], "outputs": outputs, "timestamp": int(time.time()), "locktime": 0, "height": int(height), "nonce": 0}
    cb["txid"] = txid(cb)
    return cb


def build_genesis() -> dict:
    cb = {"txid": "", "inputs": [{"txid": "0" * 64, "vout": 0xFFFFFFFF, "pubkey": "", "signature": ""}], "outputs": [{"address": GENESIS_ADDRESS, "amount": GENESIS_REWARD, "pubkey": GENESIS_PUBKEY}], "timestamp": GENESIS_TIMESTAMP, "locktime": 0, "height": 0, "nonce": 0}
    cb["txid"] = txid(cb)
    merkle = compute_merkle_root([cb["txid"]])
    nonce = 0
    while True:
        h = block_hash(GENESIS_PREV, merkle, GENESIS_TIMESTAMP, nonce, 1)
        if h.startswith("0"):
            break
        nonce += 1
    g = {"height": 0, "hash": h, "prev_hash": GENESIS_PREV, "timestamp": GENESIS_TIMESTAMP, "nonce": nonce, "merkle": merkle, "difficulty": 1, "transactions": [cb], "cumulative_work": work_from_difficulty(1), "validators_sig": []}
    tag = compute_auth_tag(0, h)
    if tag:
        g["auth_tag"] = tag
    return g


GENESIS_BLOCK = build_genesis()


# ============================================================
# Blockchain
# ============================================================
class Blockchain:
    # [SECURITY] Whitelist opcional (para redes fechadas).
    # Deixe vazio para modo aberto.
    AUTHORIZED_VALIDATORS = [
        # "pubkey_ubuntu",
        # "pubkey_windows",
        # "pubkey_vps",
    ]

    def __init__(self, db_path="brn_v2_chain.db", genesis_address=None, genesis_pubkey=None, auto_genesis=True, network_secret=None, require_auth_tag=None):
        global _current_chain_ref
        _current_chain_ref = self

        self.db = ChainDB(db_path)
        self.genesis_expected_hash = None
        self.network_secret = network_secret if network_secret is not None else NETWORK_SECRET
        self.require_auth_tag = bool(self.network_secret) if require_auth_tag is None else bool(require_auth_tag)
        self.on_block_mined = None
        self._fork_signal = None

        self.trust_net = None
        self.p2p = None
        self._sign_collector = None
        self._local_validator_sk = None

        fila_salva = self.db.get_meta("fila_mineracao")
        self.fila_mineracao = json.loads(fila_salva) if fila_salva else {}
        rede_desc = self.db.get_meta("rede_descentralizada")
        self.rede_descentralizada = (rede_desc == "1")

        if not auto_genesis:
            self.genesis_expected_hash = GENESIS_BLOCK["hash"]
            return
        if self.db.height() < 0:
            g = GENESIS_BLOCK
            if genesis_address:
                g = self._genesis_with_address(genesis_address, genesis_pubkey if genesis_pubkey is not None else GENESIS_PUBKEY)
            self.db.add_block(g)
            self.db.apply_tx(g["transactions"][0], 0, coinbase=True)
            self.db.set_meta("genesis_hash", g["hash"])

    def set_trust_net(self, trust):
        self.trust_net = trust
        log.info(f"[Blockchain] trust_net injetado ({len(getattr(trust, 'nodes', {}))} nós)")

    def set_p2p(self, p2p):
        self.p2p = p2p

    def set_local_validator_sk(self, sk) -> None:
        if sk is None:
            self._local_validator_sk = None
            return
        try:
            from wallet import Wallet
            if isinstance(sk, Wallet):
                self._local_validator_sk = sk
                log.info("[SIG] chave local de validador configurada (Wallet)")
                return
            if isinstance(sk, str):
                h = sk.strip()
                if len(h) != 64 or any(c not in "0123456789abcdefABCDEF" for c in h):
                    log.warning("[SIG] set_local_validator_sk: hex inválido")
                    self._local_validator_sk = None
                    return
                self._local_validator_sk = Wallet(private_key_hex=h)
                log.info("[SIG] chave local de validador configurada (hex)")
                return
            self._local_validator_sk = None
        except Exception as e:
            log.warning(f"[SIG] set_local_validator_sk falhou: {e}")
            self._local_validator_sk = None

    def set_sign_collector(self, cb):
        self._sign_collector = cb

    def adicionar_na_fila(self, address: str, pubkey: str) -> None:
        if self.rede_descentralizada:
            return
        if not address or not pubkey:
            return
        if address in self.fila_mineracao:
            return
        self.fila_mineracao[address] = pubkey
        print(f"[BOOTSTRAP] Novo minerador na fila: {address[:12]}... ({len(self.fila_mineracao)}/{FILA_MAX_MINERADORES})")
        self.db.set_meta("fila_mineracao", json.dumps(self.fila_mineracao))
        if len(self.fila_mineracao) >= FILA_MAX_MINERADORES:
            self.rede_descentralizada = True
            self.db.set_meta("rede_descentralizada", "1")
            print("\n[BOOTSTRAP] 20 MINERADORES ATINGIDOS! REDE DESCENTRALIZADA.\n")

    @staticmethod
    def _genesis_with_address(address: str, pubkey_hex: str = "") -> dict:
        cb = {"txid": "", "inputs": [{"txid": "0" * 64, "vout": 0xFFFFFFFF, "pubkey": "", "signature": ""}], "outputs": [{"address": address, "amount": GENESIS_REWARD, "pubkey": pubkey_hex}], "timestamp": GENESIS_TIMESTAMP, "locktime": 0, "height": 0, "nonce": 0}
        cb["txid"] = txid(cb)
        merkle = compute_merkle_root([cb["txid"]])
        nonce = 0
        while True:
            h = block_hash(GENESIS_PREV, merkle, GENESIS_TIMESTAMP, nonce, 1)
            if h.startswith("0"):
                break
            nonce += 1
        g = {"height": 0, "hash": h, "prev_hash": GENESIS_PREV, "timestamp": GENESIS_TIMESTAMP, "nonce": nonce, "merkle": merkle, "difficulty": 1, "transactions": [cb], "cumulative_work": work_from_difficulty(1), "validators_sig": []}
        tag = compute_auth_tag(0, h)
        if tag:
            g["auth_tag"] = tag
        return g

    def set_network_secret(self, secret: str) -> None:
        self.network_secret = (secret or "").strip()
        if os.environ.get("BRN_REQUIRE_AUTH_TAG", "1") == "1":
            if self.require_auth_tag is False:
                self.require_auth_tag = bool(self.network_secret)

    def current_reward(self, height: int) -> int:
        halvings = height // HALVING_INTERVAL
        if halvings >= 64:
            return 0
        return INITIAL_REWARD >> halvings

    def current_difficulty(self) -> int:
        if FORCE_DIFFICULTY:
            try:
                return max(1, min(20, int(FORCE_DIFFICULTY)))
            except ValueError:
                pass
        h = self.db.height()
        if h < DIFFICULTY_INTERVAL:
            return INITIAL_DIFFICULTY
        start = self.db.get_block(h - DIFFICULTY_INTERVAL + 1)
        end = self.db.get_block(h)
        if not start or not end:
            return INITIAL_DIFFICULTY
        if end["difficulty"] > MAX_DIFFICULTY:
            return MAX_DIFFICULTY
        actual = max(1, end["timestamp"] - start["timestamp"])
        expected = BLOCK_TIME * DIFFICULTY_INTERVAL
        prev = end["difficulty"]
        new = int(prev * expected / actual)
        new = max(prev // 4, min(prev * 4, new))
        return max(1, min(MAX_DIFFICULTY, new))

    def cumulative_work(self) -> int:
        total = 0
        with self.db.lock:
            rows = self.db.conn.execute("SELECT difficulty FROM blocks").fetchall()
            for r in rows:
                try:
                    total += work_from_difficulty(r["difficulty"])
                except Exception:
                    continue
        return total

    def get_latest_height(self) -> int:
        return self.db.height()

    def get_transaction_block_height(self, txid_str: str) -> int:
        return self.db.get_tx_block_height(txid_str)

    def count_confirmations(self, txid_str: str) -> int:
        tx_height = self.get_transaction_block_height(txid_str)
        if tx_height == -1:
            return 0
        return self.get_latest_height() - tx_height

    def estimate_fee(self, priority: str = "medium") -> int:
        try:
            stats = self.db.mempool_stats()
        except Exception:
            return MIN_RELAY_FEE
        count = stats.get("count", 0)
        fees = stats.get("fees", [])
        if count == 0 or not fees:
            return MIN_RELAY_FEE
        fees_sorted = sorted(fees, reverse=True)
        n = len(fees_sorted)
        if priority == "high":
            idx = max(0, n // 10)
            return max(MIN_RELAY_FEE, fees_sorted[idx] * 2)
        elif priority == "low":
            idx = min(n - 1, (n * 9) // 10)
            return max(MIN_RELAY_FEE, fees_sorted[idx])
        else:
            idx = n // 2
            return max(MIN_RELAY_FEE, fees_sorted[idx])

    def tx_fee(self, tx: dict) -> int:
        in_sum = 0
        for inp in tx["inputs"]:
            u = self.db.get_utxo(inp["txid"], inp["vout"])
            if u:
                in_sum += u["amount"]
        return in_sum - sum(o["amount"] for o in tx["outputs"])

    def _validate_contract_tx(self, tx: dict) -> tuple:
        tx_data = tx.get("data") or {}
        t = tx_data.get("type")
        if t == "deploy":
            code = tx_data.get("code")
            if not isinstance(code, dict):
                return False, "deploy sem 'code' (dict)"
            try:
                from contracts import ContractVM
                return ContractVM.validate(code)
            except ImportError:
                return False, "modulo contracts.py nao encontrado"
            except Exception as e:
                return False, f"erro validando contrato: {e}"
        if t == "call":
            cid = tx_data.get("contract_id")
            if not cid or not isinstance(cid, str):
                return False, "call sem 'contract_id'"
            if not cid.startswith("ctr1"):
                return False, "contract_id deve começar com 'ctr1'"
            if not self.db.contract_get(cid):
                return False, f"contrato {cid[:16]}... nao existe"
            return True, "ok"
        return False, f"tipo de contrato desconhecido: {t}"

    def _contract_sender_address(self, tx: dict) -> str:
        inputs = tx.get("inputs") or []
        if not inputs or not isinstance(inputs[0], dict):
            raise ValueError("transacao de contrato sem input valido")
        pubkey_hex = inputs[0].get("pubkey", "")
        if not isinstance(pubkey_hex, str) or not pubkey_hex:
            raise ValueError("transacao de contrato sem pubkey do remetente")
        try:
            from bech32 import address_from_pubkey
            pubkey = bytes.fromhex(pubkey_hex)
            address = address_from_pubkey(pubkey)
        except Exception as exc:
            raise ValueError("pubkey do remetente invalida") from exc
        if not address:
            raise ValueError("nao foi possivel derivar endereco do remetente")
        return address

    def _apply_contract_tx(self, tx: dict) -> dict:
        tx_data = tx.get("data") or {}
        t = tx_data.get("type")
        from contracts import deploy as _deploy, call as _call
        sender = self._contract_sender_address(tx)
        if t == "deploy":
            r = _deploy(self, sender, tx_data.get("code") or {}, metadata=tx_data.get("metadata"))
            if not r.get("ok"):
                raise ValueError(f"deploy falhou: {r.get('msg')}")
            return r
        if t == "call":
            r = _call(self, tx_data.get("contract_id", ""), sender, tx_data.get("args"))
            if not r.get("ok"):
                raise ValueError(f"call falhou: {r.get('msg')}")
            return r
        raise ValueError(f"tipo de contrato desconhecido: {t}")

    def validate_tx(self, tx: dict, from_mempool: bool = False) -> tuple:
        from wallet import Wallet
        if not tx.get("inputs") or not tx.get("outputs"):
            return False, "tx sem inputs/outputs"
        if tx["inputs"][0]["txid"] == "0" * 64:
            return False, "coinbase invalida"
        if tx.get("txid") != txid(tx):
            return False, "txid invalido"
        tx_data = tx.get("data") or {}
        if isinstance(tx_data, dict) and tx_data.get("type") in ("deploy", "call"):
            ok_ctr, msg_ctr = self._validate_contract_tx(tx)
            if not ok_ctr:
                return False, f"contrato: {msg_ctr}"
        if not from_mempool:
            try:
                gastos_mem = self.db.utxos_gastos_na_mempool()
            except AttributeError:
                gastos_mem = set()
            except Exception:
                gastos_mem = set()
            for inp in tx["inputs"]:
                key = (inp["txid"], int(inp["vout"]))
                if key in gastos_mem:
                    return False, f"UTXO {inp['txid'][:16]}...:{inp['vout']} ja gasto na mempool"
        for inp in tx["inputs"]:
            if not inp.get("pubkey"):
                return False, "input sem pubkey"
        tx_nonce = tx.get("nonce", 0)
        for inp in tx["inputs"]:
            pk = inp["pubkey"]
            expected = self.db.get_nonce_for_pubkey(pk)
            if tx_nonce != expected:
                return False, f"nonce invalido para {pk[:16]}..."
        in_sum = 0
        seen = set()
        for inp in tx["inputs"]:
            key = (inp["txid"], inp["vout"])
            if key in seen:
                return False, "input duplicado"
            seen.add(key)
            u = self.db.get_utxo(inp["txid"], inp["vout"])
            if not u:
                return False, "UTXO inexistente"
            stored_pk = (u["pubkey"] or "").strip()
            if stored_pk and set(stored_pk) != {"0"}:
                if inp["pubkey"] != stored_pk:
                    return False, f"pubkey mismatch"
            else:
                try:
                    from bech32 import address_from_pubkey
                    derived = address_from_pubkey(bytes.fromhex(inp["pubkey"]))
                except Exception:
                    return False, "input pubkey invalida"
                if derived != u["address"]:
                    return False, f"address mismatch"
            in_sum += u["amount"]
        out_sum = sum(o["amount"] for o in tx["outputs"])
        if out_sum > in_sum:
            return False, "outputs > inputs"
        if in_sum - out_sum < MIN_RELAY_FEE:
            return False, "fee abaixo do minimo"
        sig_hash = signing_hash(tx)
        for inp in tx["inputs"]:
            if not Wallet.verify(sig_hash, inp.get("signature", ""), inp["pubkey"]):
                return False, "assinatura invalida"
        return True, "ok"

    def submit_tx(self, tx: dict) -> tuple:
        if self.db.mempool_count() >= MAX_MEMPOOL_SIZE:
            return False, "Mempool cheia. Tente novamente mais tarde."
        if self.db.has_mempool(tx["txid"]):
            return False, "ja na mempool"
        ok, msg = self.validate_tx(tx)
        if not ok:
            return False, msg
        fee = self.tx_fee(tx)
        if fee < 0:
            return False, "fee negativa"
        if not self.db.add_mempool(tx, fee):
            return False, "falha na mempool"
        return True, tx["txid"]

    def median_time_past(self, height: int) -> int:
        timestamps = []
        for i in range(max(0, height - MTP_WINDOW), height):
            try:
                b = self.db.get_block(i)
                if b:
                    timestamps.append(b["timestamp"])
            except Exception:
                continue
        if not timestamps:
            return 0
        timestamps.sort()
        return timestamps[len(timestamps) // 2]

    def _get_active_validators(self) -> list:
        trust = self.trust_net
        if trust is None:
            return []
        try:
            top = trust.get_top_validators(count=MAX_VALIDATORS)
            if not top:
                return []
            if self.AUTHORIZED_VALIDATORS:
                top = [p for p in top if p in self.AUTHORIZED_VALIDATORS]
                if not top:
                    log.warning("[VALIDATORS] Nenhum validador da whitelist online")
                    return []
            return sorted({p for p in top if p})
        except Exception as e:
            log.warning(f"[VALIDATORS] get_top_validators falhou: {e}")
            return []

    def _required_signatures(self, validators: list) -> int:
        n = len(validators)
        if n == 0:
            return 0
        if REQUIRE_ALL_SIGS:
            return n
        need = max(1, math.ceil(n * VALIDATOR_QUORUM))
        return min(need, n)

    def _validate_validators_sig(self, block: dict, validators: Optional[list] = None) -> tuple:
        if validators is None:
            validators = self._get_active_validators()
        if not validators:
            return True, ""

        required = self._required_signatures(validators)
        sigs = block.get("validators_sig", [])
        if sigs is None:
            sigs = []
        if not isinstance(sigs, list):
            return False, "validators_sig inválido"

        valid_set = set(validators)
        valid_pubkeys: set = set()

        for entry in sigs:
            if not isinstance(entry, dict):
                continue
            pubkey = (entry.get("pubkey") or "").strip()
            signature = (entry.get("signature") or "").strip()
            if not pubkey or not signature:
                continue
            if pubkey not in valid_set:
                log.warning(f"[SIG] pubkey fora do set: {pubkey[:16]}")
                continue
            if pubkey in valid_pubkeys:
                continue
            if verify_block_signature(pubkey, block, signature):
                valid_pubkeys.add(pubkey)
            else:
                log.warning(f"[SIG] assinatura inválida de {pubkey[:16]}")

        got = len(valid_pubkeys)
        if got < required:
            missing = [p[:12] + "…" for p in validators if p not in valid_pubkeys]
            return False, (
                f"Bloco #{block['height']} precisa de {required}/{len(validators)} "
                f"assinaturas, tem {got}. Faltam: {', '.join(missing[:5])}"
            )
        return True, ""

    def validate_block(self, block: dict, prev_block=None, validators: Optional[list] = None) -> tuple:
        if block["height"] == 0 and prev_block is None:
            if (self.genesis_expected_hash and block["hash"] != self.genesis_expected_hash):
                return False, f"genesis nao corresponde ao esperado"
        expected_prev = (prev_block["hash"] if prev_block else self.db.tip_hash())
        if block["prev_hash"] != expected_prev:
            return False, "prev_hash incorreto"
        expected_height = ((prev_block["height"] + 1) if prev_block else self.db.height() + 1)
        if block["height"] != expected_height:
            return False, "altura invalida"

        if block["height"] > MTP_WINDOW:
            try:
                mtp = self.median_time_past(block["height"])
                if block["timestamp"] < mtp:
                    return False, f"timestamp < MTP"
            except Exception as e:
                log.warning(f"[validate_block] Falha no MTP (tolerado): {e}")

        if not meets_difficulty(block["hash"], block["difficulty"]):
            return False, "PoW invalido"
        h = block_hash(block["prev_hash"], block["merkle"], block["timestamp"], block["nonce"], block["difficulty"])
        if h != block["hash"]:
            return False, "hash incorreto"
        calc_merkle = compute_merkle_root([t["txid"] for t in block["transactions"]])
        if calc_merkle != block["merkle"]:
            return False, "merkle incorreto"

        ok_cp, msg_cp = _verify_checkpoint_for_block(block)
        if not ok_cp:
            return False, msg_cp

        if block["height"] > 0:
            ok_sig, msg_sig = self._validate_validators_sig(block, validators=validators)
            if not ok_sig:
                return False, msg_sig

        if block["height"] > 0 and self.require_auth_tag:
            if not self.network_secret:
                return False, "no exige auth_tag mas sem BRN_NETWORK_SECRET"
            if block["height"] > AUTH_TAG_START_HEIGHT:
                tag = block.get("auth_tag")
                if not tag:
                    return False, "bloco sem auth_tag"
                if not verify_auth_tag(block["height"], block["hash"], tag, self.network_secret):
                    return False, "auth_tag invalido"
            else:
                tag = block.get("auth_tag")
                if tag:
                    if not verify_auth_tag(block["height"], block["hash"], tag, self.network_secret):
                        return False, "auth_tag invalido em bloco legado"

        cb = block["transactions"][0]
        if cb["inputs"][0]["txid"] != "0" * 64:
            return False, "primeira tx nao e coinbase"
        if cb.get("txid") != txid(cb):
            return False, "coinbase txid invalido"
        if block["height"] > 0:
            for out in cb["outputs"]:
                if not out.get("pubkey"):
                    return False, "coinbase output sem pubkey"
        for inp in cb["inputs"]:
            if inp.get("signature"):
                return False, "coinbase input com assinatura"
        reward = self.current_reward(block["height"])
        fees = 0
        for i, t in enumerate(block["transactions"][1:], 1):
            if t["txid"] != txid(t):
                return False, "txid invalido"
            ok_tx, msg_tx = self.validate_tx(t, from_mempool=True)
            if not ok_tx:
                return False, f"tx #{i}: {msg_tx}"
            fees += self.tx_fee(t)
        total_cb = sum(o["amount"] for o in cb["outputs"])
        if total_cb > reward + fees:
            return False, "coinbase acima do permitido"
        return True, "ok"

    def accept_block(self, block: dict, validators: Optional[list] = None) -> tuple:
        prev = self.db.get_block_by_hash(block["prev_hash"])
        ok, msg = self.validate_block(block, prev, validators=validators)
        if not ok:
            return False, msg

        try:
            existing = self.db.get_block(block["height"])
            if existing:
                return False, f"Bloco #{block['height']} já existe na blockchain"
        except Exception:
            pass

        try:
            self.db.add_block(block)
        except Exception as e:
            return False, f"Erro ao gravar bloco #{block['height']}: {e}"

        # [v9.4.7] Gera checkpoint multi-sig quando aplicável
        _maybe_sign_checkpoint(block)

        for i, t in enumerate(block["transactions"]):
            coinbase = (i == 0)
            self.db.apply_tx(t, block["height"], coinbase=coinbase)
            if i > 0:
                self.db.remove_mempool(t["txid"])
            if not coinbase:
                tx_data = t.get("data") or {}
                if (isinstance(tx_data, dict) and tx_data.get("type") in ("deploy", "call")):
                    try:
                        self._apply_contract_tx(t)
                    except Exception as e:
                        print(f"[CONTRACT] tx {t['txid'][:16]}... falhou: {e}")
        return True, block["hash"]

    def _attach_auth_tag(self, block: dict) -> dict:
        tag = compute_auth_tag(block["height"], block["hash"], self.network_secret)
        if tag:
            block["auth_tag"] = tag
        return block

    def _fire_block_mined(self, block: dict) -> None:
        cb = self.on_block_mined
        if cb is None:
            return
        try:
            cb(block)
        except Exception as e:
            print(f"[on_block_mined] callback falhou: {e}")

    def _collect_signatures(self, block: dict, validators: Optional[list] = None) -> list:
        if validators is None:
            validators = self._get_active_validators()
        if not validators:
            return []

        valid_set = set(validators)
        sigs: list = []
        seen: set = set()

        local_sk = self._local_validator_sk
        if local_sk is not None:
            entry = sign_block_as_validator(block, local_sk)
            if not entry:
                log.warning("[SIG] assinatura local falhou (chave inválida?)")
            else:
                pk = entry.get("pubkey", "")
                if pk in valid_set:
                    if verify_block_signature(pk, block, entry.get("signature", "")):
                        sigs.append(entry)
                        seen.add(pk)
                    else:
                        log.warning(f"[SIG] assinatura local inválida ({pk[:16]})")
                elif pk:
                    log.info(f"[SIG] pubkey local {pk[:16]} não é validador ativo")

        if self._sign_collector is not None:
            extra: list = []
            try:
                from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
                with ThreadPoolExecutor(max_workers=1, thread_name_prefix="sig-collect") as pool:
                    fut = pool.submit(self._sign_collector, block)
                    try:
                        extra = fut.result(timeout=SIG_COLLECT_TIMEOUT) or []
                    except FutTimeout:
                        log.warning(f"[SIG] _sign_collector timeout após {SIG_COLLECT_TIMEOUT:.1f}s")
            except Exception as e:
                log.warning(f"[SIG] _sign_collector falhou: {e}")

            for entry in extra:
                if not isinstance(entry, dict):
                    continue
                pk = (entry.get("pubkey") or "").strip()
                sg = (entry.get("signature") or "").strip()
                if not pk or not sg:
                    continue
                if pk not in valid_set:
                    log.warning(f"[SIG] coletor devolveu pubkey desconhecida: {pk[:16]}")
                    continue
                if pk in seen:
                    continue
                if verify_block_signature(pk, block, sg):
                    sigs.append(entry)
                    seen.add(pk)
                else:
                    log.warning(f"[SIG] coletor devolveu assinatura inválida: {pk[:16]}")

        return sigs

    def mine_block(self, miner_address: str, miner_pubkey: str) -> dict:
        if not miner_pubkey:
            raise ValueError("mine_block: miner_pubkey é obrigatória")
        return self.mine_block_interruptible(miner_address, miner_pubkey, None)

    def mine_block_interruptible(self, miner_address: str, miner_pubkey: str, should_continue=None, progress_cb=None) -> dict:
        if not miner_pubkey:
            raise ValueError("mine_block_interruptible: miner_pubkey é obrigatória")

        validators = self._get_active_validators()

        height = self.db.height() + 1
        reward = self.current_reward(height)
        diff = self.current_difficulty()

        fila_para_pagar = None
        if (not self.rede_descentralizada and len(self.fila_mineracao) > 0):
            fila_para_pagar = self.fila_mineracao
        cb = make_coinbase(miner_address, miner_pubkey, height, reward, fila_mineracao=fila_para_pagar)

        candidatas = self.db.all_mempool(limit=MAX_TX_PER_BLOCK - 1)
        selected = []
        gastos_neste_bloco = set()
        for t in candidatas:
            try:
                ok_tx, msg_tx = self.validate_tx(t, from_mempool=True)
                if not ok_tx:
                    continue
                conflito = False
                for inp in t.get("inputs", []):
                    key = (inp["txid"], int(inp["vout"]))
                    if key in gastos_neste_bloco:
                        conflito = True
                        break
                if conflito:
                    continue
                for inp in t.get("inputs", []):
                    gastos_neste_bloco.add((inp["txid"], int(inp["vout"])))
                selected.append(t)
            except Exception:
                continue
        txs = [cb] + selected
        merkle = compute_merkle_root([t["txid"] for t in txs])
        prev_hash = self.db.tip_hash()
        ts = int(time.time())
        nonce, h_hex, _ = _pow_search(prev_hash, merkle, ts, diff, should_continue=should_continue, progress_cb=progress_cb)
        if nonce is None:
            return None

        block = {
            "height": height, "hash": h_hex, "prev_hash": prev_hash,
            "timestamp": ts, "nonce": nonce, "merkle": merkle,
            "difficulty": diff, "transactions": txs,
            "validators_sig": [],
        }
        self._attach_auth_tag(block)

        sigs = self._collect_signatures(block, validators=validators)
        block["validators_sig"] = sigs

        ok_sig, msg_sig = self._validate_validators_sig(block, validators=validators)
        if not ok_sig:
            log.warning(f"[MINER] bloco #{height} REJEITADO (multi-sig): {msg_sig}")
            return None

        ok, msg = self.accept_block(block, validators=validators)
        if ok:
            self._fire_block_mined(block)
            return block
        log.warning(f"[MINER] bloco #{height} minerado mas REJEITADO: {msg}")
        return None

    def state_snapshot(self) -> dict:
        try:
            n_validators = len(self._get_active_validators())
        except Exception:
            n_validators = -1
        return {
            "height": self.get_latest_height(),
            "tip_hash": self.db.tip_hash(),
            "difficulty": self.current_difficulty(),
            "cumulative_work": self.cumulative_work(),
            "mempool": self.db.mempool_count(),
            "checkpoints": len(_checkpoints),
            "rede_descentralizada": self.rede_descentralizada,
            "fila_tamanho": len(self.fila_mineracao),
            "validators_active": n_validators,
            "require_all_sigs": REQUIRE_ALL_SIGS,
            "validator_quorum": VALIDATOR_QUORUM,
        }


# ============================================================
# Plugins externos
# ============================================================
try:
    from reorg import reorg_to as _reorg_to, find_fork_point as _find_fork
    def _reorg_to_method(self, new_blocks, max_depth=MAX_REORG_DEPTH, allow_genesis_reorg=False):
        res = _reorg_to(self, new_blocks, max_depth, allow_genesis_reorg)
        return res.to_tuple()
    def _find_fork_method(self, remote_blocks, max_depth=1000):
        return _find_fork(self, remote_blocks, max_depth)
    Blockchain.reorg_to = _reorg_to_method
    Blockchain.find_fork_point = _find_fork_method
    print("reorg.py plugado em Blockchain")
except ImportError:
    print("reorg.py nao encontrado (reorg desabilitado)")

try:
    from chain_validator import verify_chain as _verify_ext
    def _verify_chain_method(self, full=True):
        return _verify_ext(self)
    Blockchain.verify_chain = _verify_chain_method
    Blockchain.verify_chain_dict = lambda self: _verify_ext(self).to_dict()
    print("chain_validator.py plugado em Blockchain")
except ImportError:
    print("chain_validator.py nao encontrado")