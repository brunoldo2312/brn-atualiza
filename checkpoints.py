"""checkpoints.py — Checkpoints assinados do BRN (v4.0 - Multi-Sig)
================================================================
v4.0 (2026-10-29):
  [NEW] Checkpoints MULTI-SIG assinados pelos validadores.
        Cada checkpoint guarda a lista de assinaturas que o bloco
        já possui no momento em que foi aceito. Nenhuma chave
        centralizada é necessária. Mesmo se o nó Origem for
        comprometido, um reorg histórico é impossível sem controlar
        o quórum de validadores.
  [KEEP] Compatibilidade com formato legacy (Ed25519 único).
================================================================
"""
from __future__ import annotations

import os
import json
import time
import logging
import threading

log = logging.getLogger("checkpoints")

CHECKPOINT_FILE     = os.environ.get("BRN_CHECKPOINT_FILE", "checkpoints.json")
CHECKPOINT_INTERVAL = int(os.environ.get("BRN_CHECKPOINT_INTERVAL", "100"))

_lock = threading.RLock()


# ============================================================
# VERIFICAÇÃO — suporta dois formatos
# ============================================================
def verify_checkpoint(cp: dict) -> bool:
    """
    Verifica um checkpoint. Aceita os dois formatos:
      - Legacy: {"sig": hex, "pub": hex}        → Ed25519 única
      - Multi:  {"signatures": [{pubkey, signature}, ...]}  → secp256k1
    """
    if not isinstance(cp, dict):
        return False

    try:
        height = int(cp["height"])
        block_hash = str(cp["hash"])
    except Exception:
        return False

    # --- Formato novo: multi-sig (secp256k1) ---
    if "signatures" in cp:
        sigs = cp.get("signatures") or []
        if not isinstance(sigs, list):
            return False

        required = int(cp.get("quorum_required", 0))
        if required <= 0:
            return False

        # Mensagem assinada — mesmo domínio do bloco
        from blockchain import BLOCK_SIG_DOMAIN, sha256
        payload = sha256(BLOCK_SIG_DOMAIN + block_hash.encode())

        valid_count = 0
        seen = set()
        for entry in sigs:
            if not isinstance(entry, dict):
                continue
            pk = (entry.get("pubkey") or "").strip()
            sg = (entry.get("signature") or "").strip()
            if not pk or not sg or pk in seen:
                continue
            seen.add(pk)
            try:
                from wallet import Wallet
                if Wallet.verify(payload, sg, pk):
                    valid_count += 1
            except Exception:
                continue

        return valid_count >= required

    # --- Formato legado: Ed25519 única ---
    if "sig" in cp and "pub" in cp:
        try:
            from crypto import Ed25519PublicKey
            from .checkpoints_domain import _payload  # fallback abaixo
        except Exception:
            _payload = lambda h, bh: b"BRN-CHECKPOINT-v1|" + f"{h}:{bh}".encode()
        try:
            sig = bytes.fromhex(cp["sig"])
            pub = bytes.fromhex(cp["pub"])
            if len(pub) != 32 or len(sig) != 64:
                return False
            pk = Ed25519PublicKey.from_public_bytes(pub)
            pk.verify(sig, _payload(height, block_hash))
            return True
        except Exception:
            return False

    return False


# ============================================================
# LEITURA / ESCRITA
# ============================================================
def load_checkpoints() -> dict:
    if not os.path.exists(CHECKPOINT_FILE):
        return {}
    try:
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            log.warning(f"{CHECKPOINT_FILE} nao contem dict — ignorando")
            return {}
        return data
    except Exception as e:
        log.warning(f"erro lendo {CHECKPOINT_FILE}: {e}")
        return {}


def save_checkpoints(d: dict) -> bool:
    if not isinstance(d, dict):
        return False
    with _lock:
        try:
            tmp = CHECKPOINT_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, CHECKPOINT_FILE)
            return True
        except Exception as e:
            log.error(f"erro ao salvar {CHECKPOINT_FILE}: {e}")
            return False


# ============================================================
# CRIAÇÃO DO CHECKPOINT MULTI-SIG
# ============================================================
def build_multisig_checkpoint(
    block: dict,
    signatures: list,
    validators_at_time: list,
    quorum_required: int,
) -> dict:
    """
    Monta o dicionário de checkpoint a partir das assinaturas
    do próprio bloco. Nenhuma assinatura nova é gerada.
    """
    return {
        "height": int(block["height"]),
        "hash": str(block["hash"]),
        "signatures": [
            {
                "pubkey": (s or {}).get("pubkey", ""),
                "signature": (s or {}).get("signature", ""),
            }
            for s in signatures
            if isinstance(s, dict)
            and s.get("pubkey")
            and s.get("signature")
        ],
        "validators_at_time": list(validators_at_time),
        "quorum_required": int(quorum_required),
        "created_at": int(time.time()),
    }


# ============================================================
# VERIFICAÇÃO DE UM BLOCO CONTRA UM CHECKPOINT
# ============================================================
def verify_checkpoint_for(chain, height: int) -> tuple:
    """Compara o bloco local com o checkpoint. Retorna (ok, msg)."""
    cps = load_checkpoints()
    cp = cps.get(str(height))
    if not cp:
        return True, ""

    if not verify_checkpoint(cp):
        return False, f"checkpoint #{height} assinatura invalida"

    try:
        blk = chain.db.get_block(height)
    except Exception as e:
        return False, f"nao consegui ler bloco #{height}: {e}"

    if not blk:
        return False, f"bloco #{height} ausente"

    if blk["hash"] != cp["hash"]:
        return False, (
            f"checkpoint #{height} hash diverge "
            f"(esperado {cp['hash'][:16]}..., bloco {blk['hash'][:16]}...)"
        )

    return True, ""


# ============================================================
# MESCLAGEM
# ============================================================
def merge_checkpoints(local: dict, remote: dict) -> dict:
    merged = dict(remote or {})
    merged.update(local or {})
    return merged


def merge_from_file(path: str) -> int:
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            remote = json.load(f)
    except Exception as e:
        log.warning(f"erro lendo {path}: {e}")
        return 0
    if not isinstance(remote, dict):
        return 0
    local = load_checkpoints()
    before = set(local.keys())
    merged = merge_checkpoints(local, remote)
    added = len(set(merged.keys()) - before)
    if added > 0:
        save_checkpoints(merged)
    return added


# ============================================================
# AUTO-TESTE
# ============================================================
if __name__ == "__main__":
    import tempfile
    logging.basicConfig(level=logging.INFO)

    with tempfile.TemporaryDirectory() as td:
        globals()["CHECKPOINT_FILE"] = os.path.join(td, "cps.json")

        # 1) Checkpoint multi-sig válido
        from wallet import Wallet
        from blockchain import signing_hash_block

        priv1 = Wallet.create()
        priv2 = Wallet.create()
        priv3 = Wallet.create()
        block = {"height": 100, "hash": "a" * 64}

        payload = signing_hash_block(block)
        sigs = [
            {"pubkey": priv1.pub_hex, "signature": priv1.sign(payload)},
            {"pubkey": priv2.pub_hex, "signature": priv2.sign(payload)},
        ]
        cp = build_multisig_checkpoint(
            block, sigs,
            validators_at_time=[priv1.pub_hex, priv2.pub_hex, priv3.pub_hex],
            quorum_required=2,
        )
        assert verify_checkpoint(cp), "checkpoint multi-sig deveria ser válido"
        print("  [ok] checkpoint multi-sig válido")

        # 2) Checkpoint com quórum insuficiente
        cp_bad = build_multisig_checkpoint(
            block, sigs[:1], validators_at_time=[], quorum_required=2,
        )
        assert not verify_checkpoint(cp_bad), "quórum insuficiente deveria falhar"
        print("  [ok] quórum insuficiente rejeitado")

        # 3) Checkpoint com bloco adulterado
        cp_bad2 = dict(cp)
        cp_bad2["hash"] = "b" * 64
        assert not verify_checkpoint(cp_bad2), "hash adulterado deveria falhar"
        print("  [ok] hash adulterado rejeitado")

    print("checkpoints.py v4.0 OK.")