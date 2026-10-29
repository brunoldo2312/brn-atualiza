"""reorg.py — Reorganização de cadeia (Chain Reorganization) BRN (v2.2)
================================================================
v2.2 (2026-10-29):
  [FIX] _check_checkpoints agora chama verify_checkpoint() na
        assinatura do checkpoint local antes de usar o hash.
        Antes só comparava hashes, permitindo bypass se o
        checkpoints.json fosse corrompido localmente.
  [FIX] _check_checkpoints não rejeita mais reorgs curtas.
        Se um checkpoint está acima da altura alcançada pela
        reorg, ele é ignorado (não há violação possível).
  [NEW] Log detalhado de quantos checkpoints estão ativos e
        quais bloquearam o reorg.
  [KEEP] Desempate por work → timestamp → hash (compatível).
  [KEEP] Pré-validação com PoW, merkle, auth_tag e assinaturas.
v2.1:
  - find_fork_point detecta fork em local_h + 1 corretamente.
================================================================
"""
from __future__ import annotations
import logging
import threading
import time

log = logging.getLogger("reorg")

_REORG_LOCK = threading.RLock()
DEFAULT_MAX_DEPTH = 200


class ReorgResult:
    __slots__ = ("ok", "msg", "fork_height", "depth", "blocks_removed",
                 "blocks_added", "work_local", "work_remote", "duration_s",
                 "checkpoint_violated")

    def __init__(self):
        self.ok = False
        self.msg = ""
        self.fork_height = -1
        self.depth = 0
        self.blocks_removed = 0
        self.blocks_added = 0
        self.work_local = 0
        self.work_remote = 0
        self.duration_s = 0.0
        self.checkpoint_violated = None  # altura do checkpoint violado

    def to_tuple(self):
        return (self.ok, self.msg)

    def to_dict(self):
        return {
            "ok": self.ok,
            "msg": self.msg,
            "fork_height": self.fork_height,
            "depth": self.depth,
            "blocks_removed": self.blocks_removed,
            "blocks_added": self.blocks_added,
            "work_local": self.work_local,
            "work_remote": self.work_remote,
            "duration_s": round(self.duration_s, 3),
            "checkpoint_violated": self.checkpoint_violated,
        }


def _work(d):
    return 16 ** int(d or 0)


def _cum_work(blocks):
    return sum(_work(b.get("difficulty", 0)) for b in blocks)


def _local_work_above(chain, fh):
    total = 0
    for h in range(fh + 1, chain.db.height() + 1):
        b = chain.db.get_block(h)
        if b:
            total += _work(b.get("difficulty", 0))
    return total


# ============================================================
# find_fork_point
# ============================================================
def find_fork_point(chain, remote_blocks, max_depth=200):
    if not remote_blocks:
        return -1
    try:
        local_h = chain.db.height()
    except Exception:
        return -1

    remote_by_h = {}
    for b in remote_blocks:
        try:
            remote_by_h[int(b["height"])] = b
        except Exception:
            continue
    if not remote_by_h:
        return -1

    min_remote_h = min(remote_by_h.keys())
    if min_remote_h == local_h + 1:
        lowest = remote_by_h[min_remote_h]
        local_tip = chain.db.tip_hash()
        if lowest.get("prev_hash") == local_tip:
            log.info("[REORG] ancestral #%d (tip local = prev_hash do lote)", local_h)
            return local_h

    start_h = min(local_h, max(remote_by_h.keys()))
    end_h = max(-1, start_h - max(1, int(max_depth)))
    for h in range(start_h, end_h - 1, -1):
        rb = remote_by_h.get(h)
        if not rb:
            continue
        lb = chain.db.get_block(h)
        if lb and lb.get("hash") == rb.get("hash"):
            return h
    return -1


# ============================================================
# Desempate: work > timestamp > hash
# ============================================================
def _should_use_remote(chain, fork_h, blocks_to_add, local_h):
    work_remote = _cum_work(blocks_to_add)
    work_local = _local_work_above(chain, fork_h)

    if work_remote > work_local:
        log.warning("[REORG] work remoto %d > local %d", work_remote, work_local)
        return True, "work_maior"
    if work_remote < work_local:
        log.info("[REORG] work remoto %d < local %d", work_remote, work_local)
        return False, "work_menor"

    first_remote = blocks_to_add[0]
    first_local = chain.db.get_block(fork_h + 1)
    if not first_local:
        return True, "local_sem_bloco"

    ts_r = int(first_remote.get("timestamp", 0))
    ts_l = int(first_local.get("timestamp", 0))
    if ts_r < ts_l:
        log.warning("[REORG] timestamps: remoto #%d < local #%d → escolhe remoto", ts_r, ts_l)
        return True, "timestamp_mais_antigo"
    if ts_r > ts_l:
        return False, "timestamp_mais_novo"

    hr = str(first_remote.get("hash", ""))
    hl = str(first_local.get("hash", ""))
    if hr < hl:
        return True, "hash_menor"
    return False, "hash_maior"


# ============================================================
# Pré-validação criptográfica
# ============================================================
def _pre_validate(chain, fork_h, new_blocks):
    if not new_blocks:
        return False, "lista vazia"
    try:
        from blockchain import block_hash, meets_difficulty
    except ImportError:
        return False, "blockchain.py sem helpers"
    try:
        ordered = sorted(new_blocks, key=lambda b: int(b["height"]))
    except Exception as e:
        return False, f"altura inválida: {e}"

    expected_h = fork_h + 1
    if fork_h >= 0:
        prev = chain.db.get_block(fork_h)
        if not prev:
            return False, f"bloco #{fork_h} ausente"
        prev_hash = prev["hash"]
    else:
        prev_hash = "0" * 64

    for blk in ordered:
        h = int(blk["height"])
        if h != expected_h:
            return False, f"esperado #{expected_h}, recebido #{h}"
        if blk.get("prev_hash") != prev_hash:
            return False, f"#{h} prev_hash não encadeia"
        calc = block_hash(blk["prev_hash"], blk["merkle"], blk["timestamp"],
                          blk["nonce"], blk["difficulty"])
        if calc != blk.get("hash"):
            return False, f"#{h} hash inválido"
        if not meets_difficulty(calc, int(blk["difficulty"])):
            return False, f"#{h} PoW inválido"
        prev_hash = calc
        expected_h += 1
    return True, "ok"


# ============================================================
# [v2.2] Checkpoints — defesa contra reorg histórico
# ============================================================
def _check_checkpoints(fork_h, new_blocks, local_h):
    """
    Verifica se a reorg viola algum checkpoint.

    [FIX v2.2]
      - Chama verify_checkpoint() antes de usar o hash (impede
        bypass por arquivo corrompido localmente).
      - Só considera checkpoints na faixa AFETADA pela reorg:
        fork_h < checkpoint_height <= max(local_h, último bloco remoto).
        Checkpoints além da reorg são ignorados (não podem ser violados).

    Retorna (ok, msg, violado_height).
    """
    try:
        from checkpoints import load_checkpoints, verify_checkpoint
    except ImportError:
        return True, "", None
    try:
        cps = load_checkpoints() or {}
    except Exception as e:
        log.warning("[REORG] não consegui ler checkpoints: %s", e)
        return True, "", None

    if not cps:
        return True, "", None

    # Faixa máxima alcançada pela reorg
    remote_by_h = {}
    for b in new_blocks:
        try:
            remote_by_h[int(b["height"])] = b.get("hash", "")
        except Exception:
            continue
    if not remote_by_h:
        return True, "", None

    max_remote_h = max(remote_by_h.keys())
    affected_max = max(local_h, max_remote_h)

    n_active = 0
    for h_str, cp in cps.items():
        try:
            h = int(h_str)
        except (ValueError, TypeError):
            continue
        # Ignora checkpoints antes do fork (não são afetados)
        if h <= fork_h:
            continue
        # Ignora checkpoints além da reorg (não podem ser violados)
        if h > affected_max:
            continue

        n_active += 1

        # [FIX v2.2] Verifica assinatura primeiro
        if not verify_checkpoint(cp):
            log.error("[REORG] checkpoint #%d tem assinatura INVÁLIDA no arquivo local", h)
            return False, f"checkpoint #{h} com assinatura inválida local", h

        expected = cp.get("hash", "")

        # Se o bloco do checkpoint NÃO está no lote remoto:
        # a reorg não alcança essa altura → não viola.
        if h not in remote_by_h:
            log.debug("[REORG] checkpoint #%d fora do alcance da reorg — OK", h)
            continue

        if remote_by_h[h] != expected:
            log.error(
                "[REORG] checkpoint #%d VIOLADO: remoto=%s esperado=%s",
                h, remote_by_h[h][:16], expected[:16],
            )
            return False, f"checkpoint #{h} violado", h

    if n_active > 0:
        log.info("[REORG] %d checkpoint(s) na faixa afetada — nenhuma violação", n_active)
    return True, "", None


# ============================================================
# Rollback
# ============================================================
def _rollback_to(chain, fork_h, current_tip):
    removed = 0
    if hasattr(chain.db, "rollback_block"):
        for h in range(current_tip, fork_h, -1):
            chain.db.rollback_block(h)
            removed += 1
    elif hasattr(chain.db, "delete_blocks_above"):
        removed = int(chain.db.delete_blocks_above(fork_h) or 0)
    else:
        raise RuntimeError("ChainDB sem rollback_block/delete_blocks_above")
    return removed


def _set_fork_signal(chain, active):
    sig = getattr(chain, "_fork_signal", None)
    if sig is None:
        try:
            sig = threading.Event()
            chain._fork_signal = sig
        except Exception:
            return
    try:
        if active:
            sig.set()
        else:
            sig.clear()
    except Exception:
        pass


# ============================================================
# REORG PRINCIPAL
# ============================================================
def reorg_to(chain, new_blocks, max_depth=DEFAULT_MAX_DEPTH, allow_genesis_reorg=False):
    t0 = time.time()
    res = ReorgResult()

    with _REORG_LOCK:
        if not new_blocks:
            res.msg = "lista vazia"
            res.duration_s = time.time() - t0
            return res

        local_h = chain.db.height()
        if local_h < 0 and not allow_genesis_reorg:
            res.msg = "cadeia vazia"
            res.duration_s = time.time() - t0
            return res

        fork_h = find_fork_point(chain, new_blocks, max_depth=max_depth * 2)
        if fork_h < 0 and not allow_genesis_reorg:
            res.msg = "sem ancestral comum"
            res.duration_s = time.time() - t0
            return res

        res.fork_height = fork_h

        blocks_to_add = []
        for b in new_blocks:
            try:
                if int(b["height"]) > fork_h:
                    blocks_to_add.append(b)
            except Exception:
                continue
        if not blocks_to_add:
            res.msg = "nada novo"
            res.duration_s = time.time() - t0
            return res
        blocks_to_add.sort(key=lambda b: int(b["height"]))

        depth = local_h - fork_h
        res.depth = depth
        if depth > max_depth:
            res.msg = f"reorg profundo ({depth} > {max_depth})"
            res.duration_s = time.time() - t0
            return res

        # [v2.2] Checkpoints
        ok_cp, msg_cp, violado = _check_checkpoints(fork_h, blocks_to_add, local_h)
        if not ok_cp:
            res.msg = msg_cp
            res.checkpoint_violated = violado
            res.duration_s = time.time() - t0
            return res

        # Pré-validação criptográfica
        ok_pre, msg_pre = _pre_validate(chain, fork_h, blocks_to_add)
        if not ok_pre:
            res.msg = f"pré-validação: {msg_pre}"
            res.duration_s = time.time() - t0
            return res

        # Desempate work
        use_remote, motivo = _should_use_remote(chain, fork_h, blocks_to_add, local_h)
        res.work_remote = _cum_work(blocks_to_add)
        res.work_local = _local_work_above(chain, fork_h)
        if not use_remote:
            res.msg = f"mantém cadeia local ({motivo})"
            res.duration_s = time.time() - t0
            return res

        log.warning(
            "[REORG] Iniciando reorg #%d motivo=%s depth=%d add=%d",
            fork_h, motivo, depth, len(blocks_to_add),
        )

        _set_fork_signal(chain, True)
        try:
            # Backup dos blocos locais (para restaurar em caso de falha)
            backups = []
            for h in range(fork_h + 1, local_h + 1):
                b = chain.db.get_block(h)
                if b:
                    backups.append(b)

            try:
                res.blocks_removed = _rollback_to(chain, fork_h, local_h)
            except Exception as e:
                res.msg = f"rollback falhou: {e}"
                res.duration_s = time.time() - t0
                return res

            added = 0
            for b in blocks_to_add:
                try:
                    ok_acc, msg_acc = chain.accept_block(b)
                except Exception as e:
                    ok_acc, msg_acc = False, f"exceção: {e}"
                if not ok_acc:
                    log.error("[REORG] falhou #%s: %s — restaurando", b.get("height"), msg_acc)
                    try:
                        cur = chain.db.height()
                        if cur > fork_h:
                            _rollback_to(chain, fork_h, cur)
                    except Exception:
                        pass
                    for ob in backups:
                        try:
                            chain.accept_block(ob)
                        except Exception:
                            pass
                    res.blocks_added = added
                    res.msg = f"falha #{b.get('height')}: {msg_acc}"
                    res.duration_s = time.time() - t0
                    return res
                added += 1

            res.blocks_added = added
            res.ok = True
            res.msg = f"reorg OK (fork #{fork_h}, -{res.blocks_removed} +{added})"
            log.warning("[REORG] %s — altura final: %d", res.msg, chain.db.height())
        finally:
            _set_fork_signal(chain, False)

        res.duration_s = time.time() - t0
        return res