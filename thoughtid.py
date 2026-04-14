#!/usr/bin/env python3
"""
ThoughtID v5.7 — Zero-Deception Integrity System
==================================================
Every thought gets a receipt. Every receipt gets tested.
Every test gets signed. Every signature gets checked.
31 attacks tested. 0 open breaches.

Mechanical anti-hallucination system for AI coding assistants.
Forces every factual claim through a tracked, cryptographically
signed verification pipeline. The AI cannot self-approve.

See README.md for full documentation.

COMMANDS:
    thoughtid.py create <claim>                  Register claim
    thoughtid.py prove <TID> <command>           Execute command as evidence
    thoughtid.py prove-file <TID> <path> <cmd>   Diff + execute as evidence
    thoughtid.py fail <TID> <evidence>           Mark disproven
    thoughtid.py retract <TID> <reason>          Withdraw claim
    thoughtid.py challenge                       Generate nonce for daemon
    thoughtid.py checkpoint                      Full reconciliation
    thoughtid.py verify                          Check Ed25519 signature
    thoughtid.py keygen                          Generate Ed25519 keypair
    thoughtid.py status / audit / history <TID>  Inspect
    thoughtid.py reset                           Destroy ledger
"""

import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# ── Paths (auto-detect project root from .git or cwd) ─────────
def _find_project_root():
    """Walk up from this script to find the git root or use cwd."""
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(10):
        if os.path.isdir(os.path.join(d, ".git")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return os.getcwd()

PROJECT_ROOT = _find_project_root()
CLAIMS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "claims")
LEDGER = os.path.join(CLAIMS_DIR, "ledger.jsonl")
COUNTER_FILE = os.path.join(CLAIMS_DIR, "tid_counter.txt")
CHALLENGE_FILE = os.path.join(CLAIMS_DIR, ".challenge")
RESPONSE_FILE = os.path.join(CLAIMS_DIR, ".response")
PUBLIC_KEY_FILE = os.path.join(CLAIMS_DIR, ".watcher_pubkey")
PRIVATE_KEY_FILE = os.path.expanduser("~/.thoughtid_private_key")

os.makedirs(CLAIMS_DIR, exist_ok=True)

MAX_TIDS_PER_SESSION = 30

SECURITY_KEYWORDS = frozenset([
    "security", "auth", "injection", "vulnerability", "exploit", "credential",
    "password", "token", "secret", "permission", "privilege", "sanitize",
    "xss", "csrf", "sqli", "rce", "ssrf", "encryption", "decrypt",
])

_STOP_WORDS = frozenset([
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "can", "to", "of", "in", "for", "on", "with",
    "at", "by", "from", "as", "all", "each", "every", "both", "few", "more",
    "most", "other", "some", "such", "no", "not", "only", "own", "same",
    "so", "than", "too", "very", "just", "that", "this", "it", "its",
    "and", "but", "or", "if", "up", "out",
])

GENERIC_TERMS = frozenset([
    "python", "version", "installed", "system", "file", "exists",
    "directory", "running", "process", "linux", "ubuntu", "bash",
    "true", "false", "success", "error", "output", "input",
    "disk", "memory", "cpu", "gpu", "path", "home", "user",
    "works", "working", "done", "complete", "completed", "ready",
    "check", "checked", "passed", "failed", "correct", "incorrect",
    "test", "tested", "result", "results", "successfully", "errors",
    "status", "fine", "okay", "fixed", "broken", "empty", "null",
    "none", "default", "value", "values", "data", "config", "set",
    "correctly", "properly", "right", "wrong", "good", "bad",
    "clean", "dirty", "updated", "changed", "applied", "removed",
])

TRUSTED_PATHS = ("/usr/", "/bin/", "/snap/")


# ── Utilities ──────────────────────────────────────────────────
def _next_tid():
    import fcntl
    lock_path = COUNTER_FILE + ".lock"
    with open(lock_path, "w") as lock_f:
        fcntl.flock(lock_f, fcntl.LOCK_EX)
        counter = 0
        if os.path.exists(COUNTER_FILE):
            try:
                counter = int(open(COUNTER_FILE).read().strip())
            except (ValueError, FileNotFoundError):
                pass
        counter += 1
        with open(COUNTER_FILE, "w") as f:
            f.write(str(counter))
        return f"TID-{counter:04d}"


def _append(event_dict):
    with open(LEDGER, "a") as f:
        f.write(json.dumps(event_dict, separators=(",", ":")) + "\n")


def _build_state():
    state = {}
    try:
        with open(LEDGER) as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                tid = ev.get("id", "")
                event = ev.get("event", "")
                if not tid or not event:
                    continue
                if tid not in state:
                    state[tid] = {"_create_count": 0, "_events": []}
                rec = state[tid]
                rec["_events"].append(event)
                rec["last_event"] = event
                rec["ts"] = ev.get("ts", "")
                if event == "CREATE":
                    rec["_create_count"] = rec.get("_create_count", 0) + 1
                    rec["topic"] = ev.get("topic", "")
                    rec["claim"] = ev.get("claim", "")
                elif event in ("VERIFY", "PENDING", "FAIL", "RETRACT"):
                    rec["evidence"] = ev.get("evidence", "")
                    rec["evidence_hash"] = ev.get("evidence_hash", "")
                    rec["filepath"] = ev.get("filepath", "")
                    rec["diff_hash"] = ev.get("diff_hash", "")
    except FileNotFoundError:
        pass
    return state


def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _auto_topic(claim):
    words = claim.split()[:5]
    return "-".join(w.lower().strip(".,;:!?") for w in words if w.strip(".,;:!?"))


def _extract_keywords(text):
    words = re.findall(r'[a-zA-Z0-9_]+', text.lower())
    return {w for w in words if len(w) >= 3 and w not in _STOP_WORDS}


def _is_security_claim(claim):
    return any(kw in claim.lower() for kw in SECURITY_KEYWORDS)


def _get_changed_files():
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
        )
        return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]
    except Exception:
        return []


def _load_public_key():
    try:
        return Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(open(PUBLIC_KEY_FILE).read().strip())
        )
    except Exception:
        return None


def _check_semantic_relevance(claim, command, output):
    claim_kw = _extract_keywords(claim)
    if not claim_kw:
        return True, 0, set(), set()
    combined = (command + " " + output).lower()
    matched = {kw for kw in claim_kw if kw in combined}
    overlap = len(matched) / len(claim_kw)
    ok = overlap >= 0.25 or len(matched) >= 2
    return ok, len(matched), claim_kw, matched


# ── Commands ───────────────────────────────────────────────────

def cmd_keygen():
    """Generate Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    priv_hex = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    pub_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    with open(PUBLIC_KEY_FILE, "w") as f:
        f.write(pub_hex)
    with open(PRIVATE_KEY_FILE, "w") as f:
        f.write(priv_hex)
    os.chmod(PRIVATE_KEY_FILE, 0o600)
    print("=" * 60)
    print("  ThoughtID — Ed25519 Keypair Generated")
    print("=" * 60)
    print(f"  Public key:  {PUBLIC_KEY_FILE}")
    print(f"  Private key: {PRIVATE_KEY_FILE}")
    print()
    print("  Lock the private key: sudo chattr +i " + PRIVATE_KEY_FILE)
    print("=" * 60)


def cmd_create(claim):
    state = _build_state()
    if len(state) >= MAX_TIDS_PER_SESSION:
        print(f"ERROR CODE 1: Session limit ({MAX_TIDS_PER_SESSION} TIDs).")
        sys.exit(1)

    # Verb check
    has_verb = bool(re.search(
        r'\b(compile[sd]?|pass(?:es|ed)?|fix(?:ed|es)?|add(?:ed|s)?|remov(?:ed|es)?|'
        r'rewir(?:ed|es)?|run(?:s|ning)?|return(?:s|ed)?|produc(?:es|ed)?|'
        r'persist(?:s|ed)?|handle[sd]?|detect(?:s|ed)?|block(?:s|ed)?|'
        r'updat(?:es|ed)?|verif(?:y|ied|ies)|creat(?:es|ed)?|'
        r'resolv(?:es|ed)?|match(?:es|ed)?|exceed(?:s|ed)?|'
        r'improv(?:es|ed)?|reduc(?:es|ed)?|increas(?:es|ed)?|'
        r'chang(?:es|ed)?|mov(?:es|ed)?|writ(?:es|ten)|read[s]?|'
        r'show(?:s|ed)?|display[sd]?|load(?:s|ed)?|sav(?:es|ed)?|'
        r'connect(?:s|ed)?|send(?:s)?|receiv(?:es|ed)?|'
        r'is|are|has|have|was|were|does|did)\b',
        claim.lower()
    ))
    if not has_verb:
        print("ERROR CODE 1: Claim has no verb. Must be a verifiable assertion.")
        sys.exit(1)

    # Vague check
    vague_patterns = [
        r'\bwill\b.*\bwork\b', r'\bshould\b.*\bwork\b', r'\bprobably\b',
        r'\bmight\b', r'\beverything\s+(is|works|passes)\b', r'\ball\s+good\b',
        r'\bno\s+issues\b', r'\bperfect\b', r'\blooks?\s+good\b',
    ]
    for pat in vague_patterns:
        if re.search(pat, claim.lower()):
            print(f"ERROR CODE 1: Claim too vague: matched '{pat}'")
            sys.exit(1)

    # Generic check
    project_terms = _extract_keywords(claim)
    specific = project_terms - GENERIC_TERMS
    if len(specific) < 1:
        print(f"ERROR CODE 1: No project-specific terms. Only generic: {sorted(project_terms)}")
        sys.exit(1)

    # Batch check
    conjunction_count = len(re.findall(
        r'\band\b|\bplus\b|\balso\b|\bthen\b|;\s*\w|,\s*(?:fixed|added|updated|changed|removed|modified|also|then)',
        claim.lower()
    ))
    if conjunction_count >= 1:
        print(f"ERROR CODE 1: Claim batches {conjunction_count + 1} changes. Split into separate TIDs.")
        sys.exit(1)

    tid = _next_tid()
    topic = _auto_topic(claim)
    _append({"id": tid, "event": "CREATE", "topic": topic, "claim": claim, "ts": _ts()})
    print(f"{tid} [{topic}]")


def cmd_prove(tid, command):
    state = _build_state()
    if tid not in state:
        print(f"ERROR CODE 1: {tid} not in ledger.")
        sys.exit(1)
    if state[tid]["last_event"] != "CREATE":
        print(f"ERROR CODE 1: {tid} not OPEN.")
        sys.exit(1)

    # Uncommitted file check
    changed_files = _get_changed_files()
    claim_text = state[tid].get("claim", "")
    if changed_files:
        for cf in changed_files:
            cf_base = os.path.basename(cf).replace(".py", "").replace("_", " ")
            if any(word in claim_text.lower() for word in cf_base.split() if len(word) > 3):
                print(f"ERROR CODE 1: Uncommitted file '{cf}' relates to this claim.")
                print(f"Use: thoughtid.py prove-file {tid} {cf} \"<command>\"")
                sys.exit(1)

    # Subprocess integrity: dual canary
    _canary_token = secrets.token_hex(8)
    _canary_cmd = f"python3 -c \"print('{_canary_token}')\""
    _c1 = subprocess.run(_canary_cmd, shell=True, capture_output=True, text=True, timeout=5)
    _c2 = subprocess.run(["python3", "-c", f"print('{_canary_token}')"], capture_output=True, text=True, timeout=5)
    if _canary_token not in _c1.stdout or _canary_token not in _c2.stdout:
        print("ERROR CODE 1: Subprocess canary failed. Environment compromised.")
        sys.exit(1)
    if _c1.stdout.strip() != _c2.stdout.strip():
        print("ERROR CODE 1: Subprocess canary diverge. Monkey-patch detected.")
        sys.exit(1)

    # Trusted PATH check
    cmd_parts = command.split()
    if cmd_parts:
        binary = cmd_parts[0]
        real_path = subprocess.run(
            ["which", binary], capture_output=True, text=True,
            env={**os.environ, "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
        ).stdout.strip()
        if real_path and not any(real_path.startswith(tp) for tp in TRUSTED_PATHS):
            print(f"ERROR CODE 1: '{binary}' in untrusted path: {real_path}")
            sys.exit(1)

    # Block destructive and trivial commands
    BLOCKED = [
        r'\brm\b', r'\bmv\b', r'\bchmod\b', r'\bchown\b', r'\bchattr\b',
        r'\bkill\b', r'\bsudo\b', r'\bdd\b', r'>\s*/', r'>\s*~',
        r'\bsed\s+-i\b', r'\btruncate\b', r'\bmkfs\b',
        r'>\s*\.\w', r'\beval\b', r'\bexec\b',
        r'^\s*echo\b', r'^\s*printf\b', r'^\s*cat\s*<<',
        r'^\s*true\s*$', r'^\s*false\s*$',
    ]
    for pat in BLOCKED:
        if re.search(pat, command.lower()):
            print(f"ERROR CODE 1: Blocked command pattern: {pat}")
            sys.exit(1)

    # Execute
    print(f"## EXECUTING: {command}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120, cwd=PROJECT_ROOT)
        exit_code = result.returncode
        output = result.stdout[-500:] if result.stdout else ""
        if exit_code != 0:
            print(f"## FAILED (exit {exit_code})")
            sys.exit(1)
        evidence = f"CMD:{command}|EXIT:{exit_code}|OUT:{output}"
        print(f"## EXIT: {exit_code}")
    except subprocess.TimeoutExpired:
        print("ERROR CODE 1: Command timed out.")
        sys.exit(1)

    # Semantic check
    relevant, mc, ckw, matched = _check_semantic_relevance(claim_text, command, output)
    if not relevant:
        print(f"## SEMANTIC FAILED: {mc}/{len(ckw)} keywords")
        sys.exit(1)
    elif matched:
        print(f"## SEMANTIC: {mc}/{len(ckw)} matched ({sorted(matched)[:5]})")

    eh = hashlib.sha256(evidence.encode()).hexdigest()
    _append({"id": tid, "event": "PENDING", "evidence": evidence, "evidence_hash": eh, "ts": _ts()})
    print(f"{tid} -> PENDING (sha256:{eh[:12]}...)")


def cmd_prove_file(tid, filepath, command):
    state = _build_state()
    if tid not in state:
        print(f"ERROR CODE 1: {tid} not in ledger.")
        sys.exit(1)
    if state[tid]["last_event"] != "CREATE":
        print(f"ERROR CODE 1: {tid} not OPEN.")
        sys.exit(1)
    fp_full = os.path.join(PROJECT_ROOT, filepath)
    if not os.path.isfile(fp_full):
        print(f"ERROR CODE 1: {filepath} not found.")
        sys.exit(1)

    # Filepath must relate to claim
    claim_text = state[tid].get("claim", "").lower()
    fp_base = os.path.basename(filepath).replace(".py", "").replace("_", " ").lower()
    fp_words = {w for w in fp_base.split() if len(w) >= 3}
    claim_words = _extract_keywords(claim_text)
    if not (fp_words & claim_words) and fp_base.replace(" ", "_") not in claim_text:
        print(f"ERROR CODE 1: File '{filepath}' does not relate to claim.")
        sys.exit(1)

    # Block trivial file commands
    TRIVIAL = [r'^\s*wc\b', r'^\s*stat\b', r'^\s*file\b', r'^\s*ls\b',
               r'^\s*head\b', r'^\s*tail\b', r'^\s*cat\b']
    for pat in TRIVIAL:
        if re.search(pat, command):
            print(f"ERROR CODE 1: '{command.split()[0]}' is trivial for file verification.")
            sys.exit(1)

    # Show diff
    diff = subprocess.run(["git", "diff", "HEAD", "--", filepath],
                         capture_output=True, text=True, cwd=PROJECT_ROOT).stdout
    if diff:
        print(f"## DIFF: {filepath} ({diff.count(chr(10))} lines):")
        print(diff)
        diff_hash = hashlib.sha256(diff.encode()).hexdigest()
    else:
        print(f"## {filepath} matches HEAD")
        diff_hash = "clean"

    # Execute command
    print(f"\n## EXECUTING: {command}")
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120, cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"## FAILED (exit {result.returncode})")
            sys.exit(1)
        output = result.stdout[-500:] if result.stdout else ""
        evidence = f"CMD:{command}|FILE:{filepath}|EXIT:{result.returncode}|OUT:{output}"
    except subprocess.TimeoutExpired:
        print("ERROR CODE 1: Timeout.")
        sys.exit(1)

    eh = hashlib.sha256(evidence.encode()).hexdigest()
    _append({"id": tid, "event": "PENDING", "evidence": evidence, "evidence_hash": eh,
             "filepath": filepath, "diff_hash": diff_hash, "ts": _ts()})
    print(f"\n{tid} -> PENDING (file:{filepath} sha256:{eh[:12]}...)")


def cmd_fail(tid, evidence):
    state = _build_state()
    if tid not in state or state[tid]["last_event"] not in ("CREATE", "PENDING"):
        print(f"ERROR CODE 1: {tid} not open/pending.")
        sys.exit(1)
    eh = hashlib.sha256(evidence.encode()).hexdigest()
    _append({"id": tid, "event": "FAIL", "evidence": evidence, "evidence_hash": eh, "ts": _ts()})
    print(f"{tid} -> FAILED")


def cmd_retract(tid, reason):
    state = _build_state()
    if tid not in state or state[tid]["last_event"] not in ("CREATE", "PENDING"):
        print(f"ERROR CODE 1: {tid} not open/pending.")
        sys.exit(1)
    if _is_security_claim(state[tid].get("claim", "")):
        if "FAIL" not in state[tid].get("_events", []):
            print("ERROR CODE 1: Security claim needs FAIL before RETRACT.")
            sys.exit(1)
    if len(reason.strip()) < 20:
        print("ERROR CODE 1: Retract reason too short (min 20 chars).")
        sys.exit(1)
    rh = hashlib.sha256(reason.encode()).hexdigest()
    _append({"id": tid, "event": "RETRACT", "evidence": reason, "evidence_hash": rh, "ts": _ts()})
    print(f"{tid} -> RETRACTED")


def cmd_challenge():
    state = _build_state()
    pending = [(t, r) for t, r in sorted(state.items()) if r["last_event"] in ("PENDING", "CREATE")]
    if not pending:
        print("TID: clean")
        return
    nonce = secrets.token_hex(16)
    with open(CHALLENGE_FILE, "w") as f:
        f.write(f"{nonce}|{int(time.time())}")
    print(f"GATE: {len(pending)} claims. Challenge: {nonce[:8]}...")
    for tid, rec in pending:
        print(f"  {tid} [{rec.get('topic','?')}]: {rec.get('claim','?')[:60]}")


def cmd_approve():
    """Sign pending claims. Run by Watcher daemon or manually."""
    try:
        priv_hex = open(PRIVATE_KEY_FILE).read().strip()
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    except Exception:
        print(f"ERROR: No private key at {PRIVATE_KEY_FILE}")
        sys.exit(1)
    if not os.path.exists(CHALLENGE_FILE):
        print("ERROR: No challenge.")
        sys.exit(1)
    challenge = open(CHALLENGE_FILE).read().strip()
    try:
        age = int(time.time()) - int(challenge.split("|")[1])
        if age > 600:
            print(f"ERROR: Challenge expired ({age}s).")
            sys.exit(1)
    except (IndexError, ValueError):
        sys.exit(1)

    state = _build_state()
    pending = sorted(t for t, r in state.items() if r["last_event"] in ("PENDING", "CREATE"))
    if not pending:
        print("Nothing to approve.")
        sys.exit(0)

    msg = f"{challenge}|{','.join(pending)}".encode()
    sig = private_key.sign(msg).hex()
    ts = _ts()
    tag = f"ED25519:{sig[:24]}"
    eh = hashlib.sha256(tag.encode()).hexdigest()
    for tid in pending:
        _append({"id": tid, "event": "VERIFY", "evidence": tag, "evidence_hash": eh, "ts": ts})
    with open(RESPONSE_FILE, "w") as f:
        f.write(json.dumps({"challenge": challenge, "approved": pending, "signature": sig, "ts": ts}))
    os.remove(CHALLENGE_FILE)
    print(f"{len(pending)} claims signed.")
    for tid in pending:
        print(f"  {tid} -> VERIFIED (sig:{sig[:16]}...)")


def _verify_response():
    if not os.path.exists(RESPONSE_FILE):
        return False, "No response"
    pub = _load_public_key()
    if not pub:
        return False, "No public key"
    try:
        data = json.loads(open(RESPONSE_FILE).read())
        msg = f"{data['challenge']}|{','.join(data['approved'])}".encode()
        pub.verify(bytes.fromhex(data["signature"]), msg)
        return True, f"{len(data['approved'])}V sig:valid"
    except Exception as e:
        return False, f"INVALID: {e}"


def cmd_verify():
    ok, msg = _verify_response()
    print(f"GATE: {'PASS' if ok else 'FAIL'} - {msg}")
    sys.exit(0 if ok else 1)


def cmd_checkpoint():
    state = _build_state()
    if not state:
        print("TID: clean")
        return
    open_claims = []
    verified = failed = retracted = tampered = 0
    for tid, rec in sorted(state.items()):
        if rec.get("_create_count", 1) > 1:
            tampered += 1
            open_claims.append((tid, rec, "REWIND"))
            continue
        ev = rec["last_event"]
        if ev in ("CREATE", "PENDING"):
            open_claims.append((tid, rec, "UNVERIFIED"))
        elif ev == "VERIFY":
            eh = rec.get("evidence_hash", "")
            ev_text = rec.get("evidence", "")
            if eh and ev_text:
                if hashlib.sha256(ev_text.encode()).hexdigest() != eh:
                    tampered += 1
                    open_claims.append((tid, rec, "SHA256"))
                    continue
            verified += 1
        elif ev == "FAIL":
            failed += 1
        elif ev == "RETRACT":
            retracted += 1

    sig_ok, sig_msg = _verify_response()
    if open_claims or tampered or (verified > 0 and not sig_ok):
        print(f"CHECKPOINT: {len(state)} | {verified}V {failed}F {retracted}R {len(open_claims)}O {tampered}T")
        if not sig_ok and verified > 0:
            print(f"  ED25519: {sig_msg}")
        print("\nERROR CODE 1: UNRESOLVED")
        for tid, rec, reason in open_claims:
            print(f"  {tid} [{rec.get('topic','?')}]: {rec.get('claim','?')[:60]} ({reason})")
        sys.exit(1)
    elif failed:
        print(f"TID: {verified}V {failed}F {retracted}R 0O {'sig:valid' if sig_ok else 'sig:none'} warn")
    else:
        print(f"TID: {verified}V {failed}F {retracted}R 0O {'sig:valid' if sig_ok else 'sig:none'} pass")


def cmd_status():
    state = _build_state()
    if not state:
        print("TID: empty")
        return
    counts = {}
    for rec in state.values():
        label = {"CREATE": "OPEN", "PENDING": "PENDING", "VERIFY": "VERIFIED",
                 "FAIL": "FAILED", "RETRACT": "RETRACTED"}.get(rec["last_event"], "?")
        counts[label] = counts.get(label, 0) + 1
    print(f"TID: {len(state)} | " + " ".join(f"{k}:{v}" for k, v in sorted(counts.items())))


def cmd_audit():
    print("=== THOUGHTID AUDIT ===")
    state = _build_state()
    if not state:
        print("Empty.")
        return
    for tid in sorted(state):
        rec = state[tid]
        mark = {"CREATE": "?", "PENDING": "P", "VERIFY": "V", "FAIL": "X", "RETRACT": "R"}.get(rec["last_event"], "?")
        line = f"[{mark}] {tid} [{rec.get('topic','?')}] {rec.get('claim','?')[:80]}"
        if rec.get("_create_count", 1) > 1:
            line += " !! REWIND"
        print(line)
    ok, msg = _verify_response()
    print(f"\nEd25519: {msg}")


def cmd_history(tid):
    try:
        events = []
        with open(LEDGER) as f:
            for line in f:
                try:
                    ev = json.loads(line.strip())
                    if ev.get("id") == tid:
                        events.append(ev)
                except json.JSONDecodeError:
                    continue
        if not events:
            print(f"ERROR: {tid} not found.")
            sys.exit(1)
        print(f"=== {tid}: {len(events)} events ===")
        for ev in events:
            et = ev.get("event", "?")
            ts = ev.get("ts", "?")
            parts = [f"  [{et}] {ts}"]
            if et == "CREATE":
                parts.append(f'claim="{ev.get("claim","?")[:60]}"')
            elif et == "PENDING":
                evidence = ev.get("evidence", "")
                if evidence.startswith("CMD:"):
                    parts.append(f"cmd={evidence.split('|')[0][4:][:50]}")
            print(" ".join(parts))
    except FileNotFoundError:
        print("No ledger.")
        sys.exit(1)


def cmd_reset():
    import glob
    for f in glob.glob(os.path.join(CLAIMS_DIR, "*")):
        if not f.endswith(".watcher_pubkey"):
            try:
                os.remove(f)
            except (IsADirectoryError, PermissionError):
                pass
    for f in glob.glob(os.path.join(CLAIMS_DIR, "*.lock")):
        os.remove(f)
    print("ThoughtID reset. Keys preserved.")


# ── Main ───────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    c = sys.argv[1]
    try:
        if c == "keygen":
            cmd_keygen()
        elif c == "create" and len(sys.argv) >= 3:
            cmd_create(" ".join(sys.argv[2:]))
        elif c == "prove" and len(sys.argv) >= 4:
            cmd_prove(sys.argv[2], " ".join(sys.argv[3:]))
        elif c == "prove-file" and len(sys.argv) >= 5:
            cmd_prove_file(sys.argv[2], sys.argv[3], " ".join(sys.argv[4:]))
        elif c == "fail" and len(sys.argv) >= 4:
            cmd_fail(sys.argv[2], " ".join(sys.argv[3:]))
        elif c == "retract" and len(sys.argv) >= 4:
            cmd_retract(sys.argv[2], " ".join(sys.argv[3:]))
        elif c == "challenge":
            cmd_challenge()
        elif c == "approve":
            cmd_approve()
        elif c == "verify":
            cmd_verify()
        elif c == "checkpoint":
            cmd_checkpoint()
        elif c == "status":
            cmd_status()
        elif c == "audit":
            cmd_audit()
        elif c == "history" and len(sys.argv) >= 3:
            cmd_history(sys.argv[2])
        elif c == "reset":
            cmd_reset()
        else:
            print(f"Unknown: {c}. Run without args for help.")
            sys.exit(1)
    except BrokenPipeError:
        pass
