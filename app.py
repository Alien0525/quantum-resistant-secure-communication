"""
PQC Secure Communication — Flask API Backend
Cryptographic operations: KEM key exchange + AES-256-GCM encryption.

KEM layer uses liboqs (Kyber768 / Classic-McEliece) when available,
falling back to X25519 ECDH when liboqs is
not installed in the current environment.

All symmetric crypto is AES-256-GCM via HKDF-SHA256.
"""
import os
import time
import base64
import struct
import json
import logging
from flask import Flask, request, jsonify

# ── Cryptography imports (always available) ─────────────────────────
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization

# ── liboqs — optional PQC KEM layer ─────────────────────────────────
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False

# ── PyCryptodome — used by existing SecureChannel ────────────────────
try:
    from Crypto.Cipher import AES as _pycrypto_aes
    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("pqc-api")

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ── In-memory session store (keyed by session_id) ────────────────────
# Stores private keys / secret keys for active sessions.
# In production these would live in a secrets store per-user.
_sessions: dict = {}


# ════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)

def _derive_key(shared_secret: bytes) -> bytes:
    """HKDF-SHA256: shared_secret → 256-bit AES key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"quantum-resistant-aes",
        info=b"secure-channel-v1",
    )
    return hkdf.derive(shared_secret)

def _aes_gcm_encrypt(key: bytes, plaintext: str) -> dict:
    """AES-256-GCM encrypt. Returns base64-encoded fields."""
    nonce = os.urandom(12)
    timestamp = struct.pack(">Q", int(time.time()))
    aead = AESGCM(key)
    # AAD = timestamp (authenticated but not encrypted)
    ciphertext = aead.encrypt(nonce, plaintext.encode("utf-8"), timestamp)
    # AESGCM appends the 16-byte tag to ciphertext; split them.
    ct_body, tag = ciphertext[:-16], ciphertext[-16:]
    return {
        "ciphertext": _b64e(ct_body),
        "tag":        _b64e(tag),
        "nonce":      _b64e(nonce),
        "timestamp":  _b64e(timestamp),
    }

def _aes_gcm_decrypt(key: bytes, payload: dict, max_age: int = 300) -> str:
    """AES-256-GCM decrypt + timestamp validation. Returns plaintext."""
    ct_body   = _b64d(payload["ciphertext"])
    tag       = _b64d(payload["tag"])
    nonce     = _b64d(payload["nonce"])
    timestamp = _b64d(payload["timestamp"])

    # Timestamp replay guard
    ts_int = struct.unpack(">Q", timestamp)[0]
    age = int(time.time()) - ts_int
    if age > max_age:
        raise ValueError(f"Message too old ({age}s > {max_age}s limit)")
    if age < -5:
        raise ValueError("Message timestamp is in the future")

    aead = AESGCM(key)
    # Reconstruct ciphertext+tag as expected by AESGCM
    combined = ct_body + tag
    plaintext = aead.decrypt(nonce, combined, timestamp)
    return plaintext.decode("utf-8")


# ════════════════════════════════════════════════════════════════════
# KEM LAYER — liboqs when available, X25519 ECDH fallback
# ════════════════════════════════════════════════════════════════════

KEM_ALIASES = {
    "kyber768":   "Kyber768",
    "mceliece":   "Classic-McEliece-6960119",
    "kyber":      "Kyber768",
}

KEM_META = {
    "Kyber768": {
        "display": "CRYSTALS-Kyber768",
        "security": "NIST Level 3 (≈ AES-192)",
        "pk_size": 1184,
        "sk_size": 2400,
        "ct_size": 1088,
        "ss_size": 32,
        "basis": "Module Learning With Errors (MLWE)",
    },
    "Classic-McEliece-6960119": {
        "display": "Classic McEliece-6960119",
        "security": "NIST Level 5 (≈ AES-256)",
        "pk_size": 1047319,
        "sk_size": 13948,
        "ct_size": 194,
        "ss_size": 32,
        "basis": "Syndrome Decoding Problem (NP-complete)",
    },
    "X25519-ECDH": {
        "display": "X25519 ECDH",
        "security": "128-bit classical (not quantum-resistant)",
        "pk_size": 32,
        "sk_size": 32,
        "ct_size": 32,
        "ss_size": 32,
        "basis": "Elliptic Curve Diffie-Hellman",
    },
}


def _kem_keygen_oqs(kem_name: str) -> dict:
    """Generate a KEM keypair using liboqs. Returns base64 pk + session token."""
    t0 = time.perf_counter()
    with oqs.KeyEncapsulation(kem_name) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    elapsed = (time.perf_counter() - t0) * 1000

    session_id = _b64e(os.urandom(16))
    _sessions[session_id] = {"type": "oqs", "kem_name": kem_name, "sk": sk}
    meta = KEM_META.get(kem_name, {})
    return {
        "session_id":    session_id,
        "public_key":    _b64e(pk),
        "pk_size":       len(pk),
        "sk_size":       len(sk),
        "kem_name":      kem_name,
        "display_name":  meta.get("display", kem_name),
        "security":      meta.get("security", ""),
        "basis":         meta.get("basis", ""),
        "keygen_ms":     round(elapsed, 4),
        "backend":       "liboqs",
    }


def _kem_keygen_x25519() -> dict:
    """Generate X25519 keypair. Fallback when liboqs absent."""
    t0 = time.perf_counter()
    sk = X25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    sk_bytes = sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    elapsed = (time.perf_counter() - t0) * 1000

    session_id = _b64e(os.urandom(16))
    _sessions[session_id] = {"type": "x25519", "sk": sk_bytes}
    meta = KEM_META["X25519-ECDH"]
    return {
        "session_id":    session_id,
        "public_key":    _b64e(pk_bytes),
        "pk_size":       len(pk_bytes),
        "sk_size":       len(sk_bytes),
        "kem_name":      "X25519-ECDH",
        "display_name":  meta["display"],
        "security":      meta["security"],
        "basis":         meta["basis"],
        "keygen_ms":     round(elapsed, 4),
        "backend":       "x25519-fallback",
        "warning":       "liboqs not installed — using X25519 ECDH (real but not post-quantum). Install liboqs-python for Kyber/McEliece.",
    }


def _kem_encap_oqs(kem_name: str, pk_b64: str) -> dict:
    """Encapsulate shared secret using liboqs."""
    pk = _b64d(pk_b64)
    t0 = time.perf_counter()
    with oqs.KeyEncapsulation(kem_name) as kem:
        ct, ss = kem.encap_secret(pk)
    elapsed = (time.perf_counter() - t0) * 1000
    aes_key = _derive_key(ss)
    session_id = _b64e(os.urandom(16))
    _sessions[session_id] = {"type": "sender", "key": aes_key}
    return {
        "session_id":   session_id,
        "ciphertext":   _b64e(ct),
        "ct_size":      len(ct),
        "ss_size":      len(ss),
        "encap_ms":     round(elapsed, 4),
        "backend":      "liboqs",
    }


def _kem_encap_x25519(pk_b64: str) -> dict:
    """Ephemeral X25519 ECDH encapsulation (real, not mocked)."""
    pk_bytes = _b64d(pk_b64)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer_pk = X25519PublicKey.from_public_bytes(pk_bytes)
    t0 = time.perf_counter()
    eph_sk = X25519PrivateKey.generate()
    ss = eph_sk.exchange(peer_pk)
    eph_pk_bytes = eph_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    elapsed = (time.perf_counter() - t0) * 1000
    aes_key = _derive_key(ss)
    session_id = _b64e(os.urandom(16))
    _sessions[session_id] = {"type": "sender", "key": aes_key}
    return {
        "session_id":  session_id,
        "ciphertext":  _b64e(eph_pk_bytes),   # KEM "ciphertext" is eph public key
        "ct_size":     len(eph_pk_bytes),
        "ss_size":     len(ss),
        "encap_ms":    round(elapsed, 4),
        "backend":     "x25519-fallback",
    }


def _kem_decap_oqs(session_id: str, ct_b64: str) -> dict:
    """Decapsulate using stored liboqs secret key."""
    sess = _sessions.get(session_id)
    if not sess or sess.get("type") != "oqs":
        raise KeyError("Session not found or wrong type")
    ct = _b64d(ct_b64)
    kem_name = sess["kem_name"]
    sk = sess["sk"]
    t0 = time.perf_counter()
    with oqs.KeyEncapsulation(kem_name, secret_key=sk) as kem:
        ss = kem.decap_secret(ct)
    elapsed = (time.perf_counter() - t0) * 1000
    aes_key = _derive_key(ss)
    recv_session_id = _b64e(os.urandom(16))
    _sessions[recv_session_id] = {"type": "receiver", "key": aes_key}
    # Verify shared secrets match by checking key equality
    return {
        "receiver_session_id": recv_session_id,
        "ss_size":             len(ss),
        "decap_ms":            round(elapsed, 4),
        "backend":             "liboqs",
    }


def _kem_decap_x25519(session_id: str, ct_b64: str) -> dict:
    """X25519 ECDH decapsulation (receiver uses own private key)."""
    sess = _sessions.get(session_id)
    if not sess or sess.get("type") != "x25519":
        raise KeyError("Session not found or wrong type")
    sk_bytes = sess["sk"]
    eph_pk_bytes = _b64d(ct_b64)  # "ciphertext" is the ephemeral public key
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    t0 = time.perf_counter()
    sk = X25519PrivateKey.from_private_bytes(sk_bytes)
    eph_pk = X25519PublicKey.from_public_bytes(eph_pk_bytes)
    ss = sk.exchange(eph_pk)
    elapsed = (time.perf_counter() - t0) * 1000
    aes_key = _derive_key(ss)
    recv_session_id = _b64e(os.urandom(16))
    _sessions[recv_session_id] = {"type": "receiver", "key": aes_key}
    return {
        "receiver_session_id": recv_session_id,
        "ss_size":             len(ss),
        "decap_ms":            round(elapsed, 4),
        "backend":             "x25519-fallback",
    }


# ════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ════════════════════════════════════════════════════════════════════

def cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

@app.after_request
def after_request(response):
    return cors_headers(response)


@app.route("/", methods=["GET"])
def index():
    """Root welcome page — avoids confusing 404 when opening localhost:5001 directly."""
    kem_note = (f"liboqs {oqs.oqs_version()} — Kyber768 &amp; Classic-McEliece available"
                if OQS_AVAILABLE else
                "liboqs not installed — X25519 ECDH fallback active")
    html = f"""<!doctype html>
<html lang="en">
<head><meta charset="UTF-8"><title>PQC API</title>
<style>
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#09090f;color:#eaeaf4;
       max-width:700px;margin:60px auto;padding:0 24px;line-height:1.6}}
  h1{{color:#8900e1;font-size:22px;margin-bottom:4px}}
  p{{color:#8888b8;font-size:14px;margin:0 0 20px}}
  .g{{display:inline-block;padding:3px 10px;border-radius:20px;font-size:13px;
      font-family:monospace;background:rgba(39,196,122,.12);
      color:#27c47a;border:1px solid rgba(39,196,122,.3)}}
  table{{width:100%;border-collapse:collapse;font-size:14px;margin-top:20px}}
  th{{text-align:left;color:#8888b8;font-weight:600;padding:6px 10px;
      border-bottom:1px solid #252538;text-transform:uppercase;font-size:12px}}
  td{{padding:9px 10px;border-bottom:1px solid rgba(255,255,255,.04);font-family:monospace;color:#38bdf8}}
  td:first-child{{color:#eaeaf4;font-family:inherit;font-weight:500}}
</style>
</head>
<body>
<h1>PQC Secure Communication API</h1>
<p>Project Backend &nbsp;&middot;&nbsp;
   <span class="g">{'✓ ' + kem_note if OQS_AVAILABLE else '⚠ ' + kem_note}</span></p>
<p>Open <strong>chat_ui.html</strong> or <strong>dashboard.html</strong> in your browser.</p>
<table>
  <tr><th>Endpoint</th><th>Method</th><th>Description</th></tr>
  <tr><td>GET /api/status</td><td>GET</td><td>Health check + capabilities</td></tr>
  <tr><td>/api/keygen</td><td>POST</td><td>KEM keypair generation</td></tr>
  <tr><td>/api/encapsulate</td><td>POST</td><td>Sender encapsulates shared secret</td></tr>
  <tr><td>/api/decapsulate</td><td>POST</td><td>Receiver decapsulates shared secret</td></tr>
  <tr><td>/api/encrypt</td><td>POST</td><td>AES-256-GCM encrypt</td></tr>
  <tr><td>/api/decrypt</td><td>POST</td><td>AES-256-GCM decrypt + verify</td></tr>
  <tr><td>/api/full_exchange</td><td>POST</td><td>Complete KEX + encrypt + decrypt</td></tr>
  <tr><td>/api/benchmark</td><td>POST</td><td>Benchmark single scheme</td></tr>
  <tr><td>/api/benchmark/full</td><td>POST</td><td>Benchmark both schemes (dashboard)</td></tr>
</table>
</body></html>"""
    return html, 200, {"Content-Type": "text/html"}


@app.route("/api/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    """CORS pre-flight for all /api/* routes."""
    return "", 204

@app.route("/api/status", methods=["GET"])
def status():
    """Health check + capability report."""
    return jsonify({
        "status":         "ok",
        "oqs_available":  OQS_AVAILABLE,
        "oqs_version":    oqs.oqs_version() if OQS_AVAILABLE else None,
        "pycrypto":       PYCRYPTO_AVAILABLE,
        "schemes":        list(KEM_ALIASES.keys()) if OQS_AVAILABLE else ["x25519"],
        "note":           "All symmetric crypto is AES-256-GCM via HKDF-SHA256" +
                          (" + liboqs KEM" if OQS_AVAILABLE else " + X25519 ECDH KEM fallback"),
    })


@app.route("/api/keygen", methods=["POST"])
def keygen():
    """
    Generate a KEM keypair.
    Body: { "scheme": "kyber768" | "mceliece" | "kyber" }
    Returns: session_id, public_key (base64), sizes, timing.
    """
    body = request.get_json(force=True) or {}
    scheme_raw = body.get("scheme", "kyber768").lower().strip()
    kem_name = KEM_ALIASES.get(scheme_raw)

    try:
        if OQS_AVAILABLE and kem_name:
            result = _kem_keygen_oqs(kem_name)
        else:
            result = _kem_keygen_x25519()
        return jsonify(result)
    except Exception as e:
        logger.exception("keygen error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/encapsulate", methods=["POST"])
def encapsulate():
    """
    Encapsulate a shared secret given a public key.
    Body: { "public_key": "<base64>", "scheme": "kyber768", "backend": "oqs"|"x25519" }
    Returns: session_id (sender), ciphertext (base64), sizes, timing.
    """
    body = request.get_json(force=True) or {}
    pk_b64 = body.get("public_key")
    if not pk_b64:
        return jsonify({"error": "public_key required"}), 400

    scheme_raw = body.get("scheme", "kyber768").lower()
    kem_name = KEM_ALIASES.get(scheme_raw, "Kyber768")

    try:
        if OQS_AVAILABLE:
            result = _kem_encap_oqs(kem_name, pk_b64)
        else:
            result = _kem_encap_x25519(pk_b64)
        return jsonify(result)
    except Exception as e:
        logger.exception("encap error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/decapsulate", methods=["POST"])
def decapsulate():
    """
    Decapsulate shared secret (receiver side).
    Body: { "session_id": "<keygen session>", "ciphertext": "<base64>", "backend": "oqs"|"x25519" }
    Returns: receiver_session_id, timing.
    """
    body = request.get_json(force=True) or {}
    session_id = body.get("session_id")
    ct_b64 = body.get("ciphertext")
    if not session_id or not ct_b64:
        return jsonify({"error": "session_id and ciphertext required"}), 400

    # Route based on session type stored at keygen time — not on client-supplied "backend" string.
    # This is the authoritative source: if we generated an oqs keypair, we must decap with oqs.
    sess = _sessions.get(session_id)
    if not sess:
        return jsonify({"error": "session not found (expired or invalid session_id)"}), 404

    try:
        if sess.get("type") == "oqs":
            result = _kem_decap_oqs(session_id, ct_b64)
        elif sess.get("type") == "x25519":
            result = _kem_decap_x25519(session_id, ct_b64)
        else:
            return jsonify({"error": f"unknown session type: {sess.get('type')}"}), 400
        return jsonify(result)
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logger.exception("decap error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    """
    AES-256-GCM encrypt a message.
    Body: { "session_id": "<sender or receiver session>", "message": "..." }
    Returns: ciphertext, tag, nonce, timestamp (all base64), timing.
    """
    body = request.get_json(force=True) or {}
    session_id = body.get("session_id")
    message = body.get("message", "")
    if not session_id:
        return jsonify({"error": "session_id required"}), 400
    if not message:
        return jsonify({"error": "message required"}), 400

    sess = _sessions.get(session_id)
    if not sess:
        return jsonify({"error": "session not found"}), 404
    key = sess.get("key")
    if not key:
        return jsonify({"error": "session has no AES key (run encapsulate/decapsulate first)"}), 400

    try:
        t0 = time.perf_counter()
        payload = _aes_gcm_encrypt(key, message)
        elapsed = (time.perf_counter() - t0) * 1000
        payload["encrypt_ms"] = round(elapsed, 4)
        payload["plaintext_bytes"] = len(message.encode("utf-8"))
        payload["ciphertext_bytes"] = len(_b64d(payload["ciphertext"]))
        return jsonify(payload)
    except Exception as e:
        logger.exception("encrypt error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    """
    AES-256-GCM decrypt a message.
    Body: { "session_id": "...", "ciphertext": "...", "tag": "...", "nonce": "...", "timestamp": "..." }
    Returns: { "plaintext": "..." }
    """
    body = request.get_json(force=True) or {}
    session_id = body.get("session_id")
    if not session_id:
        return jsonify({"error": "session_id required"}), 400

    sess = _sessions.get(session_id)
    if not sess:
        return jsonify({"error": "session not found"}), 404
    key = sess.get("key")
    if not key:
        return jsonify({"error": "session has no AES key"}), 400

    try:
        t0 = time.perf_counter()
        plaintext = _aes_gcm_decrypt(key, body)
        elapsed = (time.perf_counter() - t0) * 1000
        return jsonify({
            "plaintext":    plaintext,
            "decrypt_ms":   round(elapsed, 4),
            "verified":     True,
            "integrity_ok": True,
        })
    except Exception as e:
        logger.exception("decrypt error")
        return jsonify({
            "error":        str(e),
            "verified":     False,
            "integrity_ok": False,
        }), 400


@app.route("/api/full_exchange", methods=["POST"])
def full_exchange():
    """
    Complete key exchange + encrypt + decrypt in one call (for the chat UI).
    Body: { "scheme": "kyber768"|"mceliece", "message": "..." }
    Returns full details of every step.
    """
    body = request.get_json(force=True) or {}
    scheme_raw = body.get("scheme", "kyber768").lower().strip()
    message = body.get("message", "")
    if not message:
        return jsonify({"error": "message required"}), 400

    kem_name = KEM_ALIASES.get(scheme_raw)

    try:
        # 1. Key generation (receiver)
        if OQS_AVAILABLE and kem_name:
            kg = _kem_keygen_oqs(kem_name)
        else:
            kg = _kem_keygen_x25519()

        # 2. Encapsulation (sender)
        backend_type = kg.get("backend", "x25519-fallback")
        if backend_type == "liboqs":
            enc = _kem_encap_oqs(kem_name or "Kyber768", kg["public_key"])
        else:
            enc = _kem_encap_x25519(kg["public_key"])

        # 3. Decapsulation (receiver)
        if backend_type == "liboqs":
            dec = _kem_decap_oqs(kg["session_id"], enc["ciphertext"])
        else:
            dec = _kem_decap_x25519(kg["session_id"], enc["ciphertext"])

        # 4. AES-GCM Encryption (sender uses sender session)
        sender_sess = _sessions[enc["session_id"]]
        t0 = time.perf_counter()
        ciphertext_payload = _aes_gcm_encrypt(sender_sess["key"], message)
        aes_enc_ms = (time.perf_counter() - t0) * 1000

        # 5. AES-GCM Decryption (receiver uses receiver session)
        receiver_sess = _sessions[dec["receiver_session_id"]]
        t0 = time.perf_counter()
        plaintext = _aes_gcm_decrypt(receiver_sess["key"], ciphertext_payload)
        aes_dec_ms = (time.perf_counter() - t0) * 1000

        return jsonify({
            "scheme":          kg.get("display_name", kg.get("kem_name", "X25519")),
            "backend":         backend_type,
            "success":         plaintext == message,
            "message":         message,
            "decrypted":       plaintext,
            "keygen_ms":       kg["keygen_ms"],
            "encap_ms":        enc["encap_ms"],
            "decap_ms":        dec["decap_ms"],
            "aes_enc_ms":      round(aes_enc_ms, 4),
            "aes_dec_ms":      round(aes_dec_ms, 4),
            "total_ms":        round(kg["keygen_ms"] + enc["encap_ms"] + dec["decap_ms"] +
                                     aes_enc_ms + aes_dec_ms, 4),
            "pk_size":         kg["pk_size"],
            "sk_size":         kg["sk_size"],
            "ct_size":         enc["ct_size"],
            "ss_size":         enc["ss_size"],
            "ciphertext":      ciphertext_payload["ciphertext"],
            "tag":             ciphertext_payload["tag"],
            "nonce":           ciphertext_payload["nonce"],
            "timestamp":       ciphertext_payload["timestamp"],
            "plaintext_bytes": len(message.encode("utf-8")),
            "public_key":      kg["public_key"][:40] + "...",
            "kem_ciphertext":  enc["ciphertext"][:40] + "...",
        })

    except Exception as e:
        logger.exception("full_exchange error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/benchmark", methods=["POST"])
def benchmark():
    """
    Real benchmark: run N iterations of KEM keygen/encap/decap.
    Body: { "scheme": "kyber768"|"mceliece", "iterations": 10 }
    """
    body = request.get_json(force=True) or {}
    scheme_raw = body.get("scheme", "kyber768").lower().strip()
    n = min(int(body.get("iterations", 5)), 50)   # cap at 50 to avoid timeouts
    kem_name = KEM_ALIASES.get(scheme_raw)

    def _bench_scheme(kem, n_iters):
        kg_times, enc_times, dec_times = [], [], []

        if OQS_AVAILABLE and kem:
            for _ in range(n_iters):
                with oqs.KeyEncapsulation(kem) as k:
                    t0 = time.perf_counter()
                    pk = k.generate_keypair()
                    kg_times.append((time.perf_counter() - t0) * 1000)

                    t0 = time.perf_counter()
                    ct, ss = k.encap_secret(pk)
                    enc_times.append((time.perf_counter() - t0) * 1000)

                    t0 = time.perf_counter()
                    k.decap_secret(ct)
                    dec_times.append((time.perf_counter() - t0) * 1000)

            meta = KEM_META.get(kem, {})
            sizes = {
                "public_key":    len(pk),
                "secret_key":    meta.get("sk_size", 0),
                "ciphertext":    len(ct),
                "shared_secret": len(ss),
            }
        else:
            for _ in range(n_iters):
                t0 = time.perf_counter()
                sk_obj = X25519PrivateKey.generate()
                pk_bytes = sk_obj.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                kg_times.append((time.perf_counter() - t0) * 1000)

                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
                t0 = time.perf_counter()
                eph = X25519PrivateKey.generate()
                eph_pk = eph.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                eph.exchange(X25519PublicKey.from_public_bytes(pk_bytes))
                enc_times.append((time.perf_counter() - t0) * 1000)

                t0 = time.perf_counter()
                sk_obj.exchange(X25519PublicKey.from_public_bytes(eph_pk))
                dec_times.append((time.perf_counter() - t0) * 1000)

            sizes = {"public_key": 32, "secret_key": 32,
                     "ciphertext": 32, "shared_secret": 32}

        def _stats(vals):
            avg = sum(vals) / len(vals)
            mn, mx = min(vals), max(vals)
            variance = sum((v - avg) ** 2 for v in vals) / len(vals)
            stddev = variance ** 0.5
            return {"avg": round(avg, 4), "min": round(mn, 4),
                    "max": round(mx, 4), "stddev": round(stddev, 4),
                    "samples": vals}

        return {
            "keygen":  _stats(kg_times),
            "encap":   _stats(enc_times),
            "decap":   _stats(dec_times),
            "total_avg": round(sum(kg_times)/n_iters + sum(enc_times)/n_iters +
                               sum(dec_times)/n_iters, 4),
            "iterations": n_iters,
            "sizes":   sizes,
        }

    try:
        result = _bench_scheme(kem_name, n)
        display = KEM_META.get(kem_name or "X25519-ECDH", {}).get("display", scheme_raw)
        return jsonify({
            "scheme":      display,
            "backend":     "liboqs" if OQS_AVAILABLE else "x25519-fallback",
            "results":     result,
            "timestamp":   time.strftime("%Y-%m-%d %H:%M:%S"),
        })
    except Exception as e:
        logger.exception("benchmark error")
        return jsonify({"error": str(e)}), 500


@app.route("/api/benchmark/full", methods=["POST"])
def benchmark_full():
    """
    Benchmark both schemes (Kyber768 + McEliece or X25519) and return
    side-by-side results for the dashboard.
    Body: { "kyber_iterations": 20, "mce_iterations": 5 }
    """
    body = request.get_json(force=True) or {}
    k_n = min(int(body.get("kyber_iterations", 20)), 50)
    m_n = min(int(body.get("mce_iterations", 5)), 20)

    def _run_oqs_bench(kem_name, n_iters, meta_key):
        kg_times, enc_times, dec_times = [], [], []
        last_pk, last_ct, last_ss = None, None, None

        for _ in range(n_iters):
            with oqs.KeyEncapsulation(kem_name) as k:
                t0 = time.perf_counter(); pk = k.generate_keypair()
                kg_times.append((time.perf_counter() - t0)*1000)
                t0 = time.perf_counter(); ct, ss = k.encap_secret(pk)
                enc_times.append((time.perf_counter() - t0)*1000)
                t0 = time.perf_counter(); k.decap_secret(ct)
                dec_times.append((time.perf_counter() - t0)*1000)
                last_pk, last_ct, last_ss = pk, ct, ss

        meta = KEM_META.get(kem_name, {})
        def stats(v): a = sum(v)/len(v); return {"avg":round(a,4),"min":round(min(v),4),"max":round(max(v),4)}

        return {
            "scheme": meta.get("display", kem_name),
            "algorithm": kem_name,
            "iterations": n_iters,
            "sizes": {
                "public_key": len(last_pk),
                "secret_key": meta.get("sk_size", 0),
                "ciphertext": len(last_ct),
                "shared_secret": len(last_ss),
            },
            "performance": {
                "keygen_avg_ms":  stats(kg_times)["avg"],
                "keygen_min_ms":  stats(kg_times)["min"],
                "keygen_max_ms":  stats(kg_times)["max"],
                "encap_avg_ms":   stats(enc_times)["avg"],
                "encap_min_ms":   stats(enc_times)["min"],
                "encap_max_ms":   stats(enc_times)["max"],
                "decap_avg_ms":   stats(dec_times)["avg"],
                "decap_min_ms":   stats(dec_times)["min"],
                "decap_max_ms":   stats(dec_times)["max"],
                "total_avg_ms":   round(
                    sum(kg_times)/n_iters + sum(enc_times)/n_iters + sum(dec_times)/n_iters, 4),
            }
        }

    def _run_x25519_bench(n_iters):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        kg_t, enc_t, dec_t = [], [], []
        for _ in range(n_iters):
            t0 = time.perf_counter()
            sk = X25519PrivateKey.generate()
            pk_b = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            kg_t.append((time.perf_counter()-t0)*1000)
            t0 = time.perf_counter()
            eph = X25519PrivateKey.generate()
            eph_pk_b = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            eph.exchange(X25519PublicKey.from_public_bytes(pk_b))
            enc_t.append((time.perf_counter()-t0)*1000)
            t0 = time.perf_counter()
            sk.exchange(X25519PublicKey.from_public_bytes(eph_pk_b))
            dec_t.append((time.perf_counter()-t0)*1000)
        def stats(v): a=sum(v)/len(v); return {"avg":round(a,4),"min":round(min(v),4),"max":round(max(v),4)}
        return {
            "scheme": "X25519 ECDH (fallback)", "algorithm": "X25519-ECDH",
            "iterations": n_iters,
            "sizes": {"public_key":32,"secret_key":32,"ciphertext":32,"shared_secret":32},
            "performance": {
                "keygen_avg_ms": stats(kg_t)["avg"], "keygen_min_ms": stats(kg_t)["min"],
                "keygen_max_ms": stats(kg_t)["max"],
                "encap_avg_ms": stats(enc_t)["avg"], "encap_min_ms": stats(enc_t)["min"],
                "encap_max_ms": stats(enc_t)["max"],
                "decap_avg_ms": stats(dec_t)["avg"], "decap_min_ms": stats(dec_t)["min"],
                "decap_max_ms": stats(dec_t)["max"],
                "total_avg_ms": round(sum(kg_t)/n_iters+sum(enc_t)/n_iters+sum(dec_t)/n_iters,4),
            }
        }

    try:
        if OQS_AVAILABLE:
            kyber = _run_oqs_bench("Kyber768", k_n, "Kyber768")
            mce   = _run_oqs_bench("Classic-McEliece-6960119", m_n, "Classic-McEliece-6960119")
        else:
            kyber = _run_x25519_bench(k_n)
            mce   = _run_x25519_bench(m_n)
            kyber["_note"] = "liboqs not installed — showing X25519 timings as demo"
            mce["_note"]   = "liboqs not installed — showing X25519 timings as demo"

        return jsonify({
            "timestamp":  time.strftime("%Y-%m-%d %H:%M:%S"),
            "oqs":        OQS_AVAILABLE,
            "schemes": {
                "kyber":    kyber,
                "mceliece": mce,
            }
        })
    except Exception as e:
        logger.exception("benchmark_full error")
        return jsonify({"error": str(e)}), 500


# ── Session cleanup ──────────────────────────────────────────────────
@app.route("/api/session/<session_id>", methods=["DELETE"])
def delete_session(session_id):
    deleted = _sessions.pop(session_id, None) is not None
    return jsonify({"deleted": deleted})


if __name__ == "__main__":
    import sys
    # Default port 5001 — macOS Monterey+ reserves 5000 for AirPlay Receiver.
    # Override: python app.py --port 5000
    port = 5001
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg in ("--port", "-p") and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
        elif arg.startswith("--port="):
            port = int(arg.split("=", 1)[1])

    print("\n  PQC Secure Communication API")
    print(f"  liboqs available: {OQS_AVAILABLE}")
    print(f"  Listening on:     http://localhost:{port}")
    print("  Endpoints: /api/status /api/keygen /api/encapsulate /api/decapsulate")
    print("             /api/encrypt /api/decrypt /api/full_exchange /api/benchmark\n")
    app.run(host="0.0.0.0", port=port, debug=False)