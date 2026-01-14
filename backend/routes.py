# backend/routes.py
import os
import base64
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, request, jsonify
from nacl.signing import SigningKey, VerifyKey

from backend.extensions import db
from backend.models import Pi, PresenceAttempt, PresenceSession, PresenceProof
from backend.crypto_utils import sign_ed25519, sha256_hex, verify_ed25519_compact

presence_bp = Blueprint("presence", __name__)

ATTEMPT_TTL_SECONDS = int(os.getenv("ATTEMPT_TTL_SECONDS", "30"))
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "15"))


# ----------------------------
# Helpers
# ----------------------------
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def require_user_id() -> str:
    uid = request.headers.get("X-User-Id")
    if not uid:
        raise ValueError("missing X-User-Id header")
    return uid


def backend_signing_key() -> SigningKey:
    # handles BACKEND_SIGNING_KEY_B64="..."
    seed_b64 = os.environ["BACKEND_SIGNING_KEY_B64"].strip().strip('"')
    seed = base64.b64decode(seed_b64)
    return SigningKey(seed)


def backend_verify_key() -> VerifyKey:
    return backend_signing_key().verify_key


def new_id(nbytes: int = 18) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).rstrip(b"=").decode("ascii")


# ----------------------------
# Routes
# ----------------------------
@presence_bp.post("/presence/attempt")
def create_attempt():
    try:
        user_id = require_user_id()
    except ValueError as e:
        return jsonify({"error": str(e)}), 401

    data = request.get_json(force=True) or {}
    pi_id = data.get("pi_id")
    if not pi_id:
        return jsonify({"error": "missing pi_id"}), 400

    pi = Pi.query.get(pi_id)
    if not pi or pi.status != "active":
        return jsonify({"error": "unknown_or_inactive_pi"}), 404

    now_dt = utcnow()
    exp_dt = now_dt + timedelta(seconds=ATTEMPT_TTL_SECONDS)
    attempt_id = new_id(18)

    token_obj = {
        "iss": "presence-backend",
        "aud": "presence-pi",
        "iat": int(now_dt.timestamp()),
        "exp_attempt": int(exp_dt.timestamp()),
        "attempt_id": attempt_id,
        "user_id": user_id,
        "pi_id": pi_id,
    }
    attempt_token = sign_ed25519(backend_signing_key(), token_obj)

    row = PresenceAttempt(
        attempt_id=attempt_id,
        user_id=user_id,
        pi_id=pi_id,
        expires_at=exp_dt,
        attempt_token_hash=sha256_hex(attempt_token.encode("utf-8")),
    )
    db.session.add(row)
    db.session.commit()

    return jsonify({"attempt_id": attempt_id, "attempt_token": attempt_token}), 200


@presence_bp.post("/presence/session")
def create_presence_session():
    data = request.get_json(force=True) or {}
    pi_id = data.get("pi_id")
    attempt_id = data.get("attempt_id")

    if not pi_id or not attempt_id:
        return jsonify({"error": "missing pi_id or attempt_id"}), 400

    pi = Pi.query.filter_by(pi_id=pi_id, status="active").first()
    if not pi:
        return jsonify({"error": "pi not found or not active"}), 404

    now_dt = utcnow()
    exp_sid = now_dt + timedelta(seconds=SESSION_TTL_SECONDS)

    try:
        attempt = (
            PresenceAttempt.query
            .filter_by(attempt_id=attempt_id)
            .with_for_update()
            .first()
        )
        if not attempt:
            return jsonify({"error": "attempt not found"}), 404

        if attempt.pi_id != pi_id:
            return jsonify({"error": "attempt/pi mismatch"}), 409

        if attempt.expires_at <= now_dt:
            return jsonify({"error": "attempt expired"}), 409

        if getattr(attempt, "consumed_at", None) is not None:
            return jsonify({"error": "attempt already consumed"}), 409

        sid = new_id(18)

        tokenB_payload = {
            "sid": sid,
            "attempt_id": attempt_id,
            "pi_id": pi_id,
            "exp": int(exp_sid.timestamp()),
            "iat": int(now_dt.timestamp()),
            "iss": "presence-backend",
            "aud": "presence-pi",
        }
        tokenB = sign_ed25519(backend_signing_key(), tokenB_payload)

        sess = PresenceSession(
            sid=sid,
            attempt_id=attempt_id,
            pi_id=pi_id,
            created_at=now_dt,
            expires_at=exp_sid,
            used_at=None,
        )

        db.session.add(sess)
        attempt.consumed_at = now_dt
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "server error", "detail": str(e)}), 500

    return jsonify({"sid": sid, "tokenB": tokenB}), 200


@presence_bp.post("/presence/attest")
def attest_presence():
    data = request.get_json(force=True) or {}
    tokenB = data.get("tokenB")
    attPi = data.get("attPi")

    if not tokenB or not attPi:
        return jsonify({"error": "missing tokenB or attPi"}), 400

    now_dt = utcnow()

    # 1) verify backend tokenB
    try:
        tokenB_payload = verify_ed25519_compact(tokenB, backend_verify_key())
    except ValueError as e:
        return jsonify({"error": "invalid tokenB", "detail": str(e)}), 401

    if tokenB_payload.get("iss") != "presence-backend" or tokenB_payload.get("aud") != "presence-pi":
        return jsonify({"error": "tokenB claims invalid"}), 401

    sid = tokenB_payload.get("sid")
    attempt_id = tokenB_payload.get("attempt_id")
    pi_id = tokenB_payload.get("pi_id")
    exp = tokenB_payload.get("exp")

    if not sid or not attempt_id or not pi_id or not exp:
        return jsonify({"error": "tokenB missing fields"}), 401

    if int(exp) <= int(now_dt.timestamp()):
        return jsonify({"error": "tokenB expired"}), 409

    try:
        # 2) load + lock session
        sess = (
            PresenceSession.query
            .filter_by(sid=sid)
            .with_for_update()
            .first()
        )
        if not sess:
            return jsonify({"error": "session not found"}), 404

        if sess.expires_at <= now_dt:
            return jsonify({"error": "session expired"}), 409

        if sess.used_at is not None:
            return jsonify({"error": "session already used"}), 409

        if sess.attempt_id != attempt_id or sess.pi_id != pi_id:
            return jsonify({"error": "session/token mismatch"}), 409

        # 3) verify Pi and pubkey
        pi = Pi.query.filter_by(pi_id=pi_id, status="active").first()
        if not pi:
            return jsonify({"error": "pi not found or not active"}), 404

        try:
            pi_vk = VerifyKey(bytes.fromhex(pi.pubkey_hex))
        except Exception:
            return jsonify({"error": "pi pubkey invalid"}), 500

        # 4) verify attPi signature
        try:
            att_payload = verify_ed25519_compact(attPi, pi_vk)
        except ValueError as e:
            return jsonify({"error": "invalid attPi", "detail": str(e)}), 401

        if att_payload.get("sid") != sid:
            return jsonify({"error": "attPi sid mismatch"}), 409

        expected_hash = sha256_hex(tokenB.encode("utf-8"))
        if att_payload.get("tokenB_hash") != expected_hash:
            return jsonify({"error": "attPi tokenB_hash mismatch"}), 409

        # 5) create proof
        attempt = PresenceAttempt.query.filter_by(attempt_id=attempt_id).first()
        if not attempt:
            return jsonify({"error": "attempt not found"}), 404

        proof_id = new_id(18)
        result = att_payload.get("result", "ok")

        proof = PresenceProof(
            proof_id=proof_id,
            user_id=attempt.user_id,
            pi_id=pi_id,
            attempt_id=attempt_id,
            sid=sid,
            result=result,
            success_count=att_payload.get("success_count"),
            timing_summary=att_payload.get("timing_summary"),
            transcript_hash=att_payload.get("transcript_hash"),
            created_at=now_dt,
            raw_attpi=attPi,
        )

        db.session.add(proof)
        sess.used_at = now_dt
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "server error", "detail": str(e)}), 500

    return jsonify({"proof_id": proof_id, "result": result}), 200


@presence_bp.get("/presence/proof/<proof_id>")
def get_proof(proof_id: str):
    try:
        user_id = require_user_id()
    except ValueError as e:
        return jsonify({"error": str(e)}), 401

    proof = PresenceProof.query.filter_by(proof_id=proof_id).first()
    if not proof:
        return jsonify({"error": "not found"}), 404

    if proof.user_id != user_id:
        return jsonify({"error": "forbidden"}), 403

    return jsonify({
        "proof_id": proof.proof_id,
        "user_id": proof.user_id,
        "pi_id": proof.pi_id,
        "attempt_id": proof.attempt_id,
        "sid": proof.sid,
        "result": proof.result,
        "success_count": proof.success_count,
        "timing_summary": proof.timing_summary,
        "transcript_hash": proof.transcript_hash,
        "created_at": proof.created_at.isoformat() if proof.created_at else None,
    }), 200
