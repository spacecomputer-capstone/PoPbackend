from datetime import datetime
from .extensions import db

class Pi(db.Model):
    __tablename__ = "pis"
    pi_id = db.Column(db.Text, primary_key=True)
    pubkey_hex = db.Column(db.Text, nullable=False)
    status = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime)

class PresenceAttempt(db.Model):
    __tablename__ = "presence_attempts"
    attempt_id = db.Column(db.Text, primary_key=True)
    user_id = db.Column(db.Text, nullable=False)
    pi_id = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    consumed_at = db.Column(db.DateTime)
    attempt_token_hash = db.Column(db.Text)

def utcnow():
    return datetime.now(timezone.utc)

class PresenceSession(db.Model):
    __tablename__ = "presence_sessions"

    sid = db.Column(db.String, primary_key=True)
    attempt_id = db.Column(db.String, db.ForeignKey("presence_attempts.attempt_id"), nullable=False, index=True)
    pi_id = db.Column(db.String, db.ForeignKey("pis.pi_id"), nullable=False, index=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Optional but recommended to bind tokenB to DB row:
    # tokenb_hash = db.Column(db.String, nullable=True, index=True)  # sha256 hex

class PresenceProof(db.Model):
    __tablename__ = "presence_proofs"

    proof_id = db.Column(db.String, primary_key=True)
    user_id = db.Column(db.String, nullable=False, index=True)

    pi_id = db.Column(db.String, nullable=False, index=True)
    attempt_id = db.Column(db.String, nullable=False, index=True)
    sid = db.Column(db.String, nullable=False, index=True)

    result = db.Column(db.String, nullable=False)  # e.g. "ok" / "fail"
    success_count = db.Column(db.Integer, nullable=True)
    timing_summary = db.Column(db.JSON, nullable=True)
    transcript_hash = db.Column(db.String, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    raw_attpi = db.Column(db.Text, nullable=False)  # store the whole attPi blob
