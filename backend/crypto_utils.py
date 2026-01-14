import base64, json, time, hashlib
from typing import Any, Dict, Tuple, Union
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

def now() -> int:
    return int(time.time())

def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def sha256_hex(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def sign_ed25519(sk: SigningKey, payload_obj: Dict[str, Any]) -> str:
    msg = canonical_json_bytes(payload_obj)
    sig = sk.sign(msg).signature
    return f"{b64url_encode(msg)}.{b64url_encode(sig)}"

def split_compact(compact: str) -> Tuple[bytes, bytes]:
    parts = compact.split(".")
    if len(parts) != 2:
        raise ValueError("bad token format (expected 2 parts)")
    return b64url_decode(parts[0]), b64url_decode(parts[1])

def verify_ed25519_compact(compact: str, vk: VerifyKey) -> Dict[str, Any]:
    payload_b, sig_b = split_compact(compact)
    try:
        vk.verify(payload_b, sig_b)
    except BadSignatureError as e:
        raise ValueError("bad signature") from e
    try:
        return json.loads(payload_b.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError("bad payload json") from e
