from __future__ import annotations

import base64
import gzip
from io import BytesIO


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    padded = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def gzip_compress(raw: bytes) -> bytes:
    buf = BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as f:
        f.write(raw)
    return buf.getvalue()


def gzip_decompress(data: bytes) -> bytes:
    with gzip.GzipFile(fileobj=BytesIO(data), mode="rb") as f:
        return f.read()
