from __future__ import annotations


class MaxBodySizeMiddleware:
    """ASGI middleware that rejects requests with bodies larger than max_bytes.

    Uses Content-Length when present for a deterministic 413.
    """

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        method = scope.get("method")
        path = scope.get("path") or ""

        enforce = method in {"POST", "PUT", "PATCH"} and (path.startswith("/v1/") or path.startswith("/agents/"))
        if not enforce:
            return await self.app(scope, receive, send)

        # Deterministic fast-path
        headers = {k.lower(): v for k, v in (scope.get("headers") or [])}
        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                if int(cl.decode("ascii")) > self.max_bytes:
                    await send({"type": "http.response.start", "status": 413, "headers": [(b"content-length", b"0")]})
                    await send({"type": "http.response.body", "body": b""})
                    return
            except Exception:
                pass

        # Streaming fallback
        received = 0

        async def receive_wrapped():
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                body = message.get("body") or b""
                received += len(body)
                if received > self.max_bytes:
                    # Consume remaining body from upstream to avoid protocol issues
                    while message.get("more_body"):
                        message = await receive()
                    await send({"type": "http.response.start", "status": 413, "headers": [(b"content-length", b"0")]})
                    await send({"type": "http.response.body", "body": b""})
                    # Return an empty request body to downstream if it still tries
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        return await self.app(scope, receive_wrapped, send)
