from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.hits = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        # Apply only to mutating endpoints
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith("/v1/"):
            key = request.client.host if request.client else "unknown"
            now = time.time()
            q = self.hits[key]
            while q and now - q[0] > self.window_seconds:
                q.popleft()
            if len(q) >= self.max_requests:
                return Response(status_code=429)
            q.append(now)

        return await call_next(request)
