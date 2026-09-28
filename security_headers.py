"""
security_headers.py

Adds standard defensive HTTP response headers to every request. Before this,
the app shipped with none of these at all - a fresh `curl -I` against any
endpoint showed no X-Frame-Options, no CSP, no HSTS, nothing.

Known, deliberate limitation: this app's own frontend JS builds a fair
amount of markup with inline `onclick="..."` attributes and inline
`style="..."` (see reports.js/app.js), so the CSP below allows
'unsafe-inline' for both script-src and style-src rather than pretending to
be a strict nonce-based policy it doesn't actually enforce. That still
blocks the two most common injection vectors this policy exists for -
loading a *different origin's* script/stylesheet, and framing the app in a
third-party page - which is real value even without going fully strict.
Tightening it further is legitimate follow-up work (migrate inline
onclick= handlers to addEventListener + a nonce-based CSP).
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, enable_hsts: bool = False):
        super().__init__(app)
        self.enable_hsts = enable_hsts

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )

        # Only advertise HSTS when we're actually confident this deployment
        # is served over HTTPS (e.g. behind Caddy/a cloud LB doing TLS
        # termination) - sending it over plain HTTP is at best a no-op and
        # at worst confusing for local/dev setups that intentionally run
        # without TLS.
        if self.enable_hsts:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"

        return response
