from slowapi import Limiter
from slowapi.util import get_remote_address

# Single shared rate limiter instance used across the entire application.
# This MUST be the same instance attached to app.state.limiter in main.py.
limiter = Limiter(key_func=get_remote_address)
