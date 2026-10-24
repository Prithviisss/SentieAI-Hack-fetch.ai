"""SentinelFlow Multi-Agent System Package."""

import asyncio

# Ensure an active asyncio event loop exists on MainThread for Python 3.12+ compatibility
try:
    asyncio.get_event_loop()
except RuntimeError:
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
