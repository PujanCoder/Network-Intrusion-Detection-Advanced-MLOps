"""Compatibility router.

The dashboard page itself is mounted by :mod:`src.serving.app` (React bundle when
present, built-in status page otherwise). Data endpoints live in
:mod:`src.serving.routes.soc`; ``/ws/alerts`` moved there when it gained session
authentication.
"""

from fastapi import APIRouter

router = APIRouter()
