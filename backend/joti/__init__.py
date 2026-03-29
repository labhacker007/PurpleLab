"""PurpleLab Joti integration package.

Exports the JotiClient class and the get_joti_client() factory function.

Quick start::

    from backend.joti import get_joti_client

    client = get_joti_client()
    if client:
        score = await client.get_coverage_score()
"""
from backend.joti.client import JotiClient, get_joti_client

__all__ = ["JotiClient", "get_joti_client"]
