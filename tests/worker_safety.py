"""The isolated runner's guards, installed before any app import in spawn children."""
from unittest.mock import patch


def install(stack):
    import subprocess
    import httpx
    import sqlalchemy
    from sqlalchemy.pool import StaticPool
    from pydantic_settings.sources import DotEnvSettingsSource
    original = sqlalchemy.create_engine
    def memory(url, **kwargs):
        if str(url).startswith('postgresql:'):
            return original('sqlite://', poolclass=StaticPool, connect_args={'check_same_thread': False})
        if str(url) not in {'sqlite://', 'sqlite:///:memory:'}:
            raise AssertionError('Only in-memory child databases permitted')
        return original(url, **kwargs)
    def blocked(*args, **kwargs):
        raise AssertionError('External process/HTTP forbidden in isolated scan children')
    async def blocked_async(*args, **kwargs):
        blocked()
    stack.enter_context(patch.object(DotEnvSettingsSource, '_read_env_files', return_value={}))
    stack.enter_context(patch.object(sqlalchemy, 'create_engine', side_effect=memory))
    stack.enter_context(patch.object(subprocess, 'Popen', side_effect=blocked))
    stack.enter_context(patch.object(httpx.HTTPTransport, 'handle_request', side_effect=blocked))
    stack.enter_context(patch.object(httpx.AsyncHTTPTransport, 'handle_async_request', side_effect=blocked_async))
