"""Monitoring tools for 389 Directory Server."""

import json
import logging
from typing import Dict, Any
from lib389.monitor import Monitor
from lib389.backend import Backends
from ..connection import get_connection

logger = logging.getLogger(__name__)


def run_monitor(backend: str = "", suffix: str = "", server_name: str = "default") -> Dict[str, Any]:
    """
    Get the Directory Server's monitor information.

    Get the backend monitor information if backend/suffix is provided.

    Args:
        backend: The database backend name, like 'userroot'
        suffix: The database suffix name, like 'dc=example,dc=com'
        server_name: Name of the server to query (default: "default")

    Returns:
        Dict containing the server's monitor information
    """
    ds = None
    try:
        logger.info(f"Get the Directory Server monitor information from {server_name}")
        ds = get_connection(server_name)

        if backend or suffix:
            # Backend monitor
            bes = Backends(ds)
            be = bes.get(backend or suffix)
            monitor = be.get_monitor()
        else:
            # Main monitor
            monitor = Monitor(ds)

        data_json = monitor.get_all_attrs_json()
        result = json.loads(data_json)

        response_data = {
            "type": "monitor",
            "server": server_name,
            "backend": backend or suffix or "main",
            "item": result
        }

        return response_data

    except Exception as e:
        logger.error(f"Error accessing the monitor on {server_name}: {str(e)}")
        raise
    finally:
        if ds:
            try:
                ds.unbind_s()
            except:
                pass
