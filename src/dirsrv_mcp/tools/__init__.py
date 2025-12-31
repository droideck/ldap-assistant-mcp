"""Tool registration modules for DirSrv MCP."""

from src.dirsrv_mcp.tools.health import register_health_tools
from src.dirsrv_mcp.tools.users import register_user_tools
from src.dirsrv_mcp.tools.groups import register_group_tools
from src.dirsrv_mcp.tools.monitoring import register_monitoring_tools
from src.dirsrv_mcp.tools.search import register_search_tools
from src.dirsrv_mcp.tools.replication import register_replication_tools
from src.dirsrv_mcp.tools.performance import register_performance_tools
from src.dirsrv_mcp.tools.indexes import register_index_tools
from src.dirsrv_mcp.tools.config import register_config_tools

__all__ = [
    "register_health_tools",
    "register_user_tools",
    "register_group_tools",
    "register_monitoring_tools",
    "register_search_tools",
    "register_replication_tools",
    "register_performance_tools",
    "register_index_tools",
    "register_config_tools",
]

