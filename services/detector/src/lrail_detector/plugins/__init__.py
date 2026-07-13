"""Built-in private detector plugin adapters."""

from lrail_detector.plugins.base import DetectorPlugin
from lrail_detector.plugins.docker import DockerPlugin
from lrail_detector.plugins.go import GoPlugin
from lrail_detector.plugins.node import NodePlugin
from lrail_detector.plugins.python import PythonPlugin
from lrail_detector.plugins.ruby import RubyPlugin
from lrail_detector.plugins.static import StaticPlugin

DEFAULT_PLUGINS: tuple[DetectorPlugin, ...] = (
    RubyPlugin(),
    NodePlugin(),
    PythonPlugin(),
    GoPlugin(),
    StaticPlugin(),
    DockerPlugin(),
)

__all__ = ["DEFAULT_PLUGINS", "DetectorPlugin"]
