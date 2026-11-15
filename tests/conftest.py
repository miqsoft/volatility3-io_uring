"""Make the repo plugins importable as volatility3.plugins.*, like `vol -p plugins`."""

import os

import volatility3.plugins
from volatility3 import framework

PLUGINS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins")

volatility3.plugins.__path__ = [os.path.abspath(PLUGINS_DIR)] + list(
    volatility3.plugins.__path__
)
framework.import_files(volatility3.plugins, True)
