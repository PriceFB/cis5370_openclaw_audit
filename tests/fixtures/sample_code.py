# Sample Python source file for testing execution-surface detection

import subprocess
import importlib


def run_agent_command(cmd):
    """Execute an agent command via subprocess."""
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout


def load_plugin(plugin_name):
    """Dynamically load a plugin module."""
    module = importlib.import_module(f"plugins.{plugin_name}")
    return module


def eval_expression(expr):
    """Evaluate a user-provided expression."""
    return eval(expr)
