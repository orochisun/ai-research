"""Static-analysis fixture: intentionally simple research entry points.
This file is inspected as text, never executed by Nexus.
Matches are not evidence of a vulnerability.
"""
import subprocess
from pathlib import Path

def read_note(name):
    base = Path('/tmp/notes').resolve()
    target = (base / name).resolve()
    if not target.is_relative_to(base):
        raise ValueError('outside notes')
    with open(target, 'r') as stream:
        return stream.read()

def version():
    return subprocess.run(['git', '--version'], check=True, capture_output=True)
