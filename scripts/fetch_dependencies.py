#!/usr/bin/env python3
"""Fetch explicitly selected pinned research dependencies; never reset existing work."""
import argparse
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / 'dependencies.json').read_text())
p = argparse.ArgumentParser()
p.add_argument('names', nargs='+', choices=list(manifest))
args = p.parse_args()
for name in args.names:
    entry = manifest[name]
    destination = root / entry['destination']
    if destination.exists():
        current = subprocess.check_output(['git', '-C', str(destination), 'rev-parse', 'HEAD'], text=True).strip()
        if current != entry['commit']:
            raise SystemExit(f'{name}: existing checkout differs; preserved without changes')
        print(f'{name}: already at {current}')
        continue
    destination.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['git', 'clone', '--no-checkout', entry['url'], str(destination)], check=True)
    subprocess.run(['git', '-C', str(destination), 'checkout', '--detach', entry['commit']], check=True)
