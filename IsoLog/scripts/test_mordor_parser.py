import sys
sys.path.insert(0, '.')
from backend.parsers.formats.mordor import MordorParser
import json
import zipfile
from pathlib import Path

p = MordorParser()
zip_path = Path(r'd:\Project_IsoLog\Security-Datasets\datasets\atomic\windows\credential_access\host\psh_lsass_memory_dump_comsvcs.zip')

print(f"Testing parser: {p.parser_name}")
print(f"Loading from: {zip_path}")

with zipfile.ZipFile(zip_path, 'r') as zf:
    for name in zf.namelist():
        if name.endswith('.json'):
            print(f"Found: {name}")
            with zf.open(name) as f:
                lines = f.read().decode('utf-8').strip().split('\n')[:5]
                for i, line in enumerate(lines):
                    event = json.loads(line)
                    parsed = p.parse_dict(event)
                    if parsed:
                        eid = parsed.extra.get("event_id")
                        print(f"  [{i}] EventID={eid} Action={parsed.event_action} User={parsed.user_name}")
                    else:
                        print(f"  [{i}] Failed to parse")

print("\nParser test PASSED!")
