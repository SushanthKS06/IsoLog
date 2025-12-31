"""Analyze the 3 remaining failing datasets in detail."""
import json
import zipfile
from pathlib import Path
import yaml

failing_datasets = [
    "SDWIN-190518230752",  # Empire Mimikatz Extract Kerberos Keys (T1003.004)
    "SDWIN-190518235535",  # Empire Mimikatz Backup Keys (T1003)
    "SDWIN-190625133822",  # Empire Reg Dump SAM Hive (T1003.002)
]

meta_path = Path(r'd:\Project_IsoLog\Security-Datasets\datasets\atomic\_metadata')
data_path = Path(r'd:\Project_IsoLog\Security-Datasets\datasets')

for ds_id in failing_datasets:
    yaml_file = meta_path / f"{ds_id}.yaml"
    if yaml_file.exists():
        with open(yaml_file) as f:
            meta = yaml.safe_load(f)
        
        print("=" * 70)
        print(f"Dataset: {ds_id}")
        print(f"Title: {meta.get('title')}")
        
        # Find data
        files = meta.get('files', [])
        for finfo in files:
            if finfo.get('type') == 'Host':
                url = finfo.get('link', '')
                if 'datasets/' in url:
                    rel = url.split('datasets/')[-1]
                    zip_path = data_path / rel
                    if zip_path.exists():
                        with zipfile.ZipFile(zip_path, 'r') as zf:
                            for name in zf.namelist():
                                if name.endswith('.json'):
                                    with zf.open(name) as jf:
                                        lines = jf.read().decode('utf-8').strip().split('\n')
                                        
                                        print(f"Total events: {len(lines)}")
                                        
                                        # Find CommandLine events
                                        cmd_events = []
                                        for i, line in enumerate(lines):
                                            raw = json.loads(line)
                                            cmd = raw.get('CommandLine', '')
                                            if cmd and len(cmd) > 10:
                                                cmd_events.append({
                                                    'i': i,
                                                    'EventID': raw.get('EventID'),
                                                    'cmd': cmd[:150]
                                                })
                                        
                                        print(f"Events with CommandLine: {len(cmd_events)}")
                                        print("Sample commands:")
                                        for ev in cmd_events[:8]:
                                            print(f"  [{ev['EventID']}] {ev['cmd']}")
                                    break
                break
        print()
