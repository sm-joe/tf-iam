#!/usr/bin/env python3
"""Build-only AWS metadata acquisition. No execution during normal CLI use."""
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from tfiam.authorization import all_catalog_actions, download_snapshot, audit

def prepare(destination):
    destination=Path(destination)
    if destination.exists():
        raise ValueError("Metadata destination exists; use a clean source checkout for distribution")
    actions=all_catalog_actions()
    services={a.split(":",1)[0] for a in actions}
    destination.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tfiam-aws-metadata-",dir=destination.parent) as temporary:
        stage=Path(temporary)/"authorization"
        download_snapshot(stage,services)
        result=audit(actions,[],stage)
        if result["status"]!="compatible" or result["actions_recognized"]!=len(actions):
            raise ValueError("AWS catalog action validation failed: "+json.dumps(result["findings"],sort_keys=True))
        manifest={"schema_version":1,"retrieved_at":datetime.now(timezone.utc).isoformat(),
                  "services":result["evidence"],"actions_recognized":result["actions_recognized"]}
        (stage/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        stage.rename(destination)
    print("Bundled AWS metadata:",len(services),"services;",len(actions),"catalog actions")

if __name__=="__main__":
    prepare(Path(__file__).resolve().parents[1]/"tfiam"/"catalog"/"authorization")
