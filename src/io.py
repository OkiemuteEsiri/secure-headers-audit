import json
from pathlib import Path
from .models import Target


def load_targets(path: str) -> list[Target]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    targets = [Target.from_dict(x) for x in raw]
    names = [t.name for t in targets]
    if len(names) != len(set(names)):
        raise ValueError("duplicate target name")
    return targets
