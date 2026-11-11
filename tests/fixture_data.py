"""Load fresh synthetic fixture data and substitute explicit runtime values."""

import json
from pathlib import Path


def fixture_data(name, values=()):
    path = Path(__file__).parent / "fixtures" / (name + ".json")
    return _materialize(json.loads(path.read_text(encoding="utf-8")), values)


def _materialize(value, values):
    if isinstance(value, dict):
        return {key: _materialize(item, values) for key, item in value.items()}
    if isinstance(value, list):
        return [_materialize(item, values) for item in value]
    if isinstance(value, str) and value.startswith("$fixture:"):
        return values[int(value.partition(":")[2])]
    return value
