from pathlib import Path

import yaml

from certweaver.config import load_config, validate_config
from certweaver.registry import project_root
from certweaver.render import write_inventory


def example_configs() -> list[Path]:
    return sorted((project_root() / "examples" / "configs").glob("*.yml"))


def test_every_example_validates() -> None:
    paths = example_configs()
    assert len(paths) >= 7
    for path in paths:
        result = validate_config(load_config(path))
        assert result.errors == [], f"{path}: {result.errors}"


def test_every_example_renders_parseable_inventory(tmp_path: Path) -> None:
    for path in example_configs():
        destination = tmp_path / f"{path.stem}-inventory.yml"
        write_inventory(load_config(path), destination)
        rendered = yaml.safe_load(destination.read_text(encoding="utf-8"))
        assert rendered["all"]["vars"]["certweaver_mode"]
        assert rendered["all"]["children"]
