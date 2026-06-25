from certweaver.registry import load_registry, project_root


def test_registry_contains_exactly_twenty_adapters() -> None:
    registry = load_registry()
    assert len(registry) == 20
    assert len(set(registry)) == 20


def test_every_adapter_has_task_file() -> None:
    root = project_root()
    for slug in load_registry():
        assert (root / "roles" / "pki_adapter" / "tasks" / "adapters" / f"{slug}.yml").is_file()


def test_registry_has_windows_and_kubernetes_targets() -> None:
    adapters = load_registry().values()
    assert any("windows" in adapter.targets for adapter in adapters)
    assert any("kubernetes" in adapter.targets for adapter in adapters)
