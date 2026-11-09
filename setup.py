"""Include the deployment tree in wheels without duplicating its source files."""

from pathlib import Path, PurePosixPath
from shutil import rmtree

from setuptools import setup
from setuptools.command.build_py import build_py


def resource_paths(source: Path) -> list[Path]:
    """Package only reviewed assets, never adjacent ignored operator files."""
    resources = []
    seen = set()
    for line in (source / "certweaver-resources.txt").read_text(encoding="utf-8").splitlines():
        name = line.strip()
        if not name or name.startswith("#"):
            continue
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or "\\" in name
            or ":" in name
            or name in seen
            or "secrets" in relative.parts
            or any(part.startswith(".") for part in relative.parts if part != ".env.example")
        ):
            raise RuntimeError(f"Invalid runtime resource allowlist entry: {name}")
        resource = source / name
        if (
            not resource.is_file()
            or resource.is_symlink()
            or not resource.resolve().is_relative_to(source)
        ):
            raise RuntimeError(f"Runtime resource is missing or outside the source tree: {name}")
        seen.add(name)
        resources.append(resource)
    if not resources:
        raise RuntimeError("The runtime resource allowlist is empty")
    return resources


class BuildPy(build_py):
    def run(self) -> None:
        super().run()
        source = Path(__file__).resolve().parent
        build_root = Path(self.build_lib).resolve()
        destination = build_root / "certweaver" / "_assets"
        if destination.is_symlink() or not destination.resolve().is_relative_to(build_root):
            raise RuntimeError(
                f"Refusing to replace resource tree outside build directory: {destination}"
            )
        if destination.exists():
            rmtree(destination)
        for resource in resource_paths(source):
            target = destination / resource.relative_to(source)
            self.mkpath(str(target.parent))
            self.copy_file(str(resource), str(target))


setup(cmdclass={"build_py": BuildPy})
