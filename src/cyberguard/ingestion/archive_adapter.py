import gzip
import tarfile
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

from cyberguard.core.models import TelemetryEvent

from .base import Adapter
from .config_file_adapter import SSHConfigAdapter
from .csv_adapter import CSVAdapter
from .json_adapter import JSONAdapter
from .structured_config_adapter import StructuredConfigAdapter
from .universal_adapter import UniversalTextAdapter

_MAX_FILES = 100
_MAX_EXPANDED_BYTES = 50 * 1024 * 1024


class ArchiveAdapter(Adapter):
    """Bounded, traversal-safe inspection of telemetry bundles."""

    name = "archive"
    extensions = (".zip", ".tar", ".tgz", ".gz")

    def parse(self, path: Path) -> list[TelemetryEvent]:
        with TemporaryDirectory(prefix="cyberguard-archive-") as directory:
            root = Path(directory)
            members = self._extract(path, root)
            events: list[TelemetryEvent] = []
            errors = []
            for member in members:
                try:
                    parsed = self._adapter(member).parse(member)
                    for event in parsed:
                        event.attributes.setdefault("archive_member", member.relative_to(root).as_posix())
                    events.extend(parsed)
                except (ValueError, OSError, UnicodeError) as exc:
                    errors.append(f"{member.name}: {exc}")
            if not events:
                detail = "; ".join(errors[:5]) or "no supported members"
                raise ValueError(f"The archive contained no analyzable telemetry: {detail}")
            return events

    def _extract(self, path: Path, root: Path) -> list[Path]:
        lower = path.name.lower()
        if lower.endswith(".zip"):
            with zipfile.ZipFile(path) as archive:
                infos = [item for item in archive.infolist() if not item.is_dir()]
                self._validate([(item.filename, item.file_size) for item in infos])
                paths = []
                for item in infos:
                    target = self._target(root, item.filename)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(item) as source, target.open("wb") as output:
                        output.write(source.read(_MAX_EXPANDED_BYTES + 1))
                    paths.append(target)
                return paths
        if tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as archive:
                infos = [item for item in archive.getmembers() if item.isfile()]
                self._validate([(item.name, item.size) for item in infos])
                paths = []
                for item in infos:
                    target = self._target(root, item.name)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(item)
                    if source:
                        target.write_bytes(source.read(_MAX_EXPANDED_BYTES + 1))
                        paths.append(target)
                return paths
        if lower.endswith(".gz"):
            target = root / path.name.removesuffix(".gz")
            with gzip.open(path, "rb") as source:
                data = source.read(_MAX_EXPANDED_BYTES + 1)
            if len(data) > _MAX_EXPANDED_BYTES:
                raise ValueError("Expanded gzip content exceeds 50 MB")
            target.write_bytes(data)
            return [target]
        raise ValueError("Unsupported archive format")

    @staticmethod
    def _validate(members: list[tuple[str, int]]) -> None:
        if len(members) > _MAX_FILES:
            raise ValueError(f"Archive contains more than {_MAX_FILES} files")
        if sum(size for _, size in members) > _MAX_EXPANDED_BYTES:
            raise ValueError("Expanded archive content exceeds 50 MB")

    @staticmethod
    def _target(root: Path, name: str) -> Path:
        target = (root / name).resolve()
        if root.resolve() not in target.parents:
            raise ValueError(f"Unsafe archive path: {name}")
        return target

    @staticmethod
    def _adapter(path: Path) -> Adapter:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            return CSVAdapter()
        if suffix in {".json", ".jsonl"}:
            return JSONAdapter()
        if suffix in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".xml", ".env", ".properties"}:
            return StructuredConfigAdapter()
        if suffix in {".conf", ".config"} and "ssh" in path.name.lower():
            return SSHConfigAdapter()
        return UniversalTextAdapter()
