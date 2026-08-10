"""Normalize an already-built sdist without changing its file contents."""

from __future__ import annotations

import argparse
import gzip
import io
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


class NormalizationError(RuntimeError):
    """The input is not a safe regular-file source distribution."""


def normalize(sdist: Path, source_date_epoch: int) -> None:
    """Rewrite tar/gzip metadata deterministically and atomically."""
    if source_date_epoch <= 0:
        raise NormalizationError("SOURCE_DATE_EPOCH must be positive")
    entries: list[tuple[str, bytes | None]] = []
    with tarfile.open(sdist, mode="r:gz") as source:
        names: set[str] = set()
        for member in source.getmembers():
            path = PurePosixPath(member.name)
            if (
                not member.name
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in member.name
                or member.name in names
            ):
                raise NormalizationError("unsafe or duplicate sdist path")
            names.add(member.name)
            if member.isdir():
                entries.append((member.name.rstrip("/") + "/", None))
                continue
            if not member.isfile():
                raise NormalizationError("sdist contains a link or special file")
            stream = source.extractfile(member)
            if stream is None:
                raise NormalizationError("sdist member is unreadable")
            entries.append((member.name, stream.read()))

    with tempfile.NamedTemporaryFile(
        mode="w+b", prefix=f".{sdist.name}.", suffix=".tmp", dir=sdist.parent, delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
        with (
            gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=temporary,
                mtime=source_date_epoch,
            ) as compressed,
            tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as target,
        ):
            for name, data in sorted(entries):
                info = tarfile.TarInfo(name)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = source_date_epoch
                info.pax_headers = {}
                if data is None:
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.size = 0
                    target.addfile(info)
                else:
                    info.type = tarfile.REGTYPE
                    info.mode = 0o644
                    info.size = len(data)
                    target.addfile(info, io.BytesIO(data))
        temporary.flush()
        os.fsync(temporary.fileno())
    os.replace(temporary_path, sdist)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdist", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    args = parser.parse_args()
    normalize(args.sdist.resolve(), args.source_date_epoch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
