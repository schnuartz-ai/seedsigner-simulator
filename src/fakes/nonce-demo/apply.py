"""Apply the fixed-nonce teaching overlay to the pinned stock firmware."""

from pathlib import Path
import shutil
import sys


def insert_once(path: Path, marker: str, replacement: str) -> None:
    source = path.read_text(encoding="utf-8")
    if source.count(marker) != 1:
        raise SystemExit(f"expected one patch marker in {path}, found {source.count(marker)}")
    path.write_text(source.replace(marker, replacement, 1), encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: apply.py UPSTREAM_ROOT FIXED_NONCE_SOURCE")

    root = Path(sys.argv[1])
    helper = Path(sys.argv[2])
    main_py = root / "src/main.py"
    psbt_views = root / "src/seedsigner/views/psbt_views.py"
    helper_target = root / "src/seedsigner/helpers/fixed_nonce.py"

    if helper_target.exists():
        raise SystemExit(f"refusing to overwrite an existing file: {helper_target}")

    helper_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(helper, helper_target)

    main_marker = "from seedsigner.controller import Controller\n"
    main_replacement = (
        "from seedsigner.helpers.fixed_nonce import install_fixed_nonce\n\n"
        "install_fixed_nonce()\n\n"
        + main_marker
    )
    insert_once(main_py, main_marker, main_replacement)

    psbt_marker = "from seedsigner.models.psbt_parser import "
    psbt_replacement = (
        "from seedsigner.helpers.fixed_nonce import install_fixed_nonce\n\n"
        "install_fixed_nonce()\n\n"
        + psbt_marker
    )
    insert_once(psbt_views, psbt_marker, psbt_replacement)


if __name__ == "__main__":
    main()
