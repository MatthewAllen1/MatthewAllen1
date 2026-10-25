"""Local file integrity baseline and drift checker. Do not scan sensitive folders."""
import argparse
import hashlib
import json
from pathlib import Path


def inventory(root, exclude=None):
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("Directory not found")
    exclude = Path(exclude).resolve() if exclude else None
    result = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or (exclude and path.resolve() == exclude):
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        result[str(path.relative_to(root))] = digest.hexdigest()
    return result


def compare(before, after):
    return {
        "added": sorted(after.keys() - before.keys()),
        "deleted": sorted(before.keys() - after.keys()),
        "modified": sorted(p for p in before.keys() & after.keys() if before[p] != after[p])
    }


def main():
    parser = argparse.ArgumentParser(description="Local SHA-256 file baseline and drift checker")
    parser.add_argument("directory")
    parser.add_argument("baseline", help="Baseline JSON path, preferably outside the monitored directory")
    parser.add_argument("--init", action="store_true", help="Create/replace baseline")
    args = parser.parse_args()
    baseline = Path(args.baseline).resolve()
    current = inventory(args.directory, exclude=baseline)
    if args.init:
        baseline.write_text(json.dumps(current, indent=2), encoding="utf-8")
        print(f"Saved {len(current)} file hashes")
    else:
        old = json.loads(baseline.read_text(encoding="utf-8"))
        changes = compare(old, current)
        print(json.dumps(changes, indent=2))
        if any(changes.values()):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
