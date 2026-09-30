"""Script to verify all project source files are under ~300 lines."""

from pathlib import Path



def check_line_counts():
    root = Path(".")
    max_limit = 300
    violations = []
    total_files = 0

    ignore_dirs = {".git", ".pytest_cache", "vendor", "__pycache__", "securelink.egg-info", "keys", "logs"}
    valid_exts = {".py", ".js", ".html", ".css", ".yaml", ".md"}

    print(f"{'LINES':<8} {'STATUS':<8} {'FILE PATH'}")
    print("-" * 65)

    for path in sorted(root.rglob("*")):
        if any(ignored in path.parts for ignored in ignore_dirs):
            continue
        if path.is_file() and path.suffix in valid_exts and path.name != "chart.umd.min.js":
            total_files += 1
            lines = len(path.read_text(encoding="utf-8", errors="ignore").splitlines())
            status = "OK" if lines <= max_limit else "EXCEEDED"
            print(f"{lines:<8} {status:<8} {path}")
            if lines > max_limit:
                violations.append((path, lines))

    print("-" * 65)
    print(f"Scanned {total_files} files.")
    if violations:
        print(f"FAILED: {len(violations)} files exceeded {max_limit} lines!")
    else:
        print(f"PASSED: All source files stay under {max_limit} lines limit.")


if __name__ == "__main__":
    check_line_counts()
