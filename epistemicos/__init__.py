from pathlib import Path

# Create package structure and empty __init__.py files
pkg_dir = Path("epistemicos")
pkg_dir.mkdir(exist_ok=True)

init_file = pkg_dir / "__init__.py"
if not init_file.exists():
    init_file.touch()
