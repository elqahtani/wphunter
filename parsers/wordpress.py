from typing import List, Tuple


def parse_plugins(filepath: str) -> List[Tuple[str, str]]:
    """Parse WordPress plugins file.

    Supported formats:

    1. Simple: slug,version (one per line)
       elementor,3.6.0
       contact-form-7,5.5.0

    2. wp-cli output: wp plugin list --format=csv
       name,status,update,version
       elementor,active,available,3.6.0
       contact-form-7,active,none,5.5.0

    3. Tab-separated (wp-cli --format=table piped output)
       elementor	active	available	3.6.0

    Lines starting with # are comments.
    """
    with open(filepath, 'r') as f:
        content = f.read().strip()

    lines = content.splitlines()
    if not lines:
        return []

    # Detect wp-cli CSV format (header: name,status,update,version)
    header = lines[0].strip().lower()
    if header.startswith("name") and "version" in header:
        sep = '\t' if '\t' in header else ','
        return _parse_wpcli(lines, sep)

    # Simple format: slug,version
    return _parse_simple(lines)


def _parse_simple(lines: list) -> List[Tuple[str, str]]:
    """Parse simple slug,version format."""
    packages = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Support both comma and tab separated
        sep = '\t' if '\t' in line else ','
        parts = line.split(sep, 1)
        if len(parts) == 2:
            slug = parts[0].strip()
            version = parts[1].strip()
            if slug and version:
                packages.append((slug, version))

    return packages


def _parse_wpcli(lines: list, sep: str) -> List[Tuple[str, str]]:
    """Parse wp-cli output (CSV or table format)."""
    packages = []
    header = lines[0].strip().lower().split(sep)

    try:
        name_idx = header.index("name")
        version_idx = header.index("version")
    except ValueError:
        return packages

    for line in lines[1:]:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('+') or line.startswith('|'):
            continue

        parts = line.split(sep)
        if len(parts) <= max(name_idx, version_idx):
            continue

        slug = parts[name_idx].strip()
        version = parts[version_idx].strip()

        if slug and version:
            packages.append((slug, version))

    return packages
