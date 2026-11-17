from collections import Counter
from pathlib import Path


DATA_DIR = Path(__file__).parent / "osv_data" / "PyPI"

def main():
    prefixes = Counter(path.name.split("-")[0] for path in DATA_DIR.glob("*.json"))

    for prefix, count in prefixes.most_common():
        print(f"{prefix}: {count}")

if __name__ == "__main__":
    main()