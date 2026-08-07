from .config import load_settings
from .db import connect, migrate


def main() -> None:
    settings = load_settings()
    applied = migrate(connect(settings.db_path))
    print(f"migrations applied: {applied or 'none (up to date)'}")


if __name__ == "__main__":
    main()
