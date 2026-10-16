"""Compatibility forwarder: use 'scripts/init_db.py' instead."""
from scripts.init_db import init_database

if __name__ == "__main__":
    init_database()