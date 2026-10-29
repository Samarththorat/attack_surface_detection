"""Test package with an isolated SQLite database for all test modules."""

import atexit
import os
import tempfile

from database import database


_test_database = tempfile.NamedTemporaryFile(prefix="asr-tests-", suffix=".db", delete=False)
_test_database_path = _test_database.name
_test_database.close()
database.DB_PATH = _test_database_path


def _remove_test_database():
    try:
        os.remove(_test_database_path)
    except FileNotFoundError:
        pass


atexit.register(_remove_test_database)
