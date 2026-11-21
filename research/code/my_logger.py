"""
logger.py - copy everything a script prints into a log file as well.

    from logger import start_logging
    start_logging("dataset_osv.log")    # from here on, every print() goes to the screen AND to the file
"""
import sys
from typing import TextIO


class MyLogger:
    """Takes the place of sys.stdout / sys.stderr: everything written to it goes to the console and to the log
    file. print() keeps working unchanged. (Not related to Python's logging.Logger.)"""

    def __init__(self, console: TextIO, log: TextIO) -> None:
        self.console = console
        self.log = log

    def write(self, text: str) -> None:
        self.console.write(text)
        self.log.write(text)

    def flush(self) -> None:
        self.console.flush()
        self.log.flush()


def start_logging(log_path: str) -> None:
    """Overwrite log_path and, from now on, copy everything printed (stdout and stderr) into it."""
    # not in a "with" block on purpose: Python prints the sys.exit() message or a crash traceback after
    # main() ends, and those lines must reach the log too. buffering=1 writes every line to disk at once;
    # the file is closed when the program exits.
    log = open(log_path, "w", encoding="utf-8", buffering=1)
    sys.stdout = MyLogger(sys.stdout, log)
    sys.stderr = MyLogger(sys.stderr, log)
