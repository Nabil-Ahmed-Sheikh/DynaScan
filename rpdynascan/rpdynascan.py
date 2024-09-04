# rpdynascan/rpdynascan.py
from pathlib import Path
from typing import Any, Dict, List, NamedTuple
from rpdynascan import DB_READ_ERROR
from rpdynascan.database import DatabaseHandler
from scanner import sql_injection_scanner
import uuid

class Log(NamedTuple):
    report: Dict[str, Any]
    error: int

class Dynascanner:
    def __init__(self, db_path: Path) -> None:
        self._db_handler = DatabaseHandler(db_path)
    
    def scan_sql_injection(self, url: str, params: Dict) -> Log:
        """Scan for sql injection vulnerability of an URL."""
        vulnerabilities = sql_injection_scanner.scan_sql_injection(url, params)
        print(vulnerabilities)

        report = {
            "id": uuid.uuid4(),
            "Description": vulnerabilities,
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return Log(report, write.error)