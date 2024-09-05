# rpdynascan/rpdynascan.py
from pathlib import Path
from typing import Any, Dict, List, NamedTuple
from rpdynascan import DB_READ_ERROR
from rpdynascan.database import DatabaseHandler
import uuid
import time

from scanner.sql_injection_scanner import scan_sql_injection
from scanner.broken_authentication_scanner import scan_broken_authentication
from scanner.broken_authentication_scanner import scan_broken_authentication
from scanner.insecure_deserialization_scanner import scan_insecure_deserialization
from scanner.open_ports_scanner import scan_open_ports
from scanner.security_misconfiguration_scanner import scan_security_misconfigurations, scan_for_improper_logging, scan_for_ria_policy_files
from scanner.sensitive_data_exposure_scanner import scan_sensitive_data_exposure
from scanner.xss_scanner import scan_xss

class Log(NamedTuple):
    report: Dict[str, Any]
    error: int

class Dynascanner:
    def __init__(self, db_path: Path) -> None:
        self._db_handler = DatabaseHandler(db_path)
    
    def scan_sql_injection(self, url: str, params: Dict) -> Log:
        """Scan for sql injection vulnerability of an URL."""
        vulnerabilities = scan_sql_injection(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "type": "SQL Injection",
            "time": time.time(),
            "found_issue": "N" if len(vulnerabilities) < 1 else 'Y',
            "vulnerabilities": vulnerabilities
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return Log(report, write.error)

    def scan_broken_authentication(self, url: str, params: Dict) -> Log:
        """Scan for sql injection vulnerability of an URL."""
        vulnerabilities = scan_broken_authentication(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "type": "Broken Authentication",
            "time": time.time(),
            "found_issue": "N" if len(vulnerabilities) < 1 else 'Y',
            "vulnerabilities": vulnerabilities
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return Log(report, write.error)
    
    