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
            "url": url,
            "params": params,
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
        return report

    def scan_broken_authentication(self, url: str, params: Dict) -> Log:
        """Scan for broken authentication vulnerability of an URL."""
        vulnerabilities = scan_broken_authentication(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "url": url,
            "params": params,
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
        return report
    
    def scan_insecure_deserialization(self, url: str, params: Dict) -> Log:
        """Scan for insecure deserialization vulnerability of an URL."""
        vulnerabilities = scan_insecure_deserialization(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "url": url,
            "params": params,
            "type": "Insecure deserialization",
            "time": time.time(),
            "found_issue": "N" if len(vulnerabilities) < 1 else 'Y',
            "vulnerabilities": vulnerabilities
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return report
    
    def scan_open_ports(self, url: str, params: Dict) -> Log:
        """Scan for open ports vulnerability of an URL."""
        vulnerabilities = scan_open_ports(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "url": url,
            "params": params,
            "type": "Open ports",
            "time": time.time(),
            "found_issue": "N" if len(vulnerabilities) < 1 else 'Y',
            "vulnerabilities": vulnerabilities
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return report
    
    def scan_security_misconfigurations(self, url: str, params: Dict) -> Log:
        """Scan for security misconfigurations vulnerability of an URL."""
        vulnerabilities = scan_security_misconfigurations(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "url": url,
            "params": params,
            "type": "Security misconfigurations",
            "time": time.time(),
            "found_issue": "N" if len(vulnerabilities) < 1 else 'Y',
            "vulnerabilities": vulnerabilities
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return report
    
    def scan_for_improper_logging(self, url: str, params: Dict) -> Log:
        """Scan for improper logging vulnerability of an URL."""
        vulnerabilities = scan_for_improper_logging(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "url": url,
            "params": params,
            "type": "Improper logging",
            "time": time.time(),
            "found_issue": "N" if len(vulnerabilities) < 1 else 'Y',
            "vulnerabilities": vulnerabilities
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return report
    
    def scan_for_ria_policy_files(self, url: str, params: Dict) -> Log:
        """Scan for ria policy files vulnerability of an URL."""
        vulnerabilities = scan_for_ria_policy_files(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "url": url,
            "params": params,
            "type": "Ria policy files",
            "time": time.time(),
            "found_issue": "N" if len(vulnerabilities) < 1 else 'Y',
            "vulnerabilities": vulnerabilities
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return report
    
    def scan_sensitive_data_exposure(self, url: str, params: Dict) -> Log:
        """Scan for sensitive data exposure vulnerability of an URL."""
        vulnerabilities = scan_sensitive_data_exposure(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "url": url,
            "params": params,
            "type": "Sensitive data exposure",
            "time": time.time(),
            "found_issue": "N" if len(vulnerabilities) < 1 else 'Y',
            "vulnerabilities": vulnerabilities
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return report
    
    def scan_xss(self, url: str, params: Dict) -> Log:
        """Scan for xss vulnerability of an URL."""
        vulnerabilities = scan_xss(url, params)
        
        report = {
            "id": uuid.uuid1().int,
            "url": url,
            "params": params,
            "url": url,
            "params": params,
            "type": "Xss",
            "time": time.time(),
            "found_issue": "N" if len(vulnerabilities) < 1 else 'Y',
            "vulnerabilities": vulnerabilities
        }
        read = self._db_handler.read_report()
        if read.error == DB_READ_ERROR:
            return Log(report, read.error)
        read.vulnerable_list.append(report)
        write = self._db_handler.write_report(read.vulnerable_list)
        return report
    
    def get_report(self) -> List[Dict[str, Any]]:
        """Return the full report history."""
        read = self._db_handler.read_report()
        return read.vulnerable_list