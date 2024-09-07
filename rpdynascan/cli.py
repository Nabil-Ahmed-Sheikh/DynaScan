"""This module provides the RP Dyna Scan CLI."""
# rpdynascan/cli.py

from pathlib import Path
from typing import Optional
from typing import Dict
import json
import typer
from rpdynascan import (
    ERRORS, __app_name__, __version__, config, database, rpdynascan
)
from typing import List, Optional

app = typer.Typer()

@app.command()
def init(
    db_path: str = typer.Option(
        str(database.DEFAULT_DB_FILE_PATH),
        "--db-path",
        "-db",
        prompt="dyna database location?",
    ),
) -> None:
    """Initialize the dyna scan database."""
    app_init_error = config.init_app(db_path)
    if app_init_error:
        typer.secho(
            f'Creating config file failed with "{ERRORS[app_init_error]}"',
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    db_init_error = database.init_database(Path(db_path))
    if db_init_error:
        typer.secho(
            f'Creating database failed with "{ERRORS[db_init_error]}"',
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    else:
        typer.secho(f"The dyna scan database is {db_path}", fg=typer.colors.GREEN)

def get_dynascanner() -> rpdynascan.Dynascanner:
    if config.CONFIG_FILE_PATH.exists():
        db_path = database.get_database_path(config.CONFIG_FILE_PATH)
    else:
        typer.secho(
            'Config file not found. Please, run "rpdynascan init"',
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)
    if db_path.exists():
        return rpdynascan.Dynascanner(db_path)
    else:
        typer.secho(
            'Database not found. Please, run "rpdynascan init"',
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

@app.command()
def scan_sql_injection(
    url: str = typer.Argument(...),
    params = typer.Argument(...),
) -> None:
    """Scan for sql injection vulnerability of an URL"""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    log = scanner.scan_sql_injection(url, parsed_params)

    if log.report["found_issue"] == "Y":
        typer.secho(
            f"""Vulnerability detected: {log}""",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(
            f"""Vulnerability not found""",
            fg=typer.colors.GREEN,
        )

@app.command()
def scan_broken_authentication(
    url: str = typer.Argument(...),
    params = typer.Option(...,  "--params", "-p"),
) -> None:
    """Scan for broken authentication vulnerability of an URL"""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    vulnerability = scanner.scan_broken_authentication(url, parsed_params)


    if vulnerability["found_issue"] == "Y":
        typer.secho(
            f"""Vulnerability detected: {vulnerability}""",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(
            f"""Vulnerability not found""",
            fg=typer.colors.GREEN,
        )

@app.command()
def scan_insecure_deserialization(
    url: str = typer.Argument(...),
    params = typer.Argument(...),
) -> None:
    """Scan for insecure deserialization vulnerability of an URL."""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    vulnerability = scanner.scan_insecure_deserialization(url, parsed_params)

    if len(vulnerability) > 0:
        typer.secho(
            f"""Vulnerability detected: {vulnerability}""",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(
            f"""Vulnerability not found""",
            fg=typer.colors.GREEN,
        )

@app.command()
def scan_open_ports(
    url: str = typer.Argument(...),
    params = typer.Argument(...),
) -> None:
    """Scan for open ports vulnerability of an URL."""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    vulnerability = scanner.scan_open_ports(url, parsed_params)

    if len(vulnerability) > 0:
        typer.secho(
            f"""Vulnerability detected: {vulnerability}""",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(
            f"""Vulnerability not found""",
            fg=typer.colors.GREEN,
        )

@app.command()
def scan_security_misconfigurations(
    url: str = typer.Argument(...),
    params = typer.Argument(...),
) -> None:
    """Scan for security misconfigurations vulnerability of an URL."""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    vulnerability = scanner.scan_security_misconfigurations(url, parsed_params)

    if len(vulnerability) > 0:
        typer.secho(
            f"""Vulnerability detected: {vulnerability}""",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(
            f"""Vulnerability not found""",
            fg=typer.colors.GREEN,
        )

@app.command()
def scan_for_improper_logging(
    url: str = typer.Argument(...),
    params = typer.Argument(...),
) -> None:
    """Scan for improper logging vulnerability of an URL."""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    vulnerability = scanner.scan_for_improper_logging(url, parsed_params)

    if len(vulnerability) > 0:
        typer.secho(
            f"""Vulnerability detected: {vulnerability}""",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(
            f"""Vulnerability not found""",
            fg=typer.colors.GREEN,
        )

@app.command()
def scan_for_ria_policy_files(
    url: str = typer.Argument(...),
    params = typer.Argument(...),
) -> None:
    """Scan for ria policy files vulnerability of an URL."""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    vulnerability = scanner.scan_for_ria_policy_files(url, parsed_params)

    if len(vulnerability) > 0:
        typer.secho(
            f"""Vulnerability detected: {vulnerability}""",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(
            f"""Vulnerability not found""",
            fg=typer.colors.GREEN,
        )

@app.command()
def scan_sensitive_data_exposure(
    url: str = typer.Argument(...),
    params = typer.Argument(...),
) -> None:
    """Scan for sensitive data exposure vulnerability of an URL."""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    vulnerability = scanner.scan_sensitive_data_exposure(url, parsed_params)

    if len(vulnerability) > 0:
        typer.secho(
            f"""Vulnerability detected: {vulnerability}""",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(
            f"""Vulnerability not found""",
            fg=typer.colors.GREEN,
        )

@app.command()
def scan_xss(
    url: str = typer.Argument(...),
    params = typer.Argument(...),
) -> None:
    """Scan for xss vulnerability of an URL."""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    vulnerability = scanner.scan_xss(url, parsed_params)

    if len(vulnerability) > 0:
        typer.secho(
            f"""Vulnerability detected: {vulnerability}""",
            fg=typer.colors.RED,
        )
    else:
        typer.secho(
            f"""Vulnerability not found""",
            fg=typer.colors.GREEN,
        )

@app.command()
def report() -> None:
    """View Report."""
    scanner = get_dynascanner()
    vulnerability_list = scanner.get_report()
    if len(vulnerability_list) == 0:
        typer.secho(
            "There are no vulnerability to report yet", fg=typer.colors.BRIGHT_YELLOW
        )
        raise typer.Exit()
    typer.secho("\nVulnerability list:\n", fg=typer.colors.BLUE, bold=True)
    columns = (
        "ID.  ",
        "| URL ",
        "| Type  ",
        "| Description  ",
        "| Vulnarable  ",
        "| Params  ",
        "| Time  ",
        
    )
    headers = "".join(columns)
    typer.secho(headers, fg=typer.colors.BLUE, bold=True)
    typer.secho("-" * len(headers), fg=typer.colors.BLUE)
    for _, vulnerability in enumerate(vulnerability_list, 1):
        id, url, params, type, vulnerabilities, found_issue, time = vulnerability.values()
        typer.secho(
            f"{id}{(len(columns[0]) - len(str(id))) * ' '}"
            f"| ({url}){(len(columns[1]) - len(str(url))) * ' '}"
            f"| {type}{(len(columns[1]) - len(str(type))) * ' '}"
            f"| {time}{(len(columns[1]) - len(str(time))) * ' '}"
            f"| {found_issue}{(len(columns[1]) - len(str(found_issue))) * ' '}"
            f"| {params}{(len(columns[1]) - len(str(params))) * ' '}"
            f"| {vulnerabilities}",
            fg=typer.colors.CYAN,
        )
    typer.secho("-" * len(headers) + "\n", fg=typer.colors.BLUE)

def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{__app_name__} v{__version__}")
        raise typer.Exit()

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=_version_callback,
        is_eager=True,
    )
) -> None:
    return