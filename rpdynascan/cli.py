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
    """Scan for sql injection vulnarability of an URL"""
    scanner = get_dynascanner()
    parsed_params = json.loads(params)
    vulnerability = scanner.scan_sql_injection(url, parsed_params)

    typer.secho(
        f"""Vulnerability detected: {vulnerability}""",
        fg=typer.colors.RED,
    )

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