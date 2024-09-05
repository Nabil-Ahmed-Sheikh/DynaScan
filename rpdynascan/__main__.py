"""RP Dyna Scan entry point script."""
# rpdynascan/__main__.py
import typer
from rpdynascan import cli, __app_name__


def main():
    try:
        cli.app(prog_name=__app_name__)
    except Exception as e:
        typer.secho(
        f"""Error Message: {e}""",
        fg=typer.colors.BRIGHT_RED,
    )

if __name__ == "__main__":
    main()