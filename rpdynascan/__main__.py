"""RP Dyna Scan entry point script."""
# rpdynascan/__main__.py

from rpdynascan import cli, __app_name__

def main():
    try:
        cli.app(prog_name=__app_name__)
    except RuntimeError:
        print(RuntimeError)

if __name__ == "__main__":
    main()