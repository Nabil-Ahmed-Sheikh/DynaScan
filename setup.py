from setuptools import setup, find_packages

setup(
    name="rpdynascan",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "typer==0.3.2",
        "colorama==0.4.4",
        "shellingham==1.4.0",
        "pytest==6.2.4",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "rpdynascan=rpdynascan.cli:app",  # The "rpdynascan" command will call the app defined in rpdynascan.cli
        ],
    },
)
