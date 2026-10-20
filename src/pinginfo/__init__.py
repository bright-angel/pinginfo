__version__ = "1.0.0"
__all__ = ["__version__", "main"]


def main() -> int:
    from .cli import main as cli_main

    return cli_main()
