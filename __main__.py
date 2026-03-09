"""
Entry point: python -m dll_injector
"""

import ctypes
import sys


def is_admin() -> bool:
    """Check if running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main() -> None:
    # Set console window title
    ctypes.windll.kernel32.SetConsoleTitleW("WHISSKY — DLL Injector v1.0")

    if not is_admin():
        print()
        print("  +--------------------------------------------------+")
        print("  |  !  Please run as Administrator for injection  |")
        print("  |     Right-click -> Run as administrator        |")
        print("  +--------------------------------------------------+")
        print()
        input("  Press Enter to continue anyway (limited mode)...")

    from .app import DLLInjectorApp

    app = DLLInjectorApp()
    app.run()


if __name__ == "__main__":
    main()
