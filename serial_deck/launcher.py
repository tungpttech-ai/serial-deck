"""Entry point of the frozen app bundle: `serial-deck [app|web|desktop|hub|flash|mcp|console] ...`.

pip installs keep their own console scripts (`serial-deck`, `serial-deck-web`, ...);
this dispatcher is what PyInstaller freezes. With no subcommand (a launch from
the Start menu, Dock or an app launcher) it opens the app. Subcommands import
their module lazily, so one missing optional part breaks only that command.
"""

from __future__ import annotations

import sys

COMMANDS = {
    "app": ("app", "native window with the Web dashboard (default)"),
    "web": ("web", "Web dashboard in your browser"),
    "desktop": ("desktop_hub", "Tk desktop app"),
    "hub": ("hub", "the shared UART hub daemon (--status, --shutdown)"),
    "flash": ("flash", "flash an ESP-IDF build"),
    "mcp": ("mcp_server", "MCP server for AI agents (stdio)"),
    "console": ("uart_client", "terminal console: monitor, hello, query, button, reset, ..."),
}


def usage() -> str:
    lines = ["usage: serial-deck [command] [options]", "", "commands:"]
    lines += [f"  {name:<9} {help_text}" for name, (_module, help_text) in COMMANDS.items()]
    lines += ["", "Run `serial-deck <command> --help` for a command's options."]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import multiprocessing
    multiprocessing.freeze_support()  # harmless; required if a child ever uses spawn
    args = list(sys.argv[1:] if argv is None else argv)
    # AppRun / Finder may pass these before the subcommand; they are not ours.
    args = [a for a in args if a != "--appimage-extract-and-run" and not a.startswith("-psn_")]
    if args and args[0] in ("-h", "--help"):
        print(usage())
        return 0
    if args and args[0] in ("-V", "--version"):
        from serial_deck import __version__
        print(f"serial-deck {__version__}")
        return 0
    if args and args[0] == "host-exec":  # internal: see runtime.popen_host
        from serial_deck import runtime
        return runtime.host_exec(args[1:])
    command = args.pop(0) if args and args[0] in COMMANDS else "app"
    module_name = COMMANDS[command][0]
    import importlib
    module = importlib.import_module(f"serial_deck.{module_name}")
    result = module.main(args)
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    raise SystemExit(main())
