"""Colour policy. ``NO_COLOR`` and ``--no-colour`` both disable ANSI."""

from __future__ import annotations

import os

from rich.console import Console


def no_color_env() -> bool:
    """True when the process environment disables colour.

    The ``NO_COLOR`` convention treats a present variable as off, including
    an empty value.
    """

    return "NO_COLOR" in os.environ


def colour_enabled(*, no_colour: bool) -> bool:
    return not (no_colour or no_color_env())


def make_console(*, no_colour: bool, quiet: bool = False) -> Console:
    colour = colour_enabled(no_colour=no_colour)
    return Console(
        no_color=not colour,
        quiet=quiet,
        highlight=False,
        soft_wrap=True,
    )
