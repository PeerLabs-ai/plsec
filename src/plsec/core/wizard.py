"""
Interactive wizard for plsec commands.

Provides consistent prompts for create and secure workflows.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TypeVar

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

console = Console()

T = TypeVar("T")


@dataclass
class Choice:
    """A single choice in a selection prompt."""

    value: str
    label: str
    description: str | None = None
    checked: bool = False  # For multi-select defaults


@dataclass
class WizardState:
    """Accumulated state from wizard questions."""

    project_name: str = ""
    project_type: str = "python"
    agents: list[str] = field(default_factory=lambda: ["claude", "opencode"])
    preset: str = "balanced"
    sensitive_data: list[str] = field(default_factory=list)
    cloud_providers: list[str] = field(default_factory=list)

    # Detected values (for secure command)
    detected_type: str | None = None
    detected_providers: list[str] = field(default_factory=list)
    existing_security: dict[str, bool] = field(default_factory=dict)


class Wizard:
    """Interactive wizard for gathering user input."""

    def __init__(self, title: str) -> None:
        """
        Initialize wizard.

        Args:
            title: Title shown at the top of the wizard.
        """
        self.title = title
        self.state = WizardState()
        self.step = 0
        self.total_steps = 0

    def header(self, total_steps: int) -> None:
        """Display wizard header."""
        self.total_steps = total_steps
        console.print()
        console.print(Panel(f"[bold]{self.title}[/bold]", box=box.ROUNDED))
        console.print()

    def step_header(self, title: str) -> None:
        """Display step header."""
        self.step += 1
        console.print(f"[dim][{self.step}/{self.total_steps}][/dim] [bold]{title}[/bold]")

    def select(
        self,
        prompt: str,
        choices: list[Choice],
        default: str | None = None,
    ) -> str:
        """
        Single selection prompt.

        Args:
            prompt: Question to ask.
            choices: List of choices.
            default: Default value.

        Returns:
            Selected value.
        """
        console.print(f"    {prompt}\n")

        # Display choices
        for i, choice in enumerate(choices, 1):
            marker = ">" if choice.value == default else " "
            label = choice.label
            if choice.description:
                label += f" [dim]- {choice.description}[/dim]"
            console.print(f"    {marker} [{i}] {label}")

        console.print()

        # Get selection
        valid_choices = [str(i) for i in range(1, len(choices) + 1)]
        valid_choices.extend([c.value for c in choices])

        while True:
            response = Prompt.ask(
                "    Select",
                default=str(choices.index(next(c for c in choices if c.value == default)) + 1)
                if default
                else "1",
            )

            if response in valid_choices:
                if response.isdigit():
                    return choices[int(response) - 1].value
                return response

            console.print(f"    [red]Invalid choice. Enter 1-{len(choices)}[/red]")

    def multi_select(
        self,
        prompt: str,
        choices: list[Choice],
    ) -> list[str]:
        """
        Multi-selection prompt.

        Args:
            prompt: Question to ask.
            choices: List of choices with default checked state.

        Returns:
            List of selected values.
        """
        console.print(f"    {prompt}")
        console.print("    [dim](Enter numbers separated by commas, or 'done')[/dim]\n")

        # Track selected state
        selected = {c.value: c.checked for c in choices}

        def display_choices() -> None:
            for i, choice in enumerate(choices, 1):
                marker = "x" if selected[choice.value] else " "
                console.print(f"    [{marker}] [{i}] {choice.label}")

        display_choices()
        console.print()

        while True:
            response = Prompt.ask("    Toggle (or 'done')").strip().lower()

            if response in ("done", "d", ""):
                break

            try:
                # Handle comma-separated numbers
                nums = [int(n.strip()) for n in response.split(",")]
                for num in nums:
                    if 1 <= num <= len(choices):
                        value = choices[num - 1].value
                        selected[value] = not selected[value]
                    else:
                        console.print(f"    [red]Invalid: {num}[/red]")

                # Redisplay
                console.print()
                display_choices()
                console.print()

            except ValueError:
                console.print("    [red]Enter numbers (e.g., 1,2,3) or 'done'[/red]")

        return [v for v, s in selected.items() if s]

    def confirm(
        self,
        prompt: str,
        default: bool = True,
    ) -> bool:
        """
        Yes/no confirmation prompt.

        Args:
            prompt: Question to ask.
            default: Default value.

        Returns:
            True for yes, False for no.
        """
        return Confirm.ask(f"    {prompt}", default=default)

    def text(
        self,
        prompt: str,
        default: str = "",
        validator: Callable[[str], bool] | None = None,
    ) -> str:
        """
        Free text input prompt.

        Args:
            prompt: Question to ask.
            default: Default value.
            validator: Optional validation function.

        Returns:
            User input.
        """
        while True:
            response = Prompt.ask(f"    {prompt}", default=default)

            if validator is None or validator(response):
                return response

            console.print("    [red]Invalid input[/red]")

    def summary(self, items: dict[str, str]) -> None:
        """
        Display a summary table.

        Args:
            items: Key-value pairs to display.
        """
        console.print()
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Key", style="dim")
        table.add_column("Value")

        for key, value in items.items():
            table.add_row(key, value)

        console.print(table)
        console.print()

    def info(self, message: str) -> None:
        """Display info message."""
        console.print(f"    [blue][i][/blue] {message}")

    def warn(self, message: str) -> None:
        """Display warning message."""
        console.print(f"    [yellow][!][/yellow] {message}")

    def error(self, message: str) -> None:
        """Display error message."""
        console.print(f"    [red][x][/red] {message}")

    def success(self, message: str) -> None:
        """Display success message."""
        console.print(f"    [green][OK][/green] {message}")


# Pre-defined choice sets for reuse
PROJECT_TYPE_CHOICES = [
    Choice("python", "Python", "Django, FastAPI, CLI"),
    Choice("node", "Node.js", "Express, Next.js, CLI"),
    Choice("go", "Go"),
    Choice("rust", "Rust"),
    Choice("mixed", "Mixed / Polyglot"),
    Choice("other", "Other"),
]

AGENT_CHOICES = [
    Choice("claude", "Claude Code", checked=True),
    Choice("opencode", "Opencode", checked=True),
    Choice("copilot", "GitHub Copilot"),
    Choice("cursor", "Cursor"),
    Choice("other", "Other"),
]

PRESET_CHOICES = [
    Choice("minimal", "Minimal", "Secret scanning only"),
    Choice("balanced", "Balanced", "Full static analysis, audit logging"),
    Choice("strict", "Strict", "Add container isolation, runtime proxy"),
    Choice("paranoid", "Paranoid", "Network isolation, integrity monitoring"),
]

SENSITIVE_DATA_CHOICES = [
    Choice("api_keys", "API keys", "Cloud providers, SaaS"),
    Choice("database", "Database credentials"),
    Choice("pii", "PII / Customer data"),
    Choice("payment", "Payment / Financial data"),
    Choice("healthcare", "Healthcare / HIPAA"),
    Choice("secrets", "Secrets / Encryption keys"),
]

CLOUD_PROVIDER_CHOICES = [
    Choice("aws", "AWS"),
    Choice("gcp", "Google Cloud"),
    Choice("azure", "Azure"),
    Choice("digitalocean", "DigitalOcean"),
    Choice("cloudflare", "Cloudflare"),
    Choice("none", "None / Self-hosted"),
]
