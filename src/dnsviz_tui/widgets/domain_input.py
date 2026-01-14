"""Domain input widget."""

import re
from textual.widgets import Input
from textual.validation import Validator, ValidationResult


class DomainValidator(Validator):
    """Validator for domain names."""

    # Domain name pattern (simplified)
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z]{2,}\.?$'
    )

    def validate(self, value: str) -> ValidationResult:
        """Validate a domain name."""
        if not value:
            return self.failure("Enter a domain name")

        value = value.strip()

        # Check for valid characters
        if not self.DOMAIN_PATTERN.match(value):
            return self.failure("Invalid domain format")

        # Check length
        if len(value) > 253:
            return self.failure("Domain name too long")

        return self.success()


class DomainInput(Input):
    """Input widget for entering domain names."""

    DEFAULT_CSS = """
    DomainInput:focus {
        border: tall $accent;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(
            placeholder="Enter domain (e.g., example.com)",
            validators=[DomainValidator()],
            **kwargs
        )

    @property
    def domain(self) -> str:
        """Get the normalized domain."""
        value = self.value.strip()
        if value and not value.endswith('.'):
            value = value + '.'
        return value
