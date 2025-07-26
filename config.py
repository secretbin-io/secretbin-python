from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Expires:
    """
    Represents an expiration time for a secret

    Attributes:
        count: Number of units for this expiration option
        unit: Unit of time for this expiration option (e.g., "hr", "d", "w", "m", "y")
        seconds: Duration in seconds for this expiration option
    """
    count: int
    unit: str
    seconds: int

    def __str__(self) -> str:
        """
        Returns a string representation of the expiration option

        Returns:
            str: A formatted string showing the count, unit, and total seconds
        """
        s = "s" if self.count > 1 else ""
        return f"{self.count} {self.unit}{s} ({self.seconds}s)"


@dataclass
class Banner:
    """
    Represents a banner that can be displayed on the SecretBin interface

    Attributes:
        type: The type of banner ()"info", "warning", "error")
        text: The text content of the banner
    """
    type: str
    text: str


@dataclass
class Config:
    """
    Represents the configuration for the SecretBin server

    Attributes:
        name: Name of the SecretBin server
        endpoint: Base URL of the SecretBin server
        version: Version of the SecretBin server
        banner: Optional banner to display on the interface
        expires: Dictionary of available expiration options, keyed by their identifier
        default_expires: Default expiration option identifier
    """

    name: str
    endpoint: str
    version: str
    banner: Optional[Banner] = None
    expires: Dict[str, Expires] = field(default_factory=dict)
    default_expires: Optional[str] = None

    def expires_sorted(self) -> List[tuple[str, Expires]]:
        """
        Returns a sorted list of expiration options based on their duration in seconds

        Returns:
            List[tuple[str, Expires]]: A list of tuples where each tuple contains the identifier and the Expires object,
        """

        return sorted(self.expires.items(), key=lambda item: item[1].seconds)

    def expire_options_sorted(self) -> List[str]:
        """
        Returns a sorted list of expiration option identifiers based on their duration in seconds

        Returns:
            List[str]: A list of expiration option identifiers sorted by their duration
        """

        return [k for k, _ in self.expires_sorted()]
