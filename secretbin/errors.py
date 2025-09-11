from pydantic import BaseModel


class SecretBinError(BaseModel):
    """
    Error class for JSON API errors in SecretBin

    Attributes:
        name: Name of the error
        message: Optional error message
        status: HTTP status code associated with the error
    """
    name: str
    message: str = ""
    status: int = 0

    def __str__(self) -> str:
        """
        Returns a string representation of the error

        Returns:
            str: Formatted string showing the error name and message
        """

        return f"{self.name}: {self.message}"

    def is_same(self, other: Exception) -> bool:
        """
        is_same checks if the current error is the same as another exception based on its name.

        Args:
            other (Exception): The exception to compare with

        Returns:
            bool: True if the other exception is a SecretBinError and has the same name, False otherwise
        """
        return isinstance(other, SecretBinError) and self.name == other.name


class SecretBinException(Exception):
    """
    Exception for SecretBin API errors
    """

    def __init__(self, err: SecretBinError):
        self.err = err
