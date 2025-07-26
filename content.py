import json
import mimetypes
import secrets
from base64 import b64encode
from dataclasses import dataclass, field
from os import path
from typing import List

from base58 import b58encode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


@dataclass
class Attachment:
    """
    Represents an attachment to a secret message

    Attributes:
        name: Name of the attachment file
        content_type: MIME type of the attachment (optional, guessed base on file extension)
        data: Binary data of the attachment
    """
    name: str
    content_type: str
    data: bytes


@dataclass
class Secret:
    """
    Represents a secret message with optional attachments
    """
    message: str
    attachments: List[Attachment] = field(default_factory=list)

    def add_attachment(self, name: str, content_type: str, data: bytes):
        """
        add_attachment adds an attachment to the secret content.
        If the content type is not provided, it will be guessed based on the file extension.

        Args:
            name (str): Name of the attachment file
            content_type (str): MIME type of the attachment (optional, guessed based on file extension)
            data (bytes): Binary data of the attachment
        """

        self.attachments.append(Attachment(name, content_type, data))

    def add_file_attachment(self, file: str):
        """
        add_file_attachment reads a file from the given path and adds it as an attachment to the secret content.
        The content type is guessed based on the file extension.

        Args:
            file (str): Path to the file to be attached
        """

        with open(file, "rb") as f:
            data = f.read()
        content_type, _ = mimetypes.guess_type(file)
        self.add_attachment(path.basename(file), content_type or "", data)

    def encrypted(self, password: str) -> tuple[str, str]:
        """
        encrypted encrypts the secret content using AES-256-GCM and returns the base58 encoded key and a crypto URL.

        Args:
            password (str): Optional password used to derive the encryption key along with a random base key

        Returns:
            tuple[str, str]: A tuple containing the base58 encoded base key and the crypto URL with the encrypted secret content.
        """

        # Ensure attachments is not None
        if self.attachments is None:
            self.attachments = []

        # Ensure all attachments have a content type
        for att in self.attachments:
            if not att.content_type:
                att.content_type, _ = mimetypes.guess_type(att.name)
                att.content_type = att.content_type or ""

        # Marshal the secret content to JSON
        # Need to base64 encode the data field for JSON serialization
        def attachment_to_dict(att):
            return {
                "name": att.name,
                "contentType": att.content_type,
                "data": b64encode(att.data).decode("utf-8"),
            }
        secret_dict = {
            "message": self.message,
            "attachments": [attachment_to_dict(a) for a in self.attachments],
        }
        data = json.dumps(secret_dict).encode("utf-8")

        # Generate random base key, IV, and salt
        base_key = secrets.token_bytes(32)
        iv = secrets.token_bytes(12)
        salt = secrets.token_bytes(16)
        iter_count = 210_000

        # Derive key using PBKDF2-HMAC-SHA512
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=iter_count,
        )
        key = kdf.derive(base_key + password.encode("utf-8"))

        # Encrypt using AES-GCM
        aesgcm = AESGCM(key)
        enc = aesgcm.encrypt(iv, data, None)

        # Compose crypto URL
        crypto_url = (
            f"crypto://?algorithm=AES256-GCM"
            f"&key-algorithm=pbkdf2"
            f"&nonce={b58encode(iv).decode()}"
            f"&salt={b58encode(salt).decode()}"
            f"&iter={iter_count}"
            f"&hash=SHA-512#"
            f"{b64encode(enc).decode()}"
        )

        # Encode base key in base58
        base_key_b58 = b58encode(base_key).decode()

        return base_key_b58, crypto_url
