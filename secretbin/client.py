from semver import Version

from .api import (_get_api_config, _get_api_info, _post_secret,
                  _PostSecretPayload)
from .config import Config
from .content import Secret
from .errors import SecretBinError

_min_cbor_version = Version.parse("3.1.0")


class SecretBin:
    """
    SecretBin is a client for the SecretBin service, allowing users to submit secrets with optional attachments.
    """

    def __init__(self, endpoint: str):
        """
        Initializes the SecretBin client with the given endpoint.

        Args:
            endpoint (str): base URL of the SecretBin server, e.g. "https://secretbin.example.com"

        Raises:
            SecretBinError: If there is an error retrieving the API configuration or information.
        """

        self.endpoint = endpoint

        try:
            cfg = _get_api_config(endpoint)
            info = _get_api_info(endpoint)

            self._config = Config(
                name=cfg.branding.appName,
                endpoint=endpoint,
                version=Version.parse(info.version),
                default_expires=cfg.defaults.expires,
                expires=cfg.expires
            )

            if cfg.banner.enabled:
                self._config.banner = {
                    "type": cfg.banner.type,
                    "text": cfg.banner.text["en"]
                }

            # Use CBOR if using SecretBin v2.1.0 or newer
            self._use_cbor = self._config.version.compare(
                _min_cbor_version) != -1

        except Exception as e:
            raise e

    @property
    def config(self) -> Config:
        """
        Returns the configuration of the SecretBin server.

        Returns:
            Config: An instance of Config containing the server's configuration details.
        """
        return self._config

    def submit_secret(self, secret: Secret, password: str = "", expires: str = "", burn_after: int = 0) -> str:
        """
        submit_secret submits a new secret to the SecretBin server

        Args:
            secret (Secret): The secret to be submitted, containing the message and optional attachments.
            password (str): Optional password used to derive the encryption key along with a random base key.
            expires (str): The expiration time for the secret. Use [SecretBin.config.expires] to get the available options.
            burn_after (int): Indicates after how many reads the secret should be deleted. 0 means no burn after reading.

        Raises:
            SecretBinError: If the expiration time is invalid or not supported by the server.

        Returns:
            str: A URL to access the submitted secret, including the secret ID and encryption key.
        """

        # If no expiration time is set, use the server's default one.
        if expires == "":
            expires = self.config.default_expires

        # Validate the expiration time against the server's available options.
        if expires not in self.config.expires:
            raise SecretBinError(
                name="InvalidExpirationTime",
                message=f"Invalid expiration time '{expires}'. Valid options are: {list(self.config.expires.keys())}",
            )

        # Encrypt the secret with the provided password and return the key and encrypted data.
        key, enc, data_bytes = secret.encrypted(
            password, use_cbor=self._use_cbor)

        # Create the payload for the secret to be posted to SecretBin.
        pl = _PostSecretPayload(
            expires=expires,
            burnAfter=burn_after,
            passwordProtected=password != "",
            data=enc,
            dataBytes=data_bytes,
        )
        
        # The SecretBin API uses -1 to indicate no burn after reading.
        # The value 0 is used to indicate that the secret should not be deleted by the server garbage collector.
        if pl.burnAfter == 0:
            pl.burnAfter = -1

        # Post the secret to the SecretBin server and retrieve the result.
        r = _post_secret(self.endpoint, pl, use_cbor=self._use_cbor)

        # Construct the URL to access the secret using the secret ID and the encryption key.
        return f"{self.endpoint}/secret/{r.id}#{key}"
