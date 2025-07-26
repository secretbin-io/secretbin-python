from dataclasses import dataclass
from typing import Any, Dict, Optional, Type, TypeVar

from pydantic import BaseModel
from requests import request

from secretbin.config import Expires
from secretbin.errors import SecretBinError


class _ApiInfo(BaseModel):
    """JSON result for: GET /api/info"""
    version: str


class _ApiConfigBanner(BaseModel):
    """Partial JSON result for: GET /api/config"""
    enabled: bool
    type: str
    text: Dict[str, str]


class _ApiConfigBranding(BaseModel):
    """Partial JSON result for: GET /api/config"""
    appName: str


class _ApiConfigDefaults(BaseModel):
    """Partial JSON result for: GET /api/config"""
    expires: str


class _ApiConfig(BaseModel):
    """Partial JSON result for: GET /api/config"""
    banner: _ApiConfigBanner
    branding: _ApiConfigBranding
    defaults: _ApiConfigDefaults
    expires: Dict[str, Expires]


@dataclass
class _PostSecretPayload:
    """Payload for: POST /api/secret"""
    data: str
    expires: str
    burnAfter: int
    passwordProtected: bool


class _PostSecretResult(BaseModel):
    """JSON result for: POST /api/secret"""
    id: str


T = TypeVar("T")


def _api_call(method: str, endpoint: str, path: str, payload: Optional[Any], result_cls: Type[T]) -> T:
    """
    _api_call is a generic function to make API calls to the SecretBin server
    It handles the HTTP request, response decoding, and error handling.
    T is the expected type of the response body.
    If the response status code is not 200, it returns a SecretBinError.

    Args:
        method (str): HTTP method to use for the request (GET or POST).
        endpoint (str): base URL of the SecretBin server, e.g. "https://secretbin.example.com"
        path (str): API path to call, e.g., "/api/info" or "/api/secret".
        payload (Optional[Any]): Data to send in the request body, if applicable.
            If None, no data is sent.
            If a dict, it is sent as JSON.
            If a dataclass, its __dict__ is used.
        result_cls (Type[T]): Expected type of the response body.

    Raises:
        SecretBinError: If the response status code is not 200, this error is raised with the error details from the response.

    Returns:
        T: An instance of result_cls containing the parsed response data.
    """

    headers = {}
    data = None
    if payload is not None:
        data = payload if isinstance(payload, dict) else payload.__dict__
        headers["Content-Type"] = "application/json"

    res = request(
        method=method,
        url=f"{endpoint}{path}",
        json=data,
        headers=headers,
    )

    if res.status_code != 200:
        try:
            raise SecretBinError(**res.json())
        except Exception:
            res.raise_for_status()

    return result_cls(**res.json())


def _get_api_info(endpoint: str) -> _ApiInfo:
    """
    _get_api_info retrieves the version information from the SecretBin server

    Args:
        endpoint (str): base URL of the SecretBin server, e.g. "https://secretbin.example.com"

    Returns:
        ApiInfo: An instance of ApiInfo containing the version information.
    """

    return _api_call("GET", endpoint, "/api/info", None, _ApiInfo)


def _get_api_config(endpoint: str) -> _ApiConfig:
    """
    _get_api_config retrieves the configuration from the SecretBin server.
    This includes banner settings, branding, default expiration, and available expiration times.

    Args:
        endpoint (str): base URL of the SecretBin server, e.g. "https://secretbin.example.com"

    Returns:
        ApiConfig: An instance of ApiConfig containing the server configuration.
    """

    return _api_call("GET", endpoint, "/api/config", None, _ApiConfig)


def _post_secret(endpoint: str, payload: _PostSecretPayload) -> _PostSecretResult:
    """
    _post_secret submits a new secret to the SecretBin server

    Args:
        endpoint (str): base URL of the SecretBin server, e.g. "https://secretbin.example.com"
        payload (PostSecretPayload): Payload containing the secret data and options

    Returns:
        PostSecretResult: An instance of PostSecretResult containing the ID of the created secret.
    """

    return _api_call("POST", endpoint, "/api/secret", payload, _PostSecretResult)
