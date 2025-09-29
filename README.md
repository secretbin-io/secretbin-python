# SecretBin-Python

This module allows for automatic secret creation in SecretBin. Note however this
module currently only support creating AES256-GCM secrets. XChaCha20 is
currently not supported.

## Installation

```bash
pip3 install git+https://github.com/SecretBin-io/secretbin-python.git@v2.1.1
```

## Usage

```python
from secretbin import Secret, SecretBin

sb = SecretBin("http://localhost:8000")

secret = Secret(message="Hello, world!")
secret.add_file_attachment(file="README.md")
link = sb.submit_secret(secret=secret,
                        password="secret",
                        expires="1hr",
                        burn_after=1)
print(link)
```
