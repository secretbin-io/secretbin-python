# SecretBin-Python
This module allows for automatic secret creation in SecretBin. Note however this module currently only support creating AES256-GCM secrets. XChaCha20 is currently not supported.

## Usage
``` python
from secretbin.content import Secret

from secretbin import secretbin

sb = secretbin.SecretBin("http://localhost:8000")

secret = Secret(message="Hello, world!")
secret.add_file_attachment(file="README.md")
link = sb.submit_secret(secret=secret,
                        options=secretbin.Options(
                            password="secret",
                            expires="1hr",
                            burn_after=1))
print(link)
```