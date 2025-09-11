from secretbin import Secret, SecretBin

sb = SecretBin("http://localhost:8000")

secret = Secret(message="Hello, world!")
secret.add_file_attachment(file="README.md")
link = sb.submit_secret(secret=secret,
                        password="secret",
                        expires="1hr",
                        burn_after=1)
print(link)
