# My Private Network – standalone installation

This folder is for running the tool without Home Assistant. The application file is `../my_private_network/mpn.py`.


A small IP address manager with a web UI. One Python file, standard library only, data in JSON.

- Login (PBKDF2 password hashes, session cookies, CSRF protection, lockout after 5 failed logins)
- HTTPS with a self-signed or your own certificate
- Multiple networks (IPv4, /16 or smaller), selectable in the header
- Per address: IP, MAC, name, type, description, last modified
- Ping status dot in front of every IP (refreshed every 60 s)
- Search, sortable columns, "next free address"
- CSV export and import (merge or replace, all-or-nothing validation)
- Atomic writes with `data.json.bak` backup, audit log in `mpn.log`

Requires Python 3.9+ (Rocky Linux 9 ships 3.9), `openssl` for certificate generation and `ping` (iputils) for the status dots.

## Installation on Rocky Linux 9

```bash
sudo dnf install -y python3 openssl iputils

# service user and directory
sudo useradd --system --home-dir /opt/mpn --shell /sbin/nologin mpn
sudo mkdir -p /opt/mpn
sudo cp ../my_private_network/mpn.py /opt/mpn/

# first user (creates config.json) and TLS certificate
sudo python3 /opt/mpn/mpn.py --config /opt/mpn/config.json --set-password admin
sudo python3 /opt/mpn/mpn.py --config /opt/mpn/config.json --gen-cert --san DNS:ipam.home.lan

# optional: adjust port, default network etc.
sudo vi /opt/mpn/config.json

sudo chown -R mpn:mpn /opt/mpn

# service
sudo cp mpn.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mpn

# firewall
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

Then open `https://<server>:8443`. The browser will warn about the self-signed certificate once.

Logs: `journalctl -u mpn -f` or `/opt/mpn/mpn.log`.

## Configuration (`config.json`)

| Key | Default | Meaning |
|---|---|---|
| `listen_address` | `0.0.0.0` | Bind address |
| `port` | `8443` | Listen port (override with `--port`) |
| `data_file` | `data.json` | Data file, relative to the config file |
| `log_file` | `mpn.log` | Audit/log file, empty string to disable |
| `default_network` | Home, `192.168.0.0/24` | Network created on first start only; afterwards manage networks in the UI |
| `tls.enabled` | `true` | HTTPS on/off (`--no-tls` overrides) |
| `tls.cert_file` / `tls.key_file` | `cert.pem` / `key.pem` | Certificate and key (PEM) |
| `session_timeout_minutes` | `60` | Idle time until re-login |
| `ping.enabled` | `true` | Ping status dots |
| `ping.timeout_seconds` | `1` | Timeout per ping |
| `ping.cache_seconds` | `30` | Ping results are cached this long |
| `ping.workers` | `64` | Parallel pings |
| `types` | Router, Switch, … | Suggestions for the Type field (free text is allowed) |
| `users` | | Managed with the CLI, do not edit by hand |

Restart the service after changing the config: `sudo systemctl restart mpn`.

## Command line

```
python3 mpn.py [--config PATH] [--port N] [--listen ADDR] [--no-tls] [-v]
python3 mpn.py --set-password USER      # add user / change password
python3 mpn.py --delete-user USER
python3 mpn.py --list-users
python3 mpn.py --gen-cert [--san DNS:name] [--san IP:addr] [--cert-days 3650]
```

Run CLI commands as the service user or fix ownership afterwards (`chown mpn:mpn /opt/mpn/*`).
`--set-password` also reads the password from stdin when not run in a terminal.

To use your own certificate (e.g. from an internal CA), point `tls.cert_file` and `tls.key_file` to it; the key file must be readable by the `mpn` user.

## CSV format

```
ip,mac,name,type,description,modified
192.168.0.1,3C:A6:2F:11:04:9A,fritzbox,Router,Gateway,2026-09-30 03:29:48
```

- Header row required; `ip` and `name` are mandatory, all other columns optional.
- Comma, semicolon (German Excel) or tab separated, UTF-8 (with or without BOM).
- Merge: new IPs are added, existing IPs are updated. Replace: the network is emptied first.
- If any row is invalid, nothing is imported and all errors are listed.
- Cells starting with `=`, `+`, `-` or `@` are exported with a leading `'` so spreadsheet apps don't run them as formulas; the import strips it again.

## Backup

Everything is in `/opt/mpn/data.json` (plus `config.json`). `data.json.bak` always holds the state before the last change.
