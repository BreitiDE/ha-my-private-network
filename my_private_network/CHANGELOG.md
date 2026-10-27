# Changelog

## 1.3.0

- New color design, shared with Stream Recorder: accent #ce6c00, warm neutral grays, light and dark mode
- New logo, favicon and app icon (orange square with network symbol)
- "Networks" in the header is highlighted while you are on the network pages
- Tables, tiles, buttons, badges and messages restyled; no functional changes

## 1.2.0

- Network scan: pings every address of a network once in the background
- New devices that answer are added automatically (name from reverse DNS, otherwise `unknown-<ip>`)
- Empty MAC addresses of existing entries are filled in from the ARP table
- Scan report shows deviations: changed MAC, known MAC at a new IP, recorded devices not answering
- Last scan summary on the network page, report kept across restarts
- Scans limited to networks of up to 4096 addresses (/20)

## 1.1.0

- Available as a Home Assistant app with ingress (sidebar)
- All settings configurable in the app configuration
- Optional direct port with its own users and HTTPS from `/ssl`
- Opens the last used network after login
- Ping refresh interval configurable

## 1.0.0

- First release as standalone Python tool
- Login, HTTPS, multiple networks, ping status, type field, CSV import/export
