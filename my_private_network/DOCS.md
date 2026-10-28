# My Private Network

Manage the IP addresses of your home network directly in Home Assistant.

## Features

- List of all assigned addresses with IP, MAC, name, type, description and last change
- Green/red dot in front of each IP showing whether it answers ping
- Several networks (e.g. LAN, IoT VLAN, guest), selectable at the top
- "Next free address" suggestion, search and sortable columns
- Network scan that adds new devices automatically and reports deviations
- CSV export and import (merge or replace)
- Opens in the Home Assistant sidebar; Home Assistant handles the login

## Editing addresses

**Add address** and the pencil icon open an overlay on top of the list. Save, Cancel and Delete are at the bottom; Esc or a click next to the overlay closes it without saving. If something is wrong (for example an IP that is already taken), the message appears in the overlay and your input stays as it is.

## Getting started

1. Start the app and enable **Show in sidebar**.
2. Open **My Private Network** in the sidebar.
3. The first network is created from the options **Default network name** and **Default network range** (default `192.168.0.0/24`).
4. Add addresses with **Add address**, or import an existing list with **Import CSV**.

Additional networks are managed in the app under **Networks**.

## Options

| Option | Meaning |
|---|---|
| Default network name / range | Only used on the very first start, when no data exists yet |
| Device types | Suggestions for the Type field |
| Ping status | Turns the ping dots on or off |
| Ping timeout | Seconds to wait for a ping answer |
| Ping refresh | How often the open page updates the dots |
| Background ping | Minutes between background checks of all recorded addresses (0 = off) |
| Session timeout | Idle minutes until users of the direct port must sign in again |
| Direct access users | Users for the optional direct port |
| HTTPS on the direct port | Uses the certificate from `/ssl` |
| Certificate / key file | File names in `/ssl` (e.g. from the Let's Encrypt app) |
| Log level | Detail of the app log |

## Optional direct access (without Home Assistant)

The sidebar needs no extra setup. If you also want to reach the tool directly, for example from a device without a Home Assistant login:

1. Add at least one user under **Direct access users**.
2. Optionally enable **HTTPS on the direct port** and enter your certificate files from `/ssl`.
3. Under **Network**, enter a host port for `8443/tcp` (for example `8443`).
4. Restart the app and open `http(s)://<home-assistant-ip>:<port>`.

After 5 failed logins from the same address, logins from that address are blocked for 5 minutes.

## CSV format

```
ip,mac,name,type,description,modified
192.168.0.1,3C:A6:2F:11:04:9A,router,Router,Gateway,2026-09-30 12:00:00
```

- A header row is required; `ip` and `name` are mandatory, all other columns are optional.
- Comma, semicolon or tab separated, UTF-8.
- **Merge** adds new IPs and updates existing ones. **Replace** empties the network first.
- If any row is invalid, nothing is imported and every error is listed.

## Network scan

**Scan network** on the list pings every address of the network once (a /24 takes a few seconds). The scan runs in the background; you can leave the page.

- **New devices** that answer are added automatically. The name comes from reverse DNS (e.g. the names your router hands out), otherwise `unknown-<ip>`. The description is set to "Found by network scan".
- **Deviations** are only reported, never changed:
  - *MAC address changed*: another MAC answers at a recorded IP
  - *New address with a known MAC*: a recorded device also answers at a new IP
  - *Recorded but not answering*: the device is off, asleep or blocks ping
- The report of the last scan stays available under **View report** on the list.

**MAC addresses in Home Assistant:** the app runs in Home Assistant's isolated container network, so it cannot see the MAC addresses of your devices. Scanned devices are added without MAC; enter it by hand if you need it. (The standalone version on a Linux host in the same network fills in MAC addresses automatically.)

Networks larger than 4096 addresses (/20) cannot be scanned.

## Data and backup

All data is stored in `/data/data.json` inside the app, with the previous state in `data.json.bak`. Both are included in Home Assistant backups. You can also export each network as CSV.

## Ping status

Move the mouse over an IP address or its dot (or tap it on a phone) to see when the device last answered a ping and when it was last checked. The app also pings all recorded addresses in the background every 5 minutes (option **Background ping**, 0 turns it off), so the time is meaningful even when nobody has the page open. The history is kept in `/data/ping_state.json`.

The app pings from the Home Assistant host. Addresses in other VLANs only show green if Home Assistant can reach them (routing and firewall). Devices that do not answer ping (for example some phones in standby, or Windows machines with the default firewall) show red even when they are online.

## Troubleshooting

- **All dots stay grey:** set **Log level** to `debug` and check the app log.
- **Direct port shows only a login page:** add a user under **Direct access users**.
- **"Invalid or expired form token":** the app was restarted while the page was open. Reload the page.
