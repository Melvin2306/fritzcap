# fritzcap

Long, unattended packet captures from a **FRITZ!Box**, driven from the command line.

FRITZ!OS has a hidden, genuinely useful feature: a built-in packet sniffer
("Paketmitschnitt", at `http://fritz.box/html/capture.html`) that streams a `.pcap`
of any interface straight to your browser — no extra hardware, no SPAN port, and on
a Wi-Fi AP interface the frames come out already decrypted.

It has one problem: **it is tied to your web session.** Leave it running and the
FRITZ!Box eventually logs the session out, which stops the capture and loses it.
That makes the built-in tool useless for the captures you most often want — an
overnight run, a multi-hour soak test, "catch the thing that only happens
occasionally."

`fritzcap` talks to the same capture endpoint directly, from Python, so there is no
web session to expire:

- it logs in with AVM's PBKDF2 challenge-response and starts the capture itself;
- it streams the pcap **straight to disk**;
- if the stream ever drops, it **logs back in and starts a fresh numbered segment**,
  so a long capture survives disconnects;
- every segment is a complete, openable pcap — merge them afterwards with `mergecap`.

It can capture **one interface** or **all of them in parallel**.

## Why

I wrote this while investigating a cheap Android device on an isolated guest Wi-Fi:
I wanted to record everything it did over many hours, and the browser-based capture
kept timing out and dying. Driving the same built-in endpoint from a script fixed
it — the capture now runs as long as you want and picks itself back up if the
connection blips.

## Requirements

- Python 3 (standard library only — nothing to `pip install`)
- A FRITZ!Box with the built-in packet-capture feature (it has been in FRITZ!OS for
  years). `mergecap` / `tshark` (from Wireshark) are optional, for the result.

## Usage

```bash
# 1) list the capture interfaces your box exposes, then exit
python3 -I fritzcap.py --host fritz.box --list

# 2) capture one interface until you press Ctrl-C
#    (the password is read from the env var, or prompted — never stored)
FRITZBOX_PASSWORD='your-password' python3 -I fritzcap.py --iface guest5

# 3) capture every interface in parallel for 8 hours
FRITZBOX_PASSWORD='your-password' python3 -I fritzcap.py --all --hours 8

# 4) merge one interface's segments into a single pcap
mergecap -F pcap -w capture.pcap out/capture-*/guest5/seg*.pcap
```

Interface names come from your own box (`--list` shows them). Common ones are the
LAN bridge, the 2.4/5 GHz APs, the guest AP, and the internet uplink — but the exact
set and names depend on your model and firmware, so always start with `--list`.

### Options

| flag | meaning |
|------|---------|
| `--host` | router address (default `fritz.box`) |
| `--iface NAME` | capture this interface (from `--list`) |
| `--all` | capture every available interface in parallel, each to its own folder |
| `--list` | print the capture interfaces and exit |
| `--hours` / `--minutes` | how long to run (default: 10 h, or until Ctrl-C) |
| `--user` | FRITZ!Box username, if your box requires one (auto-detected otherwise) |
| `--out` | output directory (default `./out`) |

Output layout: `out/capture-<timestamp>/<iface>/seg001.pcap`, `seg002.pcap`, …

## Security & privacy

- The password is taken from `FRITZBOX_PASSWORD` or an interactive prompt and is
  **never written to disk**.
- The tool talks **only to your router** over your LAN. It sends nothing anywhere
  else and has no telemetry.
- A capture contains real network traffic. Treat the pcap files as sensitive and do
  not share them without sanitizing first.

## Compatibility

Tested against current FRITZ!OS, which serves the capture UI from `data.lua`; the
tool also falls back to the older `html/capture.html`. If `--list` finds no
interfaces, the raw capture page is saved to `out/session-*/capture_page.raw` so you
can see what your firmware returns and open an issue.

## License

MIT — see [LICENSE](LICENSE).
