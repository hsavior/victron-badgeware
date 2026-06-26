# victron-badgeware

Wireless Victron SmartShunt battery monitor for Pimoroni Badgeware devices.
Decrypts BLE Instant Readout broadcasts and shows SOC, voltage, current, and
consumed Ah on a Badger 2040 W (e-ink) and/or Tufty 2350 (colour IPS) display.

**No VE.Direct wiring required.** The SmartShunt's encrypted Bluetooth LE
advertisement is read passively — no pairing, no connection, no cables.

---

## Hardware

- Victron SmartShunt 300A (or any SmartShunt / BMV-7xx with Instant Readout enabled)
- Pimoroni Badger 2040 W and/or Pimoroni Badgeware Tufty 2350

---

## Project structure

```
victron-badgeware/
├── README.md
├── LICENSE
├── .gitignore
├── config.example.py       ← copy to config.py and fill in your device details
├── config.py               ← git-ignored; never commit this file
├── badger2040/
│   └── main.py             ← Badger 2040 W script (e-ink, mono)
└── tufty2350/
    └── main.py             ← Tufty 2350 script (IPS, colour)
```

---

## Setup

### 1. Enable Instant Readout on your SmartShunt

In VictronConnect: open your SmartShunt → gear icon → Product Info →
"Instant Readout via Bluetooth" → turn it on, then tap **Show** next to the
encryption key to reveal the 32-character hex key. Note both the key and the
device's MAC address shown on that screen.

### 2. Create config.py

Copy `config.example.py` to `config.py` and fill in your device details:

```python
DEVICES = [
    {
        "name": "Trolling Motor",
        "mac":  "ED:0C:49:94:98:FA",
        "key":  "your32hexcharacterkeygoeshere00",
    },
]
```

`config.py` is listed in `.gitignore` and will never be committed to the repo.

### 3. Find your MAC address (if you don't know it yet)

Set `DISCOVER_MODE = True` at the top of the script, copy it to the device,
and watch the console output in Thonny. Your SmartShunt will appear by name.
Copy the MAC into `config.py`, set `DISCOVER_MODE = False`, and run again.

### 4. Copy files to your device

**Both devices:** copy `config.py` plus the relevant script to the root of the
device. Double-tap RESET to mount as a USB drive for easy drag-and-drop.

To add the script as a **BadgerOS / Badgeware launcher app**, place it inside
the `/examples/` folder on the device instead of the root. The launcher
discovers apps by scanning that folder automatically.

---

## Buttons

### Badger 2040 W

| Button | Action |
|--------|--------|
| A | Refresh the e-ink screen immediately |
| B | Toggle 2-minute auto-refresh on / off (small square in header = on) |

### Tufty 2350

| Button | Action |
|--------|--------|
| A | Restart BLE scan (use if the shunt drops off and data goes stale) |
| B | Toggle Tufty's own internal battery percentage in the header |

---

## What is shown

| Field | Source |
|-------|--------|
| SOC % | State of charge, 0.1 % resolution |
| Voltage | Battery voltage, 0.01 V resolution |
| Current | Charge/discharge current, 0.001 A resolution |
| Power | Calculated: voltage × current |
| Consumed Ah | Amp-hours drawn since last full charge |
| Start Battery | Aux voltage (only shown when SmartShunt aux mode = starter battery) |

On the **Tufty 2350** the percentage and bar segments change colour based on
charge level: green ≥ 50 %, orange ≥ 20 %, red below 20 %.

---

## How it works

The Victron SmartShunt broadcasts an encrypted BLE advertisement (Instant
Readout) roughly once per second. This is a one-way passive broadcast — no
pairing or active connection is required. The payload is AES-128-CTR encrypted
with a device-specific key available in VictronConnect.

MicroPython's `cryptolib` only provides AES-ECB mode. CTR mode is emulated:
the broadcast's 2-byte nonce is zero-padded to 16 bytes, encrypted with ECB,
then XOR'd against the ciphertext. For payloads ≤ 16 bytes the result is
identical to real AES-CTR.

Credit to [petaramesh](https://gist.github.com/petaramesh) and
[georg90](https://gist.github.com/georg90) for the original MicroPython BLE
decryption approach this project is based on.

---

## Planned

- [ ] Two-device support on Tufty 2350 (side-by-side layout)
- [ ] Support for Victron SmartSolar MPPT Instant Readout (record type 0x01)

---

## License

MIT — see [LICENSE](LICENSE).
