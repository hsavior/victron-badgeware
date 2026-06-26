"""
Victron SmartShunt -> Badger 2040 W Bluetooth battery display
================================================================
Part of: https://github.com/hsavior/victron-badgeware

Reads the SmartShunt's "Instant Readout" Bluetooth LE broadcast directly
(no wiring to the shunt at all), decrypts it, and shows the battery state
of charge on the Badger 2040 W's e-ink screen.

Device credentials (MAC address and AES key) are loaded from config.py.
Copy config.example.py to config.py and fill in your device details before
running this script.

SETUP
-----
1. In VictronConnect: SmartShunt -> gear icon -> Product Info ->
   "Instant Readout via Bluetooth" -> enable -> tap Show for the key.
2. Copy config.example.py to config.py and fill in your MAC and key.
3. If you don't know your MAC yet, set DISCOVER_MODE = True below, run
   the script, and find your SmartShunt in the console output.
4. Set DISCOVER_MODE = False and run. The screen will start showing your
   battery data within a few seconds.

Buttons
-------
Button A: Refresh the e-ink screen immediately with the latest reading.
Button B: Toggle 2-minute auto-refresh on/off. When on, a small filled
          square appears next to the header. When off, the screen only
          updates on Button A presses.

Why AES-CTR via ECB
-------------------
MicroPython's cryptolib only implements AES-ECB, not the AES-CTR mode
Victron's protocol uses. For payloads <= 16 bytes, CTR collapses to a
simpler equivalent: encrypt one counter block (the broadcast's 2-byte
nonce, zero-padded to 16 bytes) with ECB, then XOR against the ciphertext.
That produces the same result as real CTR mode for this payload size.
"""

import bluetooth
import struct
import time
from micropython import const
import cryptolib
import badger2040

# -------------------------------------------------------------------------
# Developer flag — set True to print nearby BLE device names and MACs
# to the console. Useful for finding your SmartShunt's MAC address.
# Set back to False for normal operation.
# -------------------------------------------------------------------------
DISCOVER_MODE = False

# -------------------------------------------------------------------------
# Load device credentials from config.py
# -------------------------------------------------------------------------

if not DISCOVER_MODE:
    try:
        from config import DEVICES
    except ImportError:
        raise ImportError(
            "config.py not found. Copy config.example.py to config.py "
            "and fill in your SmartShunt MAC address and encryption key."
        )

    def _mac_str_to_bytes(mac_str):
        """Convert 'ED:0C:49:94:98:FA' to b'\\xED\\x0C...'"""
        return bytes(int(x, 16) for x in mac_str.split(":"))

    _dev      = DEVICES[0]
    SHUNT_NAME = _dev["name"]
    SHUNT_MAC  = _mac_str_to_bytes(_dev["mac"])
    SHUNT_KEY  = bytes.fromhex(_dev["key"])
else:
    SHUNT_NAME = ""
    SHUNT_MAC  = None
    SHUNT_KEY  = None

# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------

# How often to redraw the e-ink screen automatically (seconds).
# Frequent refreshes cause visible flicker — 2 minutes is more than enough
# for a battery monitor that changes slowly.
AUTO_REFRESH_INTERVAL_S = 120

# How often to poll for button presses (seconds).
BUTTON_POLL_INTERVAL_S = 0.1

# Victron record type for Battery Monitor devices (SmartShunt, BMV)
RECORD_TYPE_BATTERY_MONITOR = 0x02

_IRQ_SCAN_RESULT = const(5)

# -------------------------------------------------------------------------
# BLE state
# -------------------------------------------------------------------------

ble = bluetooth.BLE()

latest_soc             = None
latest_voltage         = None
latest_current         = None
latest_consumed_ah     = None
latest_starter_voltage = None
_seen_macs             = set()

# -------------------------------------------------------------------------
# BLE advertisement parsing
# -------------------------------------------------------------------------

def _parse_local_name(adv_data):
    """Walk BLE AD structures for a Short (0x08) or Complete (0x09) Local
    Name. Only used in DISCOVER_MODE to show human-readable device names."""
    i = 0
    while i + 1 < len(adv_data):
        length = adv_data[i]
        if length == 0:
            break
        ad_type = adv_data[i + 1]
        value   = adv_data[i + 2:i + 1 + length]
        if ad_type in (0x08, 0x09):
            try:
                return value.decode("utf-8")
            except Exception:
                return None
        i += 1 + length
    return None


def _decrypt(adv_data, key):
    """Decrypt a Victron Instant Readout advertisement payload.
    Returns (record_type, cleartext) or None if the key check fails."""
    record_type    = adv_data[11]
    nonce          = adv_data[12:14]
    key_check_byte = adv_data[14]
    ciphertext     = bytearray(adv_data[15:])

    if key[0] != key_check_byte:
        return None

    counter_block = bytearray(nonce)
    counter_block.extend(bytes(14))
    cipher = cryptolib.aes(key, 1)   # mode 1 = ECB
    cipher.encrypt(counter_block, counter_block)

    if len(ciphertext) < 16:
        ciphertext.extend(bytes(16 - len(ciphertext)))

    cleartext = bytes(a ^ b for a, b in zip(ciphertext, counter_block))
    return record_type, cleartext


def _parse_battery_monitor(cleartext):
    """Extract readings from a decrypted Battery Monitor payload.

    Field layout per Victron's Instant Readout spec (bit-packed):
      bytes  2-3   voltage          signed, 0.01 V
      bytes  6-7   aux              starter voltage if aux_mode == 0
      byte   8     aux_mode (low 2 bits) + top bits of current
      bytes  9-10  rest of current  (22-bit signed, milliamps total)
      bytes 11-13  consumed_ah      (20-bit, 0.1 Ah)
      bytes 13-14  soc              (10-bit, 0.1 %)
    """
    voltage_raw = struct.unpack("<h", cleartext[2:4])[0]
    voltage     = voltage_raw / 100 if voltage_raw != 0x7FFF else None

    aux_mode = cleartext[8] & 0x03

    current_bytes = bytearray(cleartext[8:11])
    current_bytes.append(0xFF if current_bytes[2] & 0x80 else 0x00)
    current_raw = struct.unpack("<i", current_bytes)[0] >> 2
    current     = current_raw / 1000 if current_raw != 0x3FFFFF else None

    consumed_bytes = cleartext[11:14] + b"\x00"
    consumed_raw   = struct.unpack("<I", consumed_bytes)[0] & 0xFFFFF
    consumed_ah    = -consumed_raw / 10 if consumed_raw != 0xFFFFF else None

    soc_raw = struct.unpack("<H", cleartext[13:15])[0]
    soc_raw = (soc_raw & 0x3FFF) >> 4
    soc     = soc_raw / 10 if soc_raw != 0x3FF else None

    starter_voltage = None
    if aux_mode == 0:
        starter_raw     = struct.unpack("<h", cleartext[6:8])[0]
        starter_voltage = starter_raw / 100

    return {
        "soc":             soc,
        "voltage":         voltage,
        "current":         current,
        "consumed_ah":     consumed_ah,
        "starter_voltage": starter_voltage,
    }


def _bt_irq(event, data):
    global latest_soc, latest_voltage, latest_current
    global latest_consumed_ah, latest_starter_voltage

    if event != _IRQ_SCAN_RESULT:
        return

    addr_type, addr, adv_type, rssi, adv_data = data
    addr     = bytes(addr)
    adv_data = bytes(adv_data)

    if DISCOVER_MODE:
        if addr in _seen_macs or len(adv_data) < 15:
            return
        _seen_macs.add(addr)
        mac_str = ":".join("{:02X}".format(b) for b in addr)
        name    = _parse_local_name(adv_data) or "(no name broadcast)"
        print("Found:", mac_str, " RSSI:", rssi, " ", name)
        return

    if addr != SHUNT_MAC or adv_type != 0 or len(adv_data) < 16:
        return

    result = _decrypt(adv_data, SHUNT_KEY)
    if result is None:
        return
    record_type, cleartext = result
    if record_type != RECORD_TYPE_BATTERY_MONITOR:
        return

    reading = _parse_battery_monitor(cleartext)
    if reading["soc"] is not None:
        latest_soc             = reading["soc"]
        latest_voltage         = reading["voltage"]
        latest_current         = reading["current"]
        latest_consumed_ah     = reading["consumed_ah"]
        latest_starter_voltage = reading["starter_voltage"]

# -------------------------------------------------------------------------
# Display
# -------------------------------------------------------------------------

badger = badger2040.Badger2040()


def _draw_waiting():
    badger.set_pen(15)
    badger.clear()
    badger.set_pen(0)
    badger.set_font("bitmap8")
    badger.text("Waiting for", 10, 50, scale=2)
    badger.text("SmartShunt...", 10, 75, scale=2)
    badger.update()


def _draw_battery_bar(x, y, w, h, soc, segments=10):
    """Vertical 10-segment LED-style bar gauge, filled from the bottom up.
    Lit segments are solid black; unlit ones are hollow outlines."""
    gap   = 2
    seg_h = (h - gap * (segments - 1)) // segments

    soc_clamped = max(0, min(100, soc))
    lit = min(segments, int(soc_clamped / (100 / segments) + 0.5))

    # Small terminal nub above the top segment
    nub_w = w // 2
    nub_h = 5
    badger.set_pen(0)
    badger.rectangle(x + (w - nub_w) // 2, y - nub_h - 2, nub_w, nub_h)

    for i in range(segments):
        seg_y = y + (segments - 1 - i) * (seg_h + gap)
        badger.set_pen(0)
        badger.rectangle(x, seg_y, w, seg_h)
        if i >= lit:
            badger.set_pen(15)
            badger.rectangle(x + 2, seg_y + 2, w - 4, seg_h - 4)


def _draw_battery(soc, voltage, current, consumed_ah, starter_voltage,
                  auto_refresh_enabled=True):
    badger.set_pen(15)
    badger.clear()
    badger.set_pen(0)

    # Header — device name from config
    badger.set_font("bitmap8")
    badger.text("{} Battery Status".format(SHUNT_NAME), 8, 2, scale=1)

    # Small square indicator: auto-refresh is on when filled
    if auto_refresh_enabled:
        badger.set_pen(0)
        badger.rectangle(224, 3, 6, 6)

    # Big SOC percentage
    badger.set_pen(0)
    badger.text("{:.0f}%".format(soc), 8, 14, scale=4)

    # 10-segment battery bar, far right
    _draw_battery_bar(252, 12, 30, 110, soc)

    # Reset pen after bar (last hollow segment leaves it white)
    badger.set_pen(0)

    # Detail rows
    badger.set_font("bitmap8")
    y = 72
    if voltage is not None and current is not None:
        badger.text("{:.2f}V   {:.2f}A".format(voltage, current), 8, y, scale=2)
    elif voltage is not None:
        badger.text("{:.2f}V".format(voltage), 8, y, scale=2)
    y += 18

    if voltage is not None and current is not None:
        line = "{:.0f}W".format(voltage * current)
        if consumed_ah is not None:
            line += "   {:.1f}Ah".format(consumed_ah)
        badger.text(line, 8, y, scale=2)
    elif consumed_ah is not None:
        badger.text("{:.1f}Ah".format(consumed_ah), 8, y, scale=2)
    y += 18

    if starter_voltage is not None:
        badger.text("Start Battery: {:.2f}V".format(starter_voltage), 8, y, scale=2)

    badger.update()

# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------

def main():
    ble.active(True)
    ble.irq(_bt_irq)
    # duration_ms=0 = scan forever; interval_us == window_us = no gaps
    ble.gap_scan(0, 30000, 30000, True)

    if DISCOVER_MODE:
        print("DISCOVER MODE: listening for nearby BLE advertisers.")
        print("Find your SmartShunt by name, copy its MAC into config.py,")
        print("then set DISCOVER_MODE = False and run again.")
        while True:
            time.sleep(1)

    auto_refresh_enabled = True
    last_drawn_time      = time.time()
    had_data             = False
    prev_a               = False
    prev_b               = False

    def redraw():
        nonlocal last_drawn_time
        if latest_soc is not None:
            _draw_battery(
                latest_soc, latest_voltage, latest_current,
                latest_consumed_ah, latest_starter_voltage,
                auto_refresh_enabled,
            )
        else:
            _draw_waiting()
        last_drawn_time = time.time()

    redraw()

    while True:
        time.sleep(BUTTON_POLL_INTERVAL_S)

        # Show first reading immediately without waiting for scheduled refresh
        if not had_data and latest_soc is not None:
            had_data = True
            redraw()

        a_pressed = badger.pressed(badger2040.BUTTON_A)
        b_pressed = badger.pressed(badger2040.BUTTON_B)

        if a_pressed and not prev_a:
            redraw()

        if b_pressed and not prev_b:
            auto_refresh_enabled = not auto_refresh_enabled
            redraw()

        prev_a = a_pressed
        prev_b = b_pressed

        if auto_refresh_enabled:
            if (time.time() - last_drawn_time) >= AUTO_REFRESH_INTERVAL_S:
                redraw()


main()
