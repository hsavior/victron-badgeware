"""
Victron SmartShunt -> Badgeware Tufty 2350 Bluetooth battery display
======================================================================
Part of: https://github.com/hsavior/victron-badgeware

Reads the SmartShunt's "Instant Readout" Bluetooth LE broadcast directly
(no wiring to the shunt at all), decrypts it, and shows the battery state
of charge on the Tufty 2350's 320x240 full-colour IPS display.

Device credentials (MAC address and AES key) are loaded from config.py.
Copy config.example.py to config.py and fill in your device details before
running this script.

Unlike the Badger 2040 W version, the Tufty's IPS screen redraws every
frame automatically via run(update). The display always shows the latest
BLE data — no manual refresh needed, no e-ink flicker to avoid.

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
Button A: Restart BLE scan. Use this if the shunt drops off — the footer
          shows how many seconds ago data was last received.
Button B: Toggle the Tufty's own internal battery % in the header.

Why AES-CTR via ECB
-------------------
MicroPython's cryptolib only implements AES-ECB, not the AES-CTR mode
Victron's protocol uses. For payloads <= 16 bytes, CTR collapses to a
simpler equivalent: encrypt one counter block (the broadcast's 2-byte
nonce, zero-padded to 16 bytes) with ECB, then XOR against the ciphertext.
That produces the same result as real CTR mode for this payload size.

Note: The Badgeware API globals (screen, color, badge, font, rom_font,
BUTTON_A, etc.) are injected by the Tufty firmware — no explicit import
is needed for them. This script will only run correctly on a Tufty 2350
with Badgeware firmware installed.
"""

import bluetooth
import struct
import time
from micropython import const
import cryptolib

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

    _dev       = DEVICES[0]
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

RECORD_TYPE_BATTERY_MONITOR = const(0x02)
_IRQ_SCAN_RESULT             = const(5)

# -------------------------------------------------------------------------
# BLE state
# -------------------------------------------------------------------------

ble = bluetooth.BLE()

latest_soc             = None
latest_voltage         = None
latest_current         = None
latest_consumed_ah     = None
latest_starter_voltage = None
last_rx_ms             = None    # time.ticks_ms() of the last valid packet
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
    global latest_consumed_ah, latest_starter_voltage, last_rx_ms

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
        name    = _parse_local_name(adv_data) or "(no name)"
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
        last_rx_ms             = time.ticks_ms()

# -------------------------------------------------------------------------
# Badgeware display setup
# -------------------------------------------------------------------------
# screen, color, badge, font, rom_font, image, BUTTON_A, BUTTON_B, run()
# are Badgeware firmware globals — no import required.

# Pixel fonts selected from the font sampler
# absolute = bold/chunky title font   (header + SOC)
# winds    = clean/readable body font (detail rows)
# nope     = 8 px micro font          (footer — always fits)
pf_title = rom_font.absolute
pf_body  = rom_font.winds
pf_foot  = rom_font.nope

PAD = 10

# Measure actual rendered pixel heights at startup so layout is self-calibrating.
# screen.measure_text("X") returns (width, height) for the current font.
screen.font = pf_title
_, H_TITLE = screen.measure_text("X")
screen.font = pf_body
_, H_BODY  = screen.measure_text("X")

COL_NAVY    = color.rgb(10,  15,  40)
COL_GREEN   = color.rgb(50,  210, 80)
COL_ORANGE  = color.rgb(255, 155, 0)
COL_RED     = color.rgb(225, 40,  40)
COL_DIMGREY = color.rgb(90,  90,  110)
COL_LINE    = color.rgb(50,  55,  80)


def _soc_color(soc):
    if soc >= 50:
        return COL_GREEN
    if soc >= 20:
        return COL_ORANGE
    return COL_RED


# Single-line header to leave room for the larger pixel fonts.
# All Y positions derive from H_TITLE / H_BODY so changing those two
# constants is all you need to fix spacing if the fonts are larger/smaller
# than estimated.
_Y_NAME    = 6
_Y_DIVIDER = _Y_NAME    + H_TITLE + 5
_Y_SOC     = _Y_DIVIDER + 1       + 4
_Y_DETAIL1 = _Y_SOC     + H_TITLE + 4
_Y_DETAIL2 = _Y_DETAIL1 + H_BODY  + 2
_Y_DETAIL3 = _Y_DETAIL2 + H_BODY  + 2
_Y_FOOTER  = _Y_DETAIL3 + H_BODY  + 8

BAR_X = int(screen.width * 0.87)
BAR_W = int(screen.width * 0.11)
BAR_Y = _Y_DIVIDER + 2          # starts just below divider, aligns with data area
BAR_H = _Y_FOOTER - BAR_Y - 3   # taller bar → taller segments automatically


def _draw_battery_bar(soc, segments=10):
    """10-segment LED-style bar gauge, right side, filled from bottom.
    Lit segments use the SOC colour; empty segments are hollow outlines."""
    gap   = 3
    seg_h = (BAR_H - gap * (segments - 1)) // segments

    soc_clamped = max(0, min(100, soc))
    lit     = min(segments, int(soc_clamped / (100 / segments) + 0.5))
    lit_col = _soc_color(soc)

    # Terminal nub — centred on the inner fill area (not the full bar border)
    # so it visually aligns with the green segments rather than the outline
    inner_x = BAR_X + 2
    inner_w = BAR_W - 4
    nub_w = inner_w // 2
    nub_h = 5
    screen.pen = color.white
    screen.rectangle(inner_x + (inner_w - nub_w) // 2, BAR_Y - nub_h - 2, nub_w, nub_h)

    for i in range(segments):
        seg_y = BAR_Y + (segments - 1 - i) * (seg_h + gap)
        if i < lit:
            screen.pen = lit_col
            screen.rectangle(BAR_X, seg_y, BAR_W, seg_h)
        else:
            screen.pen = COL_DIMGREY
            screen.rectangle(BAR_X, seg_y, BAR_W, seg_h)
            screen.pen = COL_NAVY
            screen.rectangle(BAR_X + 2, seg_y + 2, BAR_W - 4, seg_h - 4)

# -------------------------------------------------------------------------
# App state
# -------------------------------------------------------------------------

show_tufty_bat = True    # Button B toggles the Tufty's own battery % in header

# Optional background image — place a 320x240 JPEG at assets/back.jpg inside
# the app folder. If absent the navy background is used as before.
# Tries multiple paths so it works whether run from the launcher or Thonny.
_bg = None
for _bg_path in (
    "assets/back.png",                             # RGBA PNG — relative from app dir
    "/system/apps/batteryBoat/assets/back.png",    # absolute path
    "/apps/batteryBoat/assets/back.png",           # fallback
):
    try:
        _bg = image.load(_bg_path)
        print("Background loaded:", _bg_path)
        break
    except Exception as e:
        print("Tried {}: {}".format(_bg_path, e))


def _restart_ble():
    """Stop and restart BLE scanning — use if the shunt drops off."""
    try:
        ble.gap_scan(None)
    except Exception:
        pass
    ble.gap_scan(0, 30000, 30000, True)

# -------------------------------------------------------------------------
# Badgeware update() — called every frame by run()
# -------------------------------------------------------------------------

def update():
    global show_tufty_bat

    if badge.pressed(BUTTON_A):
        _restart_ble()
    if badge.pressed(BUTTON_B):
        show_tufty_bat = not show_tufty_bat

    # Background — navy base always, then alpha PNG composited on top if available
    screen.pen = COL_NAVY
    screen.clear()
    if _bg is not None:
        screen.blit(_bg, rect(0, 0, screen.width, screen.height))

    # ---- Waiting state ------------------------------------------------
    if latest_soc is None:
        # Two-line title as tight as possible — just H_TITLE + 3px between lines
        y_wait = int(screen.height * 0.3)
        screen.font = pf_title
        screen.pen  = color.white
        screen.text("Waiting for", PAD, y_wait)
        screen.text("SmartShunt...", PAD, y_wait + H_TITLE + 3)
        screen.font = pf_foot
        screen.pen  = COL_DIMGREY
        screen.text("A: restart BLE scan", PAD, int(screen.height * 0.85))
        return

    soc_col = _soc_color(latest_soc)

    # ---- Header (single line) -----------------------------------------
    # Device name in winds (body font) — same family as the detail rows
    screen.font = pf_body
    screen.pen  = color.white
    screen.text(SHUNT_NAME, PAD, _Y_NAME)

    # Tufty battery (same font as the detail rows / "Start:")
    if show_tufty_bat:
        bat   = badge.battery_level()
        label = "{}%{}".format(bat, " +" if badge.is_charging() else "")
        screen.font = pf_body
        w, _ = screen.measure_text(label)
        screen.pen = COL_DIMGREY
        screen.text(label, screen.width - w - PAD, _Y_NAME)
        screen.pen = color.white

    # Thin divider
    screen.pen = COL_LINE
    screen.rectangle(PAD, _Y_DIVIDER, BAR_X - PAD * 4, 1)

    # ---- SOC percentage -----------------------------------------------
    screen.font = pf_title
    screen.pen  = soc_col
    screen.text("{:.0f}%".format(latest_soc), PAD, _Y_SOC)

    # ---- Battery bar --------------------------------------------------
    _draw_battery_bar(latest_soc)
    screen.pen = color.white

    # ---- Detail rows --------------------------------------------------
    screen.font = pf_body

    if latest_voltage is not None and latest_current is not None:
        screen.text("{:.2f}V  {:.2f}A".format(latest_voltage, latest_current), PAD, _Y_DETAIL1)
    elif latest_voltage is not None:
        screen.text("{:.2f}V".format(latest_voltage), PAD, _Y_DETAIL1)

    if latest_voltage is not None and latest_current is not None:
        line = "{:.0f}W".format(latest_voltage * latest_current)
        if latest_consumed_ah is not None:
            line += "  {:.1f}Ah".format(latest_consumed_ah)
        screen.text(line, PAD, _Y_DETAIL2)
    elif latest_consumed_ah is not None:
        screen.text("{:.1f}Ah".format(latest_consumed_ah), PAD, _Y_DETAIL2)

    if latest_starter_voltage is not None:
        screen.text("Start: {:.2f}V".format(latest_starter_voltage), PAD, _Y_DETAIL3)

    # ---- Footer -------------------------------------------------------
    screen.font = pf_body

    if last_rx_ms is not None:
        age_s = time.ticks_diff(time.ticks_ms(), last_rx_ms) // 1000
        screen.pen = COL_RED if age_s > 30 else COL_DIMGREY
        screen.text(
            "Last: {}s  A:scan  B:bat {}".format(
                age_s,
                "ON" if show_tufty_bat else "OFF"
            ),
            PAD,
            _Y_FOOTER
        )
    else:
        screen.pen = color.white
        screen.text(
            "Scanning...  A:restart  B:bat {}".format(
                "ON" if show_tufty_bat else "OFF"
            ),
            PAD,
            _Y_FOOTER
        )
# -------------------------------------------------------------------------
# Startup
# -------------------------------------------------------------------------

ble.active(True)
ble.irq(_bt_irq)
ble.gap_scan(0, 30000, 30000, True)

if DISCOVER_MODE:
    print("DISCOVER MODE: listening for BLE advertisers.")
    print("Find your SmartShunt by name, copy its MAC into config.py,")
    print("then set DISCOVER_MODE = False and run again.")
    while True:
        time.sleep(1)

run(update)
