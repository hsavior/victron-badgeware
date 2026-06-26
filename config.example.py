# config.example.py
#
# Copy this file to config.py and fill in your device details.
# config.py is git-ignored and should NEVER be committed to the repo —
# it contains your encryption keys.
#
# How to find these values:
#   VictronConnect → your SmartShunt → gear icon → Product Info →
#   "Instant Readout via Bluetooth" → enable → tap Show
#   The MAC address and 32-character AES key are shown on that screen.
#
# MAC format: colon-separated hex pairs, e.g. "ED:0C:49:94:98:FA"
# Key format: 32 lowercase hex characters, no spaces or colons

DEVICES = [
    {
        "name": "Trolling Motor",           # Shown on screen
        "mac":  "AA:BB:CC:DD:EE:FF",        # Replace with your SmartShunt MAC
        "key":  "00000000000000000000000000000000",  # Replace with your 32-char key
    },

    # Uncomment and fill in to add a second device:
    # {
    #     "name": "Start Battery",
    #     "mac":  "AA:BB:CC:DD:EE:FF",
    #     "key":  "00000000000000000000000000000000",
    # },
]
