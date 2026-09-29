"""Versioned positional contract for the acquired AWID2 public copies."""
import json
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "awid2-public-155-v1.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
SCHEMA_ID = SCHEMA["id"]
COLUMNS = tuple(field["name"] for field in SCHEMA["fields"])
if len(COLUMNS) != 155 or len(set(COLUMNS)) != 155:
    raise RuntimeError("AWID compatibility schema must have 155 unique positions")
if [f["position"] for f in SCHEMA["fields"]] != list(range(1, 156)):
    raise RuntimeError("AWID schema positions are not contiguous")

CLS_LABELS = frozenset({"normal", "flooding", "injection", "impersonation"})
ATK_LABELS = frozenset({
    "normal", "amok", "arp", "authentication_request", "beacon", "cafe_latte",
    "chop_chop", "cts", "deauthentication", "disassociation", "evil_twin",
    "fragmentation", "hirte", "power", "power_saving", "probe_request",
    "probe_response", "rts",
})

# Raw fields remain strings; aliases expose validated nullable integer types.
INTEGER_FIELDS = {
    "frame_type": ("wlan.fc.type", 0, 3, "Int8"),
    "frame_subtype": ("wlan.fc.subtype", 0, 15, "Int8"),
    "sequence_number": ("wlan.seq", 0, 4095, "Int16"),
    "rssi_dbm": ("radiotap.dbm_antsignal", -128, 127, "Int16"),
}
STRING_FIELDS = {
    "source_mac": "wlan.sa",
    "destination_mac": "wlan.da",
    "bssid": "wlan.bssid",
    "ssid": "wlan_mgt.ssid",
    "label": "class",
}
