"""Inert mitigation templates and safe spreadsheet export helpers."""
import re


def unicast_mac(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", value):
        return None
    value = value.lower()
    if value == "00:00:00:00:00:00" or int(value[:2], 16) & 1:
        return None
    return value


def csv_cell(value):
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def generate_rules(threats, *, iptables=False, hostapd=False):
    addresses = sorted({mac for row in threats if (mac := unicast_mac(row.get("bssid")))})
    files = []
    if iptables:
        files.append({"name": "iptables-review.txt", "content": "\n".join([
            "# Review before applying. Generated templates; nothing has been executed.",
            "# FORWARD only: routed IP traffic with this visible source MAC.",
            "# This does not block 802.11 management frames or rogue AP beacons.",
            *[f"iptables -A FORWARD -m mac --mac-source {mac} -j DROP" for mac in addresses], ""])})
    if hostapd:
        files.append({"name": "hostapd-deny.txt", "content": "\n".join([
            "# Review before applying. Candidate MAC deny-list for your own hostapd AP.",
            "# Configure macaddr_acl=0 and deny_mac_file=/absolute/path/to/hostapd-deny.txt.",
            "# Denies client associations using these MACs; does not disable rogue APs.",
            *addresses, ""])})
    return {"targets": len(addresses), "files": files, "executed": False}
