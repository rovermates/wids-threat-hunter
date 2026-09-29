"""Chunked inference and observable heuristic evidence for a single capture."""
from collections import deque
from contextlib import closing
from datetime import datetime, timezone
import json
import hashlib

import pandas as pd

from backend.core.awid_loader import iter_awid_chunks
from backend.core.ml_engine import InferenceSession
from backend.core.pcap_parser import iter_pcap_chunks
from backend.dashboard.rules import unicast_mac


THRESHOLDS = {"rssi_drift_db": 12, "sequence_gap": 64,
              "beacon_gap_ns": 1_000_000_000, "ssid_mac_count": 3, "frames_per_second": 200}


def scalar(value):
    if value is None or pd.isna(value):
        return None
    return value.item() if hasattr(value, "item") else value


def evidence_tags(features, frame_rate):
    tags = []
    if features.get("rssi_delta_db") is not None and abs(features["rssi_delta_db"]) >= THRESHOLDS["rssi_drift_db"]:
        tags.append("RSSI drift")
    if (features.get("sequence_gap") or 0) >= THRESHOLDS["sequence_gap"]:
        tags.append("Sequence gap")
    if (features.get("beacon_interval_delta_ns") or 0) >= THRESHOLDS["beacon_gap_ns"]:
        tags.append("Sparse beacons")
    if (features.get("ssid_mac_count_60s") or 0) >= THRESHOLDS["ssid_mac_count"]:
        tags.append("SSID / MAC churn")
    if frame_rate >= THRESHOLDS["frames_per_second"]:
        tags.append("Frame burst")
    return tags


def analyze_capture(path, *, filename, variant, analysis_id, settings, store, progress):
    session = InferenceSession(settings.model_path)
    attack_type = session.bundle.get('attack_type', 'suspected_evil_twin')
    chunks = (iter_awid_chunks(path, variant=variant, chunk_size=settings.chunk_size)
              if path.suffix.lower() == ".csv" else iter_pcap_chunks(path, chunk_size=settings.chunk_size))
    recent = deque()
    threats = {}
    total = positive = unattributed = evaluated_count = 0
    first = last = None
    with store.connect() as db, closing(chunks):
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM packets")
        db.execute("DELETE FROM threats")
        for raw in chunks:
            if total + len(raw) > settings.max_packets:
                raise ValueError(f"Capture exceeds the {settings.max_packets:,}-packet limit. Split the capture and retry.")
            predictions, enriched = session.predict_with_features(raw)
            batch = []
            feature_names = ["rssi_delta_db", "rssi_std_db", "sequence_gap", "beacon_interval_delta_ns", "ssid_mac_count_60s"]
            for index, row in enriched.iterrows():
                ns = int(row["timestamp_ns"])
                if first is None:
                    first = ns
                last = ns
                recent.append(ns)
                while recent and recent[0] <= ns - 1_000_000_000:
                    recent.popleft()
                features = {name: scalar(row[name]) for name in feature_names}
                tags = evidence_tags(features, len(recent))
                evaluated = bool(predictions.at[index, "evaluated"]) if "evaluated" in predictions else True
                evaluated_count += int(evaluated)
                prediction = int(predictions.at[index, "rogue_ap_prediction"])
                severity = "high" if prediction and tags else "medium" if prediction else "low"
                bssid = unicast_mac(scalar(row["bssid"]))
                std = features["rssi_std_db"]
                variance = std * std if std is not None else None
                timestamp = pd.Timestamp(ns, unit="ns", tz="UTC").isoformat()
                packet = {"id": int(index), "timestamp": timestamp, "timestamp_ns": str(ns),
                          "source_mac": scalar(row.get("source_mac")), "destination_mac": scalar(row.get("destination_mac")),
                          "bssid": bssid, "ssid": scalar(row["ssid"]), "rssi_dbm": scalar(row["rssi_dbm"]),
                          "frame_type": scalar(row["frame_type"]), "frame_subtype": scalar(row["frame_subtype"]),
                          "ground_truth": scalar(row.get("label")), "prediction": prediction,
                          "attack_type": attack_type if prediction else "no_detection" if evaluated else "not_evaluated",
                          "evaluated": evaluated,
                          "severity": severity, "evasion_tags": tags, "features": features,
                          "positive_vote_fraction": scalar(predictions.at[index, "positive_vote_fraction"])}
                if 'detection_score' in predictions:
                    packet['detection_score'] = scalar(predictions.at[index, 'detection_score'])
                advertising = scalar(row['frame_type']) == 0 and scalar(row['frame_subtype']) in (5, 8)
                # Data frames may name a victim AP; only advertising evidence
                # supports a suspected rogue advertiser in the broader mode.
                attributable = attack_type != 'suspected_rogue_ap' or advertising
                packet['ap_advertising_evidence'] = bool(prediction and bssid and attributable)
                batch.append((packet["id"], ns, bssid, packet["source_mac"], packet["destination_mac"],
                              packet["attack_type"], severity, prediction, variance, json.dumps(packet, allow_nan=False)))
                positive += prediction
                if prediction and (not bssid or not attributable):
                    unattributed += 1
                if prediction and bssid and attributable:
                    threat = threats.setdefault(bssid, {"bssid": bssid, "ssid": packet["ssid"], "packets": 0,
                        "first_seen": timestamp, "last_seen": timestamp, "severity": "medium", "evasion_tags": set()})
                    threat["packets"] += 1
                    threat["last_seen"] = timestamp
                    if packet["ssid"]:
                        threat["ssid"] = packet["ssid"]
                    if severity == "high":
                        threat["severity"] = "high"
                    threat["evasion_tags"].update(tags)
            db.executemany("INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?,?)", batch)
            total += len(raw)
            progress(total)
        if not total:
            raise ValueError("The capture contains no analyzable packets.")
        for threat in threats.values():
            threat["evasion_tags"] = sorted(threat["evasion_tags"])
            threat["attack_type"] = attack_type
            db.execute("INSERT INTO threats VALUES (?,?)", (threat["bssid"], json.dumps(threat)))
        level = "high" if any(t["severity"] == "high" for t in threats.values()) else "elevated" if positive else "low"
        if not evaluated_count:
            level = "unknown"
        capture = {"id": analysis_id, "filename": filename, "format": "AWID " + variant if path.suffix.lower() == ".csv" else "PCAP",
                   "model_artifact_sha256": hashlib.sha256(settings.model_path.read_bytes()).hexdigest(),
                   "scope": session.bundle.get("scope", "all_frames"), "evaluated_packets": evaluated_count,
                   "target": session.bundle.get("target", "evil_twin"), "total_packets": total, "detected_rogue_aps": len(threats), "flagged_packets": positive,
                   "unattributed_positive_packets": unattributed, "threat_level": level,
                   "first_timestamp_ns": str(first), "last_timestamp_ns": str(last),
                   "completed_at": datetime.now(timezone.utc).isoformat(), "heuristic_thresholds": THRESHOLDS}
        db.execute("INSERT OR REPLACE INTO analysis VALUES (1,?)", (json.dumps(capture),))
    return capture
