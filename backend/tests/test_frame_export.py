import json
from pathlib import Path
import struct
import tempfile
import unittest

from backend.core.frame_export import export_pcap_frames
from backend.core.pcap_parser import PcapError, iter_pcap_chunks, resolve_tshark
from backend.tests.pcap_fixtures import beacon, write_pcap


class FrameExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            resolve_tshark()
        except PcapError as exc:
            raise unittest.SkipTest(str(exc))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "input.pcap"
        self.output = Path(self.temp.name) / "frames.jsonl"

    def test_beacon_attributes_and_exact_unsigned_tsf(self):
        packet = bytearray(beacon())
        struct.pack_into("<Q", packet, 9 + 24, 2**64 - 1)
        packet.extend(b"\x03\x01\x06")  # DS channel 6
        write_pcap(self.source, [(1700000000, 123456789, packet)], nanoseconds=True)
        report = export_pcap_frames(self.source, self.output, chunk_size=1)
        row = json.loads(self.output.read_text())
        self.assertTrue(report.complete)
        self.assertEqual(row["timestamp_ns"], 1700000000123456789)
        self.assertEqual(row["advertised_tsf_us"], 2**64 - 1)
        self.assertEqual(row["beacon_interval_us"], 102400)
        self.assertEqual(row["advertised_channel"], 6)
        self.assertTrue(row["is_beacon"])
        self.assertTrue(row["ess_capable"])
        self.assertFalse(row["privacy_capable"])
        self.assertFalse(row["retry"])
        self.assertEqual(row["transmitter_mac"], row["source_mac"])
        self.assertIsNone(row["qos_tid"])
        self.assertIsNone(row["label"])

    def test_null_empty_special_ssid_and_chunks_roundtrip(self):
        packets = [(1, i, beacon(ssid=value, rssi=None))
                   for i, value in enumerate([b"", b"NA", b'a,"\t\n\\\xff'])]
        write_pcap(self.source, packets)
        export_pcap_frames(self.source, self.output, chunk_size=1)
        rows = [json.loads(line) for line in self.output.read_text().splitlines()]
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["ssid"], "")
        self.assertEqual(rows[1]["ssid"], "NA")
        self.assertEqual(rows[2]["wlan.ssid"], b'a,"\t\n\\\xff'.hex())
        self.assertIsNone(rows[0]["rssi_dbm"])

    def test_failure_does_not_publish_partial_rows(self):
        write_pcap(self.source, count=3)
        self.source.write_bytes(self.source.read_bytes()[:-4])
        with self.assertRaises(PcapError):
            export_pcap_frames(self.source, self.output, chunk_size=1)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.output.parent.glob("*.partial")), [])

    def test_existing_output_and_source_are_preserved(self):
        write_pcap(self.source)
        original = self.source.read_bytes()
        with self.assertRaises(FileExistsError):
            export_pcap_frames(self.source, self.source)
        self.assertEqual(self.source.read_bytes(), original)
        self.output.write_text("existing")
        with self.assertRaises(FileExistsError):
            export_pcap_frames(self.source, self.output)
        self.assertEqual(self.output.read_text(), "existing")

    def test_control_frame_missing_management_fields(self):
        radio = struct.pack("<BBHI", 0, 0, 8, 0)
        ack = struct.pack("<HH", 0x00D4, 0) + bytes.fromhex("020000000001")
        write_pcap(self.source, [(1, 0, radio + ack)])
        export_pcap_frames(self.source, self.output)
        row = json.loads(self.output.read_text())
        self.assertEqual(row["frame_type"], 1)
        self.assertEqual(row["frame_subtype"], 13)
        self.assertIsNone(row["ssid"])
        self.assertIsNone(row["sequence_number"])
        self.assertIsNone(row["beacon_interval_tu"])
        self.assertIsNone(row["privacy_capable"])
        self.assertFalse(row["is_beacon"])
