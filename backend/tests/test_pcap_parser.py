import json
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

import pandas as pd

from backend.core.pcap_parser import PcapError, PcapReport, inspect_pcap, iter_pcap_chunks, resolve_tshark
from backend.core.native_stream import NativeLineStream
from backend.tests.pcap_fixtures import beacon, write_pcap


class PcapInputTests(unittest.TestCase):
    def test_missing_frame_type_is_preserved_as_malformed(self):
        from backend.core.pcap_parser import _frame, FIELDS
        values = {name: '' for name in FIELDS}
        values.update({'frame.number': '1', 'frame.time_epoch': '1.0',
                       'frame.cap_len': '1', 'frame.len': '1'})
        frame = _frame([[values[name] for name in FIELDS]], Path('truncated-header.pcap'))
        self.assertTrue(pd.isna(frame.iloc[0].frame_type))
        self.assertTrue(frame.iloc[0].malformed)

    def test_missing_executable_has_actionable_error(self):
        with self.assertRaisesRegex(PcapError, "unavailable"):
            resolve_tshark("nonexistent-tshark-for-test")

    def test_invalid_input_rejected_before_decoder_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.pcap"
            path.write_bytes(b"not a pcap")
            with self.assertRaisesRegex(PcapError, "signature"):
                inspect_pcap(path)
            with self.assertRaisesRegex(PcapError, "does not exist"):
                inspect_pcap(path.with_name("missing.pcap"))
            for size in (0, -1, True):
                with self.assertRaisesRegex(ValueError, "chunk_size"):
                    inspect_pcap(path, chunk_size=size)


class NativePcapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.tshark = resolve_tshark()
        except PcapError as exc:
            raise unittest.SkipTest(str(exc))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "saved ; $ capture.pcap"

    def test_exact_fields_and_nanosecond_timestamp(self):
        write_pcap(self.path, [(1700000000, 123456789, beacon(sequence=4095))], nanoseconds=True)
        report = PcapReport()
        chunks = list(iter_pcap_chunks(self.path, report=report))
        row = chunks[0].iloc[0]
        self.assertEqual(row["timestamp_ns"], 1700000000123456789)
        self.assertEqual(row["timestamp_utc"].value, 1700000000123456789)
        self.assertEqual(row["sequence_number"], 4095)
        self.assertEqual(row["rssi_dbm"], -47)
        self.assertEqual(row["frame_subtype"], 8)
        self.assertEqual(row["bssid"], "02:00:00:00:00:01")
        self.assertEqual(row["ssid"], "test-wifi")
        self.assertTrue(pd.isna(row["label"]))
        self.assertTrue(report.complete)

    def test_missing_rssi_and_empty_hidden_ssid(self):
        write_pcap(self.path, [(1, 0, beacon(ssid=b"", rssi=None))])
        chunks = list(iter_pcap_chunks(self.path))
        self.assertTrue(pd.isna(chunks[0].iloc[0]["rssi_dbm"]))
        self.assertEqual(chunks[0].iloc[0]["ssid"], "")

    def test_ssid_special_bytes_preserved_without_output_injection(self):
        ssid = b'a,"\t\n\\\xff'
        write_pcap(self.path, [(1, 0, beacon(ssid=ssid))])
        chunk = list(iter_pcap_chunks(self.path))[0]
        self.assertEqual(chunk.iloc[0]["wlan.ssid"], ssid.hex())
        self.assertEqual(chunk.iloc[0]["ssid"], ssid.decode("utf-8", errors="backslashreplace"))

    def test_no_radiotap_raw_80211_supported(self):
        write_pcap(self.path, [(1, 0, beacon()[9:])], linktype=105)
        report = inspect_pcap(self.path)
        self.assertEqual(report.wifi_packets, 1)
        self.assertEqual(report.missing_core["rssi_dbm"], 1)

    def test_chunk_bounds_and_backwards_time_report_without_sorting(self):
        write_pcap(self.path, [(2, 0, beacon()), (1, 0, beacon()), (3, 0, beacon())])
        report = PcapReport()
        chunks = list(iter_pcap_chunks(self.path, chunk_size=1, report=report))
        self.assertEqual([int(c.iloc[0]["timestamp_ns"]) for c in chunks], [2000000000, 1000000000, 3000000000])
        self.assertEqual(report.timestamp_decreases, 1)
        self.assertEqual(report.max_chunk_rows, 1)

    def test_nonwifi_and_empty_capture_rejected(self):
        for packets, linktype in (([], 127), ([(1, 0, b"\x00" * 60)], 1)):
            write_pcap(self.path, packets, linktype=linktype)
            with self.assertRaisesRegex(PcapError, "no decodable"):
                inspect_pcap(self.path)

    def test_truncated_file_is_not_success_after_partial_output(self):
        write_pcap(self.path, count=2)
        content = self.path.read_bytes()
        self.path.write_bytes(content[:-4])
        report = PcapReport()
        with self.assertRaises(PcapError):
            list(iter_pcap_chunks(self.path, chunk_size=1, report=report))
        self.assertFalse(report.complete)

    def test_generator_close_reaps_native_process(self):
        write_pcap(self.path, count=3000)
        instances = []
        def make_stream(*args, **kwargs):
            stream = NativeLineStream(*args, **kwargs)
            instances.append(stream)
            return stream
        report = PcapReport()
        with patch("backend.core.pcap_parser.NativeLineStream", side_effect=make_stream):
            stream = iter_pcap_chunks(self.path, chunk_size=1, report=report)
            next(stream)
            stream.close()
        self.assertIsNotNone(instances[0].process.poll())
        self.assertFalse(report.complete)

    def test_cli_json_success(self):
        write_pcap(self.path)
        result = subprocess.run([sys.executable, "-m", "backend.ingest_pcap", str(self.path)],
                                cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["wifi_packets"], 3)
        self.assertTrue(report["complete"])

    def test_pcapng_saved_capture(self):
        write_pcap(self.path)
        output = self.path.with_suffix(".pcapng")
        # Native file conversion, never live capture.
        subprocess.run([self.tshark, "-n", "-r", str(self.path), "-F", "pcapng", "-w", str(output)],
                       check=True, capture_output=True, timeout=15)
        self.assertEqual(inspect_pcap(output).wifi_packets, 3)

    def test_snaplen_truncation_is_reported(self):
        write_pcap(self.path, count=1)
        data = bytearray(self.path.read_bytes())
        original_length = struct.unpack_from("<I", data, 36)[0]
        struct.pack_into("<I", data, 36, original_length + 100)
        self.path.write_bytes(data)
        self.assertEqual(inspect_pcap(self.path).truncated_packets, 1)


if __name__ == "__main__":
    unittest.main()
