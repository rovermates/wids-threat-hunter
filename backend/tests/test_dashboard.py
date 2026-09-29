import csv
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import DashboardSettings, DATA_DIR, PROJECT_ROOT
from backend.core.pcap_parser import resolve_tshark, PcapError
from backend.dashboard.analysis import evidence_tags
from backend.dashboard.model_info import load_model_info
from backend.dashboard.rules import csv_cell, generate_rules, unicast_mac
from backend.tests.pcap_fixtures import write_pcap


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.settings = DashboardSettings(state_dir=Path(self.folder.name), chunk_size=25,
            model_path=PROJECT_ROOT / "backend/models/deployment/trained_ensemble.joblib")
        self.app = create_app(self.settings)
        self.client = TestClient(self.app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.folder.cleanup()

    def wait(self, response):
        self.assertEqual(response.status_code, 202, response.text)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            result = self.client.get(response.json()["status_url"]).json()
            if result["status"] in {"completed", "failed"}:
                return result
            time.sleep(.05)
        self.fail("Job did not finish")

    def sample(self):
        result = self.wait(self.client.post("/api/sample"))
        self.assertEqual(result["status"], "completed", result)
        return result["id"]

    def test_sample_metrics_pagination_filters_and_traffic(self):
        self.assertIsNone(self.client.get("/api/metrics").json()["capture"])
        analysis_id = self.sample()
        metrics = self.client.get("/api/metrics").json()
        self.assertEqual(metrics["capture"]["total_packets"], 100)
        self.assertEqual(metrics["capture"]["id"], analysis_id)
        benchmark = metrics["model"]["benchmark"]
        self.assertEqual(benchmark["confusion_matrix"], [[574239, 793], [51, 560]])
        self.assertAlmostEqual(benchmark["f1"], .570264765784114)
        self.assertAlmostEqual(sum(item["importance"] for item in metrics["model"]["feature_importance"]), 1)
        rows = self.client.get("/api/packets?page=2&page_size=7").json()
        self.assertEqual([row["id"] for row in rows["items"]], list(range(8, 15)))
        mac = next(row["bssid"] for row in self.client.get("/api/packets?page_size=100").json()["items"] if row["bssid"])
        selected = self.client.get("/api/packets", params={"mac": mac.upper(), "page_size": 100}).json()
        self.assertGreater(selected["total"], 0)
        self.assertTrue(all(mac in [row["bssid"], row["source_mac"], row["destination_mac"]] for row in selected["items"]))
        self.assertEqual(self.client.get("/api/packets?mac=%25").json()["total"], 0)
        traffic = self.client.get("/api/traffic").json()
        self.assertTrue(1 <= len(traffic["items"]) <= 120)
        self.assertTrue(any(item["rssi_variance"] is not None for item in traffic["items"]))
        self.assertEqual(self.client.get("/api/threats").json()["analysis_id"], analysis_id)

    def test_version_two_model_scores_and_benchmark_provenance(self):
        self._check_scored_model('detection_multisource_v2')

    def test_version_three_behavior_model_scores_and_provenance(self):
        self._check_scored_model('precision_v3')

    def _check_scored_model(self, folder):
        model = PROJECT_ROOT / 'backend/models' / folder / 'trained_ensemble.joblib'
        with tempfile.TemporaryDirectory() as directory:
            settings = replace(self.settings, model_path=model, state_dir=Path(directory))
            with TestClient(create_app(settings)) as client:
                response = client.post('/api/sample')
                self.assertEqual(response.status_code, 202)
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline:
                    job = client.get(response.json()['status_url']).json()
                    if job['status'] in {'completed', 'failed'}:
                        break
                    time.sleep(.05)
                self.assertEqual(job['status'], 'completed', job)
                model_info = client.get('/api/metrics').json()['model']
                self.assertIn('consumed-test', model_info['benchmark']['source'])
                self.assertIn('blocked holdout', model_info['additional_benchmark']['source'])
                self.assertTrue(model_info['feature_importance'])
                self.assertAlmostEqual(sum(v['importance'] for v in model_info['feature_importance']),1.)
                packets = client.get('/api/packets').json()['items']
                self.assertTrue(all(p['positive_vote_fraction'] is None for p in packets))
                self.assertTrue(all(0 <= p['detection_score'] <= 1 for p in packets))

    def test_real_multipart_upload_and_exports(self):
        result = self.wait(self.client.post("/api/upload", files={"file": ("sample.csv", (DATA_DIR / "sample_awid.csv").read_bytes())}, data={"variant": "CLS"}))
        self.assertEqual(result["status"], "completed", result)
        params = {"analysis_id": result["id"], "format": "json"}
        export = self.client.get("/api/export", params=params)
        self.assertEqual(export.status_code, 200)
        self.assertEqual(len(export.json()["packets"]), 100)
        params["format"] = "csv"
        params["mac"] = "does-not-match"
        export = self.client.get("/api/export", params=params)
        self.assertEqual(len(list(csv.reader(io.StringIO(export.text)))), 1)
        self.assertFalse(list(Path(self.folder.name).glob("export-*")))
        self.assertFalse(list(self.app.state.service.upload_dir.iterdir()))

    def test_late_parse_failure_preserves_previous_capture(self):
        previous = self.sample()
        contents = (DATA_DIR / "sample_awid.csv").read_bytes() + b"malformed,row\n"
        result = self.wait(self.client.post("/api/upload", files={"file": ("bad.csv", contents)}))
        self.assertEqual(result["status"], "failed")
        self.assertGreater(result["processed_packets"], 0)
        self.assertEqual(self.client.get("/api/metrics").json()["capture"]["id"], previous)
        self.assertEqual(self.client.get("/api/packets").json()["total"], 100)

    def test_stale_analysis_is_rejected_for_reads_and_exports(self):
        previous = self.sample()
        self.sample()
        for route in ["packets", "traffic", "threats", "rules", "export"]:
            self.assertEqual(self.client.get("/api/" + route, params={"analysis_id": previous}).status_code, 409)

    def test_invalid_uploads_and_query_parameters(self):
        self.assertEqual(self.client.post("/api/upload", files={"file": ("bad.exe", b"test")}).status_code, 415)
        self.assertEqual(self.client.post("/api/upload", files={"file": ("empty.csv", b"")}).status_code, 422)
        self.assertEqual(self.client.post("/api/upload", files={"file": ("AWID-ATK-R-Trn.csv", b"x")}, data={"variant": "CLS"}).status_code, 422)
        for query in ["page=0", "page_size=101", "severity=critical", "attack_type=bogus"]:
            self.assertEqual(self.client.get("/api/packets?" + query).status_code, 422)
        self.assertEqual(self.client.get("/api/jobs/unknown").status_code, 404)

    def test_busy_upload_does_not_queue_another_job(self):
        job = self.app.state.service.reserve("busy.csv")
        self.assertEqual(self.client.post("/api/sample").status_code, 409)
        self.app.state.service.fail(job["id"], "test finished")
        self.sample()

    def test_packet_limit_rolls_back(self):
        previous = self.sample()
        self.app.state.service.settings = replace(self.settings, max_packets=50)
        result = self.wait(self.client.post("/api/sample"))
        self.assertEqual(result["status"], "failed")
        self.assertIn("50-packet limit", result["error"])
        self.assertEqual(self.client.get("/api/metrics").json()["capture"]["id"], previous)

    def test_oversize_multipart(self):
        with TestClient(create_app(replace(self.settings, max_upload_bytes=128))) as client:
            self.assertEqual(client.post("/api/upload", files={"file": ("big.csv", b"x" * 256)}).status_code, 413)
            self.assertEqual(client.post("/api/upload", files={"file": ("big.csv", b"x" * 70000)}).status_code, 413)
            body = b'--test\r\nContent-Disposition: form-data; name="file"; filename="big.csv"\r\n\r\n' + b'x' * 70000 + b'\r\n--test--\r\n'
            response = client.post("/api/upload", content=iter([body[:100], body[100:]]),
                                   headers={"Content-Type": "multipart/form-data; boundary=test"})
            self.assertEqual(response.status_code, 413)

    def test_csv_export_escapes_uploaded_ssid_but_json_preserves_it(self):
        from backend.core.awid_schema import COLUMNS
        rows = list(csv.reader(io.StringIO((DATA_DIR / "sample_awid.csv").read_text())))
        rows[0][COLUMNS.index("wlan_mgt.ssid")] = '=HYPERLINK("example")'
        buffer = io.StringIO(newline="")
        csv.writer(buffer).writerows(rows)
        result = self.wait(self.client.post("/api/upload", files={"file": ("formula.csv", buffer.getvalue().encode())}))
        self.assertEqual(result["status"], "completed", result)
        params = {"analysis_id": result["id"], "format": "csv"}
        exported = list(csv.DictReader(io.StringIO(self.client.get("/api/export", params=params).text)))
        self.assertTrue(exported[0]["ssid"].startswith("'="))
        params["format"] = "json"
        self.assertEqual(self.client.get("/api/export", params=params).json()["packets"][0]["ssid"], '=HYPERLINK("example")')

    def test_missing_model_does_not_fabricate_results(self):
        with TestClient(create_app(replace(self.settings, model_path=Path(self.folder.name) / "missing.joblib"))) as client:
            self.assertFalse(client.get("/api/health").json()["model_ready"])
            self.assertIsNone(client.get("/api/metrics").json()["model"]["benchmark"])
            self.assertEqual(client.post("/api/sample").status_code, 503)

    def test_capture_persists_across_app_restart(self):
        analysis_id = self.sample()
        with TestClient(create_app(self.settings)) as client:
            self.assertEqual(client.get("/api/metrics").json()["capture"]["id"], analysis_id)
            self.assertEqual(client.get("/api/packets").json()["total"], 100)

    def test_model_change_marks_saved_capture_for_reanalysis(self):
        self.sample()
        self.assertFalse(self.client.get('/api/metrics').json()['needs_reanalysis'])
        updated = replace(self.settings, model_path=PROJECT_ROOT / 'backend/models/final_v7/trained_ensemble.joblib')
        with TestClient(create_app(updated)) as client:
            self.assertTrue(client.get('/api/metrics').json()['needs_reanalysis'])
            self.assertEqual(client.get('/api/metrics').json()['model']['scope'], 'ap_advertisements')
            self.assertEqual(client.get('/api/packets?attack_type=not_evaluated').status_code, 200)
            self.assertEqual(client.get('/api/packets?attack_type=suspected_rogue_ap').status_code, 200)

    def test_native_pcap_upload(self):
        try:
            resolve_tshark()
        except PcapError:
            self.skipTest("tshark not installed")
        fixture = write_pcap(Path(self.folder.name) / "fixture.pcap", count=6)
        result = self.wait(self.client.post("/api/upload", files={"file": ("fixture.pcap", fixture.read_bytes())}))
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual(result["processed_packets"], 6)
        rows = self.client.get("/api/packets").json()["items"]
        self.assertTrue(all(row["ground_truth"] is None for row in rows))

    def test_threat_evidence_and_rules_from_model_positives(self):
        from backend.core.ml_engine import InferenceSession
        predict = InferenceSession.predict_with_features

        def force_positive(session, raw):
            predictions, features = predict(session, raw)
            predictions["rogue_ap_prediction"] = 1
            return predictions, features

        with patch.object(InferenceSession, "predict_with_features", force_positive):
            analysis_id = self.sample()
        feed = self.client.get("/api/threats").json()
        self.assertGreater(feed["total"], 0)
        limited = self.client.get("/api/threats?limit=1").json()
        self.assertEqual(len(limited["items"]), 1)
        self.assertEqual(limited["total"], feed["total"])
        capture = self.client.get("/api/metrics").json()["capture"]
        self.assertEqual(capture["detected_rogue_aps"], feed["total"])
        generated = self.client.get("/api/rules", params={"analysis_id": analysis_id, "iptables": True, "hostapd": True}).json()
        self.assertEqual(len(generated["files"]), 2)
        self.assertFalse(generated["executed"])
        self.assertIn("iptables -A FORWARD", generated["files"][0]["content"])


class EvidenceTests(unittest.TestCase):
    def test_heuristics_and_rule_target_validation(self):
        tags = evidence_tags({"rssi_delta_db": -13, "sequence_gap": 65, "beacon_interval_delta_ns": 1_000_000_000,
                              "ssid_mac_count_60s": 3}, 200)
        self.assertEqual(len(tags), 5)
        self.assertEqual(evidence_tags({}, 1), [])
        for address in [None, "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01", "00:00:00:00:00:00", "bad;command"]:
            self.assertIsNone(unicast_mac(address))
        rules = generate_rules([{"bssid": "02:11:22:33:44:55"}, {"bssid": "invalid"}], hostapd=True)
        self.assertEqual(rules["targets"], 1)
        self.assertNotIn("invalid", rules["files"][0]["content"])

    def test_csv_formula_escaping(self):
        for text in ["=HYPERLINK(x)", " +cmd", "-cmd", "@cmd", "\ttext", "\rtext", "\ntext"]:
            self.assertTrue(csv_cell(text).startswith("'"))
        self.assertEqual(csv_cell("normal"), "normal")

    def test_benchmark_hash_mismatch_is_not_shown(self):
        settings = DashboardSettings()
        original = Path.read_text

        def wrong_hash(path, *args, **kwargs):
            if path.name in {"test_metrics.json", "awid_diagnostic.json"}:
                return json.dumps({"artifact_sha256": "wrong"})
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", wrong_hash):
            info = load_model_info(settings.model_path)
        self.assertTrue(info["ready"])
        self.assertIsNone(info["benchmark"])
        self.assertIn("hash", info["benchmark_note"])


if __name__ == "__main__":
    unittest.main()
