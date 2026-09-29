import sys
import time
import unittest

from backend.core.native_stream import NativeLineStream, NativeProcessError


class NativeStreamTests(unittest.TestCase):
    def command(self, script):
        return [sys.executable, "-u", "-c", script]

    def test_stderr_flood_does_not_deadlock_or_grow_unbounded(self):
        command = self.command("import sys; sys.stderr.write('x'*200000); print('ok')")
        with NativeLineStream(command, idle_timeout=10) as stream:
            self.assertEqual([line.strip() for line in stream], ["ok"])
            self.assertLessEqual(len(stream.stderr_tail), 65536)

    def test_nonzero_after_partial_output_is_not_success(self):
        command = self.command("import sys; print('partial'); sys.stderr.write('bad capture'); sys.exit(7)")
        with NativeLineStream(command, idle_timeout=10) as stream:
            iterator = iter(stream)
            self.assertEqual(next(iterator).strip(), "partial")
            with self.assertRaisesRegex(NativeProcessError, "code 7.*bad capture"):
                next(iterator)

    def test_idle_timeout_reaps_process(self):
        stream = NativeLineStream(self.command("import time; time.sleep(30)"), idle_timeout=0.2)
        started = time.monotonic()
        with self.assertRaisesRegex(NativeProcessError, "no output"):
            with stream:
                list(stream)
        self.assertIsNotNone(stream.process.poll())
        self.assertLess(time.monotonic() - started, 8)

    def test_early_close_handles_full_queue_and_reaps_process(self):
        stream = NativeLineStream(self.command("while True: print('packet')"), queue_size=1)
        with stream:
            self.assertEqual(next(iter(stream)).strip(), "packet")
        self.assertIsNotNone(stream.process.poll())
        self.assertFalse(any(t.is_alive() for t in stream.threads))

    def test_oversized_line_rejected(self):
        with NativeLineStream(self.command("print('x'*1000)"), line_limit=64) as stream:
            with self.assertRaisesRegex(NativeProcessError, "exceeds"):
                list(stream)


if __name__ == "__main__":
    unittest.main()
