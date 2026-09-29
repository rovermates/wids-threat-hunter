"""Bounded subprocess output with idle timeout and deterministic cleanup."""
from collections import deque
import math
import os
import queue
import subprocess
import threading


class NativeProcessError(RuntimeError):
    pass


class NativeLineStream:
    """Context manager for a single native decoder, never a shell command."""

    def __init__(self, command, *, idle_timeout=120.0, queue_size=128, line_limit=65536):
        if not math.isfinite(idle_timeout) or idle_timeout <= 0:
            raise ValueError("idle_timeout must be finite and positive")
        if queue_size <= 0 or line_limit <= 0:
            raise ValueError("buffer limits must be positive")
        self.command = command
        self.idle_timeout = idle_timeout
        self.line_limit = line_limit
        self.queue = queue.Queue(maxsize=queue_size)
        self.stop = threading.Event()
        self.errors = deque(maxlen=16)
        self.process = None
        self.threads = []

    def _put(self, item):
        while not self.stop.is_set():
            try:
                self.queue.put(item, timeout=0.1)
                return
            except queue.Full:
                pass

    def _stdout(self):
        try:
            while not self.stop.is_set():
                line = self.process.stdout.readline(self.line_limit + 1)
                if not line:
                    break
                if len(line) > self.line_limit:
                    raise NativeProcessError("Decoder output line exceeds the configured bound")
                self._put(line.decode("utf-8", errors="strict"))
        except (OSError, UnicodeError, NativeProcessError) as exc:
            self._put(exc)
        finally:
            self._put(None)

    def _stderr(self):
        while not self.stop.is_set():
            block = self.process.stderr.read(4096)
            if not block:
                break
            self.errors.append(block)

    @property
    def stderr_tail(self):
        return b"".join(self.errors).decode("utf-8", errors="replace").strip()

    def __enter__(self):
        self.process = subprocess.Popen(
            self.command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        self.threads = [threading.Thread(target=target, daemon=True)
                        for target in (self._stdout, self._stderr)]
        for worker in self.threads:
            worker.start()
        return self

    def __iter__(self):
        while True:
            try:
                item = self.queue.get(timeout=self.idle_timeout)
            except queue.Empty as exc:
                raise NativeProcessError(f"Decoder produced no output for {self.idle_timeout:g} seconds") from exc
            if item is None:
                break
            if isinstance(item, Exception):
                raise NativeProcessError(str(item)) from item
            yield item
        try:
            code = self.process.wait(timeout=self.idle_timeout)
        except subprocess.TimeoutExpired as exc:
            raise NativeProcessError("Decoder did not exit after closing its output") from exc
        self.threads[1].join(timeout=2)
        if code:
            raise NativeProcessError(f"Decoder exited with code {code}: {self.stderr_tail[-4096:]}")

    def __exit__(self, *exc_info):
        self.stop.set()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        for worker in self.threads:
            worker.join(timeout=2)
        self.process.stdout.close()
        self.process.stderr.close()
