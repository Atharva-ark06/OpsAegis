import asyncio
import threading
import pytest
from app.config import settings
from app.routers.nuclei import WorkerLeaseLost, execute

class FakeStdout:
    def __init__(self, chunks):
        self.chunks=list(chunks)
    async def read(self, size):
        if not self.chunks:
            return b""
        item=self.chunks.pop(0)
        if item=="wait":
            await asyncio.sleep(10)
        return item

class FakeProcess:
    def __init__(self, chunks):
        self.stdout=FakeStdout(chunks)
        self.returncode=None
        self.killed=False
    def kill(self):
        self.killed=True
        self.returncode=-9
    async def wait(self):
        if self.returncode is None:
            self.returncode=0
        return self.returncode

def test_execute_uses_explicit_pinned_template_directory(monkeypatch):
    process=FakeProcess([b""])
    captured={}
    async def fake_create(*args, **kwargs):
        captured["args"]=args
        return process
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    assert asyncio.run(execute("https://authorized.example.test")) == []
    args=captured["args"]
    assert "-t" in args
    assert args[args.index("-t")+1] == settings.nuclei_templates_path
    assert "-disable-update-check" in args

def test_execute_kills_scan_when_worker_lease_is_lost(monkeypatch):
    process=FakeProcess(["wait"])
    async def fake_create(*args, **kwargs):
        return process
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    lease_lost=threading.Event()
    lease_lost.set()
    with pytest.raises(WorkerLeaseLost):
        asyncio.run(execute("https://authorized.example.test", lease_lost=lease_lost))
    assert process.killed
