import time

import pytest
from cryptography.fernet import Fernet

from veritrace.store import MemoryStore
from veritrace.store_s3 import S3ColdArchiveStore
from veritrace.types import TraceEvent


class _Body:
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.puts = []

    def put_object(self, **kwargs):
        key = (kwargs["Bucket"], kwargs["Key"])
        self.objects[key] = kwargs
        self.puts.append(kwargs)

    def get_object(self, Bucket, Key):
        return {"Body": _Body(self.objects[(Bucket, Key)]["Body"])}


def _trace(call_id, tenant, created_at):
    return TraceEvent(
        call_id=call_id,
        tenant_id=tenant,
        session_id="s1",
        created_at=created_at,
        input_text="hello",
        output_text="world",
        prev_hash="0" * 64,
        this_hash=f"{call_id:0<64}"[:64],
    )


def test_s3_archive_prune_encrypts_and_deletes_hot_trace():
    hot = MemoryStore()
    old = _trace("old", "tenant_a", time.time() - 1000)
    fresh = _trace("fresh", "tenant_a", time.time())
    hot.save(old)
    hot.save(fresh)
    s3 = FakeS3()
    archived = []
    store = S3ColdArchiveStore(
        hot,
        bucket="audit-bucket",
        s3_client=s3,
        encryption_key=Fernet.generate_key(),
        metadata_sink=archived.append,
    )

    deleted = store.prune_older_than(time.time() - 100)

    assert deleted == 1
    assert hot.get("fresh").call_id == "fresh"
    with pytest.raises(KeyError):
        hot.get("old")
    restored = store.get("old", tenant_id="tenant_a")
    assert restored.call_id == "old"
    assert restored.tenant_id == "tenant_a"
    assert archived[0].uri.startswith("s3://audit-bucket/veritrace/traces/")
    assert s3.puts[0]["Metadata"]["encrypted"] == "true"


def test_s3_archive_delete_for_tenant_is_scoped():
    hot = MemoryStore()
    hot.save(_trace("a1", "tenant_a", time.time()))
    hot.save(_trace("b1", "tenant_b", time.time()))
    store = S3ColdArchiveStore(
        hot,
        bucket="audit-bucket",
        s3_client=FakeS3(),
        encryption_key=Fernet.generate_key(),
    )

    deleted = store.delete_for_tenant("tenant_a")

    assert deleted == 1
    assert store.get("a1", tenant_id="tenant_a").tenant_id == "tenant_a"
    with pytest.raises(PermissionError):
        store.get("a1", tenant_id="tenant_b")
    assert hot.get("b1").tenant_id == "tenant_b"
    assert store.archive_metadata()[0]["tenant_id"] == "tenant_a"


def test_s3_archive_requires_encryption_key():
    with pytest.raises(ValueError):
        S3ColdArchiveStore(MemoryStore(), bucket="audit-bucket", s3_client=FakeS3())
