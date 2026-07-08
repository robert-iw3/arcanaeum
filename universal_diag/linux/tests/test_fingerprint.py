"""Template mining: masking rules and Drain-lite clustering.

These behaviors are contract (spec/event-schema.md) — the Rust port must
reproduce them exactly.
"""
import unidiag_ml as ml


def test_mask_ip_with_port():
    assert ml.mask("connect to 10.0.0.5:5432 refused") == "connect to <ip> refused"


def test_mask_uuid():
    assert ml.mask("req 550e8400-e29b-41d4-a716-446655440000 failed") == "req <uuid> failed"


def test_mask_hex_and_hash():
    assert ml.mask("addr 0xdeadbeef") == "addr <hex>"
    assert ml.mask("commit d16e54f1aabbccdd broken") == "commit <hash> broken"


def test_mask_numbers_last():
    assert ml.mask("retry 3 of 5") == "retry <n> of <n>"


def test_same_shape_messages_share_fingerprint():
    miner = ml.TemplateMiner()
    fp1, _ = miner.fingerprint("docker", "connect to 10.0.0.5:5432 refused")
    fp2, _ = miner.fingerprint("docker", "connect to 10.0.0.9:5432 refused")
    assert fp1 == fp2


def test_diverging_tokens_become_wildcards():
    miner = ml.TemplateMiner()
    miner.fingerprint("app", "user alice failed login")
    _, template = miner.fingerprint("app", "user bob failed login")
    assert template == "user <*> failed login"


def test_different_sources_never_share_fingerprint():
    miner = ml.TemplateMiner()
    fp1, _ = miner.fingerprint("docker", "disk error on device")
    fp2, _ = miner.fingerprint("kernel", "disk error on device")
    assert fp1 != fp2


def test_dissimilar_messages_get_distinct_fingerprints():
    miner = ml.TemplateMiner()
    fp1, _ = miner.fingerprint("app", "alpha beta gamma delta epsilon")
    fp2, _ = miner.fingerprint("app", "alpha one two three four")
    assert fp1 != fp2       # only 1/5 tokens match — below 0.55 threshold


def test_fingerprint_stable_across_miner_instances():
    """Fingerprints must survive process restarts (ingest replays templates)."""
    m1 = ml.TemplateMiner()
    fp1, template = m1.fingerprint("docker", "connect to 10.0.0.5:5432 refused")
    m2 = ml.TemplateMiner()
    tokens = template.split()
    m2.buckets[("docker", len(tokens), tokens[0])].append(tokens)
    fp2, _ = m2.fingerprint("docker", "connect to 10.0.0.77:5432 refused")
    assert fp1 == fp2
