"""重建精简、可复现的算法验证结果，不保存数十 MB 的中间明细。"""

from __future__ import annotations

from datetime import datetime
from hashlib import sha256
from pathlib import Path
import csv
import json
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sdes.analysis import brute_force, collision_analysis, export_analysis
from sdes.core import crypt, trace


def save(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def cross_validate(results: Path) -> dict:
    """Compare a digest of all ordered ciphertext bytes from both implementations."""
    started = time.perf_counter()
    python_hash = sha256()
    roundtrip_errors = 0
    for key in range(1024):
        for plain in range(256):
            cipher = crypt(plain, key)
            python_hash.update(bytes((cipher,)))
            roundtrip_errors += crypt(cipher, key, True) != plain

    process = subprocess.run(
        ["node", "reference/sdes.js", "--summary"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    reference = json.loads(process.stdout)
    digest = python_hash.hexdigest()
    if reference["sha256"] != digest or reference["roundtripErrors"] or roundtrip_errors:
        raise AssertionError("Python 与 JavaScript 全域交叉验证不一致")

    summary = {
        "records": 262_144,
        "encryption_agreements": 262_144,
        "mismatches": 0,
        "bidirectional_decryption_checks": 524_288,
        "ordered_ciphertext_sha256": digest,
        "python_roundtrip_errors": roundtrip_errors,
        "javascript_roundtrip_errors": reference["roundtripErrors"],
        "javascript_samples": reference["samples"],
        "elapsed_seconds": time.perf_counter() - started,
        "platform_scope": "同一主机上的 Python 整数实现与 JavaScript 位数组实现；真实跨组测试仍需人工完成",
    }
    save(results / "cross_validation" / "summary.json", summary)
    return summary


def create_vectors(results: Path) -> None:
    vector_dir = results / "test_vectors"
    vector_dir.mkdir(parents=True, exist_ok=True)
    samples = [(642, 215), (0, 0), (1023, 255), (1, 1), (341, 42), (682, 128), (512, 32), (123, 250), (642, 8)]
    with (vector_dir / "vectors.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["key", "plaintext", "ciphertext"])
        writer.writerows((f"{key:010b}", f"{plain:08b}", f"{crypt(plain, key):08b}") for key, plain in samples)
    with (vector_dir / "other_group_template.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["group", "members", "os", "language", "key", "plaintext", "expected_ciphertext", "actual_ciphertext", "decrypted_plaintext", "date", "confirmed_by", "notes"])
        writer.writerows(["", "", "", "", f"{key:010b}", f"{plain:08b}", f"{crypt(plain, key):08b}", "", "", "", "", ""] for key, plain in samples)
    save(vector_dir / "trace.json", trace(215, 642))


def main() -> None:
    results = ROOT / "results"
    results.mkdir(exist_ok=True)
    cross = cross_validate(results)
    create_vectors(results)

    pairs = [(plain, crypt(plain, 642)) for plain in (215, 0, 1, 2, 3, 4, 8)]
    brute_runs = [brute_force(pairs[:count]) for count in range(1, len(pairs) + 1)]
    save(results / "brute_force.json", brute_runs)

    analysis = collision_analysis()
    export_analysis(analysis, results / "collision_statistics.csv")

    candidate_examples = []
    for desired in (0, 1):
        found = None
        for plain in range(256):
            groups = {cipher: [] for cipher in range(256)}
            for key in range(1024):
                groups[crypt(plain, key)].append(key)
            match = next(((cipher, keys) for cipher, keys in groups.items() if len(keys) == desired), None)
            if match is not None:
                found = (plain, *match)
                break
        if found is None:
            continue
        plain, cipher, keys = found
        candidate_examples.append({
            "plaintext": f"{plain:08b}",
            "ciphertext": f"{cipher:08b}",
            "candidate_count": desired,
            "keys": [f"{key:010b}" for key in keys],
        })
    save(results / "candidate_examples.json", candidate_examples)

    environment = {
        "python": sys.version.splitlines()[0],
        "executable": sys.executable,
        "platform": platform.platform(),
        "node": subprocess.check_output(["node", "--version"], text=True).strip(),
        "recorded_at": datetime.now().astimezone().isoformat(),
    }
    save(results / "environment.json", environment)
    print(json.dumps({
        "cross_validation": cross,
        "brute_force_candidate_counts": [run["candidate_count"] for run in brute_runs],
        "collision_encryptions": analysis["encryptions"],
        "unique_mappings": analysis["unique_mappings"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
