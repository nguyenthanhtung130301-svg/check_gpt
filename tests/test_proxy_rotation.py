import asyncio
import random
import unittest
from unittest.mock import Mock, patch

from jobs import (
    TwoFAJobManager,
    compute_proxy_id,
    build_proxy_catalog,
    canonicalize_bindings,
    normalize_proxy,
)
from server import _test_proxy_sync


class FakeJobRepository:
    def __init__(self):
        self.rows = {}

    def list_all(self):
        return []

    def create(self, row):
        self.rows[row["id"]] = dict(row)

    def update_status(self, job_id, status, **values):
        if job_id not in self.rows:
            self.rows[job_id] = {"id": job_id}
        self.rows[job_id]["status"] = status
        self.rows[job_id].update(values)

    def get_logs(self, _job_id):
        return []


class FakeSettingsRepository:
    def __init__(self, values):
        self.values = dict(values)

    def list(self, _prefix):
        return dict(self.values)

    def set(self, key, value):
        self.values[key] = value

    def bulk_set(self, items):
        self.values.update(items)


class ProxyRotationTests(unittest.TestCase):
    def test_add_creates_jobs_without_preallocated_proxy(self):
        """Lúc tạo job (add), job chưa được gán proxy; snapshot ban đầu có has_proxy = False."""
        proxies = [f"http://127.0.0.1:{port}" for port in range(8001, 8011)]
        settings = FakeSettingsRepository({
            "twofa.max_concurrent": 5,
            "twofa.proxy_pool": proxies,
        })
        manager = TwoFAJobManager(FakeJobRepository(), settings)
        lines = [
            f"user{index}@example.com|password|JBSWY3DPEHPK3PXP"
            for index in range(1, 16)
        ]

        jobs = manager.add(lines)

        self.assertEqual(len(jobs), 15)
        # Bất biến: Không cấp proxy tĩnh lúc tạo job
        self.assertTrue(all(job["proxy_slot"] is None for job in jobs))
        self.assertTrue(all(job["has_proxy"] is False for job in jobs))

    def test_fifteen_accounts_rotate_across_ten_proxies_at_runtime(self):
        """15 tài khoản khi chuẩn bị chạy ở runtime xoay vòng chính xác qua pool 10 proxy."""
        proxies = [f"http://127.0.0.1:{port}" for port in range(8001, 8011)]
        settings = FakeSettingsRepository({
            "twofa.max_concurrent": 5,
            "twofa.proxy_pool": proxies,
            "twofa.proxy_mode": "random_per_account",
        })
        manager = TwoFAJobManager(FakeJobRepository(), settings)
        snapshots = manager.add([f"user{i}@test.com|pass|SECRET" for i in range(1, 4)])

        # Runtime cấp phát proxy
        for idx, snap in enumerate(snapshots):
            job = manager.jobs[snap["id"]]
            asyncio.run(manager._prepare_proxy(job, slot_id=1))
            self.assertIsNotNone(job.proxy)
            self.assertIn(job.proxy, proxies)
            self.assertIsNotNone(job.proxy_slot)

    def test_retry_skips_failed_proxy_and_proxy_used_by_running_job(self):
        """Khi retry ở random mode, bỏ qua proxy bị phạt cooldown và proxy đang được job khác dùng."""
        proxies = [f"http://127.0.0.1:{port}" for port in range(8001, 8004)]
        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({"twofa.proxy_pool": proxies, "twofa.proxy_mode": "random_per_account"}),
        )
        snapshots = manager.add([
            "failed@example.com|password|JBSWY3DPEHPK3PXP",
            "running@example.com|password|JBSWY3DPEHPK3PXP",
            "waiting@example.com|password|JBSWY3DPEHPK3PXP",
        ])
        failed = manager.jobs[snapshots[0]["id"]]
        running = manager.jobs[snapshots[1]["id"]]
        failed.proxy = proxies[0]
        failed.proxy_slot = 1
        failed.status = "error"
        failed.error_kind = "technical_error"
        running.status = "running"
        running.proxy = proxies[1]
        running.proxy_slot = 2

        retried = manager.retry(failed.id)

        self.assertEqual(retried["status"], "queued")
        self.assertFalse(retried["has_proxy"])
        self.assertEqual(failed.last_failed_proxy, proxies[0])
        self.assertIn(proxies[0], manager._active_proxy_cooldowns())

        # Khi prepare runtime cho job retry: candidate duy nhất còn lại là proxies[2]
        asyncio.run(manager._prepare_proxy(failed, slot_id=1))
        self.assertEqual(failed.proxy, proxies[2])
        self.assertEqual(failed.proxy_slot, 3)

    def test_random_strategy_assigns_at_runtime_from_available_proxies(self):
        """Random mode cấp phát tại runtime từ tập hợp proxy khả dụng, hỗ trợ inject RNG."""
        proxies = [f"http://127.0.0.1:{port}" for port in range(8001, 8004)]
        mock_rng = Mock()
        # Mock RNG để trả về proxy thứ 3
        mock_rng.choice.return_value = proxies[2]

        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({
                "twofa.proxy_pool": proxies,
                "twofa.proxy_mode": "random_per_account",
            }),
            rng=mock_rng,
        )
        snapshots = manager.add([
            "candidate@example.com|password|JBSWY3DPEHPK3PXP",
            "running@example.com|password|JBSWY3DPEHPK3PXP",
        ])
        candidate = manager.jobs[snapshots[0]["id"]]
        running = manager.jobs[snapshots[1]["id"]]

        self.assertFalse(snapshots[0]["has_proxy"])
        running.status = "running"
        running.proxy = proxies[0]
        running.proxy_slot = 1
        manager._proxy_cooldowns[proxies[1]] = 9999999999.0

        # Chuẩn bị proxy tại runtime cho candidate
        asyncio.run(manager._prepare_proxy(candidate, slot_id=1))

        self.assertEqual(candidate.proxy, proxies[2])
        self.assertEqual(candidate.proxy_slot, 3)
        mock_rng.choice.assert_called_once_with([proxies[2]])

    def test_invalid_proxy_mode_is_rejected(self):
        """Từ chối cấu hình proxy_mode không hợp lệ với lỗi rõ ràng."""
        manager = TwoFAJobManager(FakeJobRepository(), FakeSettingsRepository({}))

        with self.assertRaisesRegex(ValueError, "Chế độ proxy không hợp lệ"):
            asyncio.run(manager.update_settings({"twofa.proxy_mode": "unknown"}))

    def test_manual_mode_requires_complete_and_unique_bindings_for_active_slots(self):
        """Manual mode fail-closed: từ chối khi thiếu binding cho slot active hoặc gán trùng proxy."""
        proxies = [f"http://127.0.0.1:{port}" for port in range(8001, 8004)]
        catalog = build_proxy_catalog(proxies)
        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({
                "twofa.max_concurrent": 3,
                "twofa.proxy_pool": proxies,
            }),
        )

        # 1. Thiếu binding cho Luồng #3
        incomplete_bindings = {"1": catalog[0]["id"], "2": catalog[1]["id"]}
        with self.assertRaisesRegex(ValueError, "Luồng #3 chưa được gán proxy cố định"):
            asyncio.run(manager.update_settings({
                "twofa.proxy_mode": "manual_per_worker",
                "twofa.proxy_bindings": incomplete_bindings,
            }))

        # 2. Gán trùng proxy giữa Luồng #1 và Luồng #2
        dup_bindings = {"1": catalog[0]["id"], "2": catalog[0]["id"], "3": catalog[2]["id"]}
        with self.assertRaisesRegex(ValueError, "phát hiện trùng"):
            asyncio.run(manager.update_settings({
                "twofa.proxy_mode": "manual_per_worker",
                "twofa.proxy_bindings": dup_bindings,
            }))

        # 3. Gán hợp lệ 1-1 cho cả 3 luồng
        valid_bindings = {"1": catalog[0]["id"], "2": catalog[1]["id"], "3": catalog[2]["id"]}
        updated = asyncio.run(manager.update_settings({
            "twofa.proxy_mode": "manual_per_worker",
            "twofa.proxy_bindings": valid_bindings,
        }))
        self.assertEqual(updated["twofa.proxy_mode"], "manual_per_worker")
        self.assertEqual(updated["twofa.proxy_bindings"]["1"], catalog[0]["id"])

    def test_manual_mode_allows_inactive_slots_to_retain_bindings(self):
        """Giảm số luồng từ 3 về 2: slot 3 chuyển sang inactive nhưng không bị mất binding trong cấu hình."""
        proxies = [f"http://127.0.0.1:{port}" for port in range(8001, 8004)]
        catalog = build_proxy_catalog(proxies)
        valid_bindings = {"1": catalog[0]["id"], "2": catalog[1]["id"], "3": catalog[2]["id"]}

        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({
                "twofa.max_concurrent": 3,
                "twofa.proxy_pool": proxies,
                "twofa.proxy_mode": "manual_per_worker",
                "twofa.proxy_bindings": valid_bindings,
            }),
        )

        # Giảm số luồng xuống 2
        updated = asyncio.run(manager.update_settings({"twofa.max_concurrent": 2}))
        self.assertEqual(updated["twofa.max_concurrent"], 2)
        # Binding của slot 3 vẫn được bảo lưu
        self.assertEqual(updated["twofa.proxy_bindings"]["3"], catalog[2]["id"])

        # Tăng lại lên 3: Luồng 3 tự động khôi phục cấu hình hợp lệ
        updated_again = asyncio.run(manager.update_settings({"twofa.max_concurrent": 3}))
        self.assertEqual(updated_again["twofa.max_concurrent"], 3)
        self.assertEqual(updated_again["twofa.proxy_bindings"]["3"], catalog[2]["id"])

    def test_reordering_proxy_pool_does_not_break_stable_bindings(self):
        """Đảo lộn thứ tự dòng proxy trong pool không làm đổi proxy đã gán của worker nhờ Stable ID."""
        p1 = "http://127.0.0.1:8001"
        p2 = "http://127.0.0.1:8002"
        id1 = compute_proxy_id(p1)
        id2 = compute_proxy_id(p2)

        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({
                "twofa.max_concurrent": 2,
                "twofa.proxy_pool": [p1, p2],
                "twofa.proxy_mode": "manual_per_worker",
                "twofa.proxy_bindings": {"1": id1, "2": id2},
            }),
        )

        # Swap vị trí proxy trong pool: [p2, p1]
        updated = asyncio.run(manager.update_settings({"twofa.proxy_pool": [p2, p1]}))
        # Luồng 1 vẫn gán đúng id1 (p1)
        self.assertEqual(updated["twofa.proxy_bindings"]["1"], id1)

        # Worker slot 1 chuẩn bị proxy: vẫn nhận đúng p1
        snapshots = manager.add(["user@example.com|pass|SECRET"])
        job = manager.jobs[snapshots[0]["id"]]
        asyncio.run(manager._prepare_proxy(job, slot_id=1))
        self.assertEqual(job.proxy, p1)

    def test_legacy_index_bindings_migrated_to_stable_ids(self):
        """Binding cũ dùng index 1, 2 tự động được migrate sang stable ID px_<hash16>."""
        p1 = "http://127.0.0.1:8001"
        p2 = "http://127.0.0.1:8002"
        id1 = compute_proxy_id(p1)
        id2 = compute_proxy_id(p2)

        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({
                "twofa.max_concurrent": 2,
                "twofa.proxy_pool": [p1, p2],
            }),
        )

        # Gửi binding dạng legacy index: {"1": 1, "2": 2}
        updated = asyncio.run(manager.update_settings({
            "twofa.proxy_mode": "manual_per_worker",
            "twofa.proxy_bindings": {"1": 1, "2": 2},
        }))

        self.assertEqual(updated["twofa.proxy_bindings"]["1"], id1)
        self.assertEqual(updated["twofa.proxy_bindings"]["2"], id2)

    def test_manual_retry_preserves_worker_affinity(self):
        """Job retry ở chế độ manual giữ nguyên worker_slot và chỉ cho phép đúng worker đó nhặt."""
        p1 = "http://127.0.0.1:8001"
        p2 = "http://127.0.0.1:8002"
        id1 = compute_proxy_id(p1)
        id2 = compute_proxy_id(p2)

        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({
                "twofa.max_concurrent": 2,
                "twofa.proxy_pool": [p1, p2],
                "twofa.proxy_mode": "manual_per_worker",
                "twofa.proxy_bindings": {"1": id1, "2": id2},
            }),
        )
        snapshots = manager.add(["job1@test.com|pass|SECRET"])
        job = manager.jobs[snapshots[0]["id"]]

        # Giả lập job chạy lần 1 trên Worker Slot #2 và gặp lỗi kỹ thuật
        job.worker_slot = 2
        job.proxy = p2
        job.proxy_slot = 2
        job.status = "error"
        job.error_kind = "technical_error"

        # Retry job
        retried = manager.retry(job.id)
        self.assertEqual(retried["status"], "queued")
        # Bất biến: giữ nguyên worker affinity với Slot 2
        self.assertEqual(job.worker_slot, 2)

        # Worker slot 1 quét queue: KHÔNG ĐƯỢC NHẶT job này
        job_picked_slot1, _ = asyncio.run(manager._pick_next_job_id(slot_id=1))
        self.assertIsNone(job_picked_slot1)

        # Worker slot 2 quét queue: ĐƯỢC PHÉP NHẶT đúng job này
        job_picked_slot2, _ = asyncio.run(manager._pick_next_job_id(slot_id=2))
        self.assertEqual(job_picked_slot2, job.id)

    def test_scheduler_non_starvation_with_mixed_affinity(self):
        """Job của Slot 2 đứng đầu queue không làm kẹt Slot 1 nhặt job của mình phía sau."""
        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({"twofa.max_concurrent": 2}),
        )
        # Thêm 2 job
        snapshots = manager.add([
            "slot2_first@test.com|pass|SECRET",
            "slot1_second@test.com|pass|SECRET",
        ])
        job_slot2 = manager.jobs[snapshots[0]["id"]]
        job_slot1 = manager.jobs[snapshots[1]["id"]]

        # Gán affinity
        job_slot2.worker_slot = 2
        job_slot1.worker_slot = 1

        # Slot 1 tìm job: dù job_slot2 ở đầu queue, Slot 1 vẫn scan và nhặt được job_slot1 mà không bị kẹt
        picked_slot1, _ = asyncio.run(manager._pick_next_job_id(slot_id=1))
        self.assertEqual(picked_slot1, job_slot1.id)

        # Slot 2 tìm job: nhặt được job_slot2
        picked_slot2, _ = asyncio.run(manager._pick_next_job_id(slot_id=2))
        self.assertEqual(picked_slot2, job_slot2.id)

    def test_worker_downscale_and_upscale_slot_integrity(self):
        """Downscale rồi upscale quản lý chính xác từng slot_id, không trùng slot hay mồ côi task."""
        async def scenario():
            manager = TwoFAJobManager(
                FakeJobRepository(),
                FakeSettingsRepository({"twofa.max_concurrent": 3}),
            )
            manager._spawn_workers(3)
            self.assertEqual(set(manager._workers.keys()), {1, 2, 3})

            # Giảm luồng về 2: slot 3 được đánh dấu thu hồi khi xong
            await manager._resize_workers(previous=3, target=2)

            # Tăng lại lên 3: khôi phục đúng slot 3
            await manager._resize_workers(previous=2, target=3)
            self.assertEqual(set(manager._workers.keys()), {1, 2, 3})

            # Dọn dẹp
            await manager.shutdown()

        asyncio.run(scenario())

    def test_atomic_settings_failure_leaves_db_and_ram_intact(self):
        """Khi DB ghi thất bại, cả SQLite và self.settings trong RAM đều được bảo toàn 100%."""
        repo = FakeSettingsRepository({"twofa.max_concurrent": 2, "twofa.proxy_mode": "random_per_account"})

        class FailingSettingsRepo(FakeSettingsRepository):
            def bulk_set(self, items):
                raise RuntimeError("DB Disk I/O Error")

        manager = TwoFAJobManager(FakeJobRepository(), FailingSettingsRepo(repo.values))

        with self.assertRaises(RuntimeError):
            asyncio.run(manager.update_settings({"twofa.max_concurrent": 5}))

        # RAM vẫn giữ nguyên giá trị cũ (2)
        self.assertEqual(manager.settings["twofa.max_concurrent"], 2)

    def test_active_jobs_prevent_proxy_settings_update_409(self):
        """Khi có job đang queued hoặc running, thay đổi routing bị từ chối."""
        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({"twofa.max_concurrent": 2}),
        )
        snapshots = manager.add(["active@test.com|pass|SECRET"])
        self.assertEqual(snapshots[0]["status"], "queued")

        with self.assertRaisesRegex(ValueError, "Không thể thay đổi cấu hình proxy hoặc số luồng khi đang có tác vụ"):
            asyncio.run(manager.update_settings({"twofa.max_concurrent": 4}))

    def test_proxy_check_reads_current_ip_without_calling_chatgpt(self):
        response = Mock(
            status_code=200,
            text="ip=203.0.113.9\nloc=VN\n",
        )
        session = Mock()
        session.get.return_value = response

        with patch("curl_cffi.requests.Session", return_value=session):
            result = _test_proxy_sync(1, "127.0.0.1:8080")

        session.get.assert_called_once_with(
            "https://www.cloudflare.com/cdn-cgi/trace",
            timeout=12.0,
            allow_redirects=False,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["exit_ip"], "203.0.113.9")
        self.assertEqual(result["country"], "VN")
        self.assertTrue(result["checked_at"])


if __name__ == "__main__":
    unittest.main()
