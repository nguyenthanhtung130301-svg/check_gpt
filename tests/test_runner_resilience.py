import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from auth.dependencies import AuthContext
from jobs import TwoFAJobManager, TwoFAJob
from service import RotationResult


class FakeJobRepository:
    def __init__(self):
        self.rows = {}
        self.logs = {}

    def list_all(self):
        return []

    def create(self, row):
        self.rows[row["id"]] = dict(row)
        self.logs[row["id"]] = []

    def update_status(self, job_id, status, **values):
        if job_id in self.rows:
            self.rows[job_id]["status"] = status
            self.rows[job_id].update(values)

    def append_log(self, job_id, line):
        if job_id not in self.logs:
            self.logs[job_id] = []
        self.logs[job_id].append(line)

    def get_logs(self, job_id):
        return [{"line": l} for l in self.logs.get(job_id, [])]


class FakeSettingsRepository:
    def __init__(self, values):
        self.values = dict(values)

    def list(self, _prefix):
        return dict(self.values)

    def set(self, key, value):
        self.values[key] = value


def make_auth(user_id: int, username: str, role: str) -> AuthContext:
    return AuthContext(
        user_id=user_id,
        username=username,
        role=role,
        session_id=user_id * 100,
        raw_token=f"token_{user_id}",
    )


class RunnerResilienceTests(unittest.IsolatedAsyncioTestCase):
    async def test_worker_survives_job_exception_and_processes_next_job(self):
        """Kiểm thử: Job 1 bị ngoại lệ bất ngờ -> Job 1 thành error, worker không chết, Job 2 chạy thành công."""
        settings = FakeSettingsRepository({
            "twofa.max_concurrent": 1,
            "twofa.auto_retry": False,
            "twofa.job_timeout": 5.0,
        })
        job_repo = FakeJobRepository()
        manager = TwoFAJobManager(job_repo, settings)

        call_count = 0

        async def mock_check(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Bất ngờ gặp sự cố mạng hoặc unhandled exception")
            return RotationResult(
                secret="JBSWY3DPEHPK3PXP",
                login_verified=True,
                account_state="live",
                plan="plus",
            )

        manager.service.check = mock_check

        admin_actor = make_auth(1, "admin", "admin")
        lines = [
            "faulty@example.com|password|JBSWY3DPEHPK3PXP",
            "healthy@example.com|password|JBSWY3DPEHPK3PXP",
        ]
        created = manager.add(lines, mode="check_only", actor=admin_actor)
        job1_id, job2_id = created[0]["id"], created[1]["id"]

        manager.start()

        # Đợi tối đa 3 giây cho 2 jobs chạy xong
        for _ in range(30):
            j1 = manager.jobs[job1_id]
            j2 = manager.jobs[job2_id]
            if j1.status in {"error", "success"} and j2.status in {"error", "success"}:
                break
            await asyncio.sleep(0.1)

        await manager.shutdown()

        j1 = manager.jobs[job1_id]
        j2 = manager.jobs[job2_id]

        # Kiểm tra Job 1
        self.assertEqual(j1.status, "error")
        self.assertIn("Bất ngờ gặp sự cố mạng", j1.error)

        # Kiểm tra Job 2 vẫn được worker tiếp tục xử lý và thành công
        self.assertEqual(j2.status, "success")
        self.assertTrue(j2.login_verified)
        self.assertEqual(j2.account_state, "live")

        # Kiểm tra counter và tasks được dọn sạch
        self.assertEqual(manager._running_by_user[1], 0)
        self.assertEqual(len(manager._tasks), 0)

    async def test_broadcast_fires_on_all_lifecycle_stages(self):
        """Kiểm thử: _broadcast() phát đúng payload ở các giai đoạn running, log, checkpoint, success, cancel."""
        settings = FakeSettingsRepository({
            "twofa.max_concurrent": 1,
            "twofa.job_timeout": 5.0,
        })
        job_repo = FakeJobRepository()
        manager = TwoFAJobManager(job_repo, settings)

        actor = make_auth(1, "admin", "admin")
        sub = manager.subscribe(actor)

        async def mock_rotate(*args, checkpoint, log, **kwargs):
            log("Bắt đầu xử lý")
            await checkpoint("NEWSECRET2FA12345")
            return RotationResult(
                secret="NEWSECRET2FA12345",
                login_verified=True,
                account_state="live",
            )

        manager.service.rotate = mock_rotate

        created = manager.add(["test@example.com|password|OLDSECRET1234567"], mode="change_2fa", actor=actor)
        job_id = created[0]["id"]

        manager.start()

        received_events = []
        for _ in range(30):
            while not sub.queue.empty():
                item = sub.queue.get_nowait()
                received_events.append(item)
            if manager.jobs[job_id].status == "success":
                break
            await asyncio.sleep(0.1)

        await manager.shutdown()

        # Kiểm tra các sự kiện nhận được qua broadcast
        statuses = [e.get("job", {}).get("status") for e in received_events if "job" in e]
        self.assertIn("running", statuses)
        self.assertIn("success", statuses)

        # Kiểm tra checkpoint 2FA mới: rotated_pending_verify đã được bật trong snapshot phát ra
        rotations = [e.get("job", {}).get("rotated_pending_verify") for e in received_events if "job" in e]
        self.assertIn(True, rotations)
        self.assertEqual(manager.jobs[job_id].secret, "NEWSECRET2FA12345")

    async def test_prepare_proxy_timeout_when_exhausted(self):
        """Kiểm thử: Tất cả proxy bận quá PROXY_WAIT_TIMEOUT -> job chuyển error rõ ràng, không treo."""
        settings = FakeSettingsRepository({
            "twofa.max_concurrent": 1,
            "twofa.proxy_pool": ["http://127.0.0.1:8080"],
            "twofa.job_timeout": 5.0,
        })
        job_repo = FakeJobRepository()
        manager = TwoFAJobManager(job_repo, settings)

        # Đánh dấu proxy duy nhất đang cooldown
        manager._proxy_cooldowns["http://127.0.0.1:8080"] = 9999999999.0

        actor = make_auth(1, "admin", "admin")
        created = manager.add(["user@example.com|password|SECRET123"], mode="check_only", actor=actor)
        job_id = created[0]["id"]

        # Patch PROXY_WAIT_TIMEOUT xuống 0.3s để test nhanh
        with patch("jobs.PROXY_WAIT_TIMEOUT", 0.3):
            manager.start()
            for _ in range(15):
                if manager.jobs[job_id].status == "error":
                    break
                await asyncio.sleep(0.1)
            await manager.shutdown()

        job = manager.jobs[job_id]
        self.assertEqual(job.status, "error")
        self.assertIn("Hết thời gian chờ proxy khả dụng", job.error)

    async def test_broadcast_owner_scoping(self):
        """Kiểm thử: Phân quyền broadcast — CTV B không nhận được event của CTV A; Admin nhận tất cả."""
        settings = FakeSettingsRepository({"twofa.max_concurrent": 1})
        job_repo = FakeJobRepository()
        manager = TwoFAJobManager(job_repo, settings)

        user_a = make_auth(2, "ctv_a", "collaborator")
        user_b = make_auth(3, "ctv_b", "collaborator")
        admin = make_auth(1, "admin", "admin")

        sub_a = manager.subscribe(user_a)
        sub_b = manager.subscribe(user_b)
        sub_admin = manager.subscribe(admin)

        async def mock_check(*args, log, **kwargs):
            log("Đang check của user A")
            return RotationResult(secret="S", login_verified=True, account_state="live")

        manager.service.check = mock_check

        # Job tạo bởi user A
        created = manager.add(["ctva@example.com|pass|SECRET"], mode="check_only", actor=user_a)
        job_id = created[0]["id"]

        manager.start()
        for _ in range(20):
            if manager.jobs[job_id].status == "success":
                break
            await asyncio.sleep(0.1)
        await manager.shutdown()

        # Thu thập event
        events_a, events_b, events_admin = [], [], []
        while not sub_a.queue.empty():
            events_a.append(sub_a.queue.get_nowait())
        while not sub_b.queue.empty():
            events_b.append(sub_b.queue.get_nowait())
        while not sub_admin.queue.empty():
            events_admin.append(sub_admin.queue.get_nowait())

        self.assertTrue(len(events_a) > 0, "CTV A phải nhận được event")
        self.assertTrue(len(events_admin) > 0, "Admin phải nhận được event")
        self.assertEqual(len(events_b), 0, "CTV B tuyệt đối không được nhận event của CTV A")

    async def test_output_includes_successful_check_only_jobs(self):
        """Kiểm thử: Job ở chế độ check_only khi thành công (live) phải xuất hiện trong output()."""
        settings = FakeSettingsRepository({"twofa.max_concurrent": 1})
        job_repo = FakeJobRepository()
        manager = TwoFAJobManager(job_repo, settings)

        admin = make_auth(1, "admin", "admin")

        async def mock_check(*args, **kwargs):
            return RotationResult(secret="LIVE_SECRET", login_verified=True, account_state="live")

        manager.service.check = mock_check

        created = manager.add(["liveuser@example.com|mypass|LIVE_SECRET"], mode="check_only", actor=admin)
        job_id = created[0]["id"]

        manager.start()
        for _ in range(20):
            if manager.jobs[job_id].status == "success":
                break
            await asyncio.sleep(0.1)
        await manager.shutdown()

        output_lines = manager.output(actor=admin)
        self.assertEqual(len(output_lines), 1)
        self.assertEqual(output_lines[0], "liveuser@example.com|mypass|LIVE_SECRET")

    async def test_check_only_keeps_selected_proxy_and_does_not_call_change_flows(self):
        proxy = "http://127.0.0.1:8080"
        settings = FakeSettingsRepository({
            "twofa.max_concurrent": 1,
            "twofa.job_timeout": 5.0,
            "twofa.proxy_pool": [proxy],
            "twofa.proxy_strategy": "random",
        })
        job_repo = FakeJobRepository()
        manager = TwoFAJobManager(job_repo, settings)
        admin = make_auth(1, "admin", "admin")
        seen_proxies = []

        async def mock_check(*args, **kwargs):
            seen_proxies.append(kwargs["proxy"])
            return RotationResult(
                secret="LIVE_SECRET",
                login_verified=True,
                account_state="live",
            )

        manager.service.check = mock_check
        manager.service.rotate = AsyncMock()
        manager.service.change_password = AsyncMock()
        manager.service.rotate_with_password = AsyncMock()
        manager.service.verify = AsyncMock()

        created = manager.add(
            ["liveproxy@example.com|mypass|LIVE_SECRET"],
            mode="check_only",
            actor=admin,
        )
        job = manager.jobs[created[0]["id"]]
        await manager._run(job)

        self.assertEqual(job.status, "success")
        self.assertEqual(job.proxy, proxy)
        self.assertEqual(seen_proxies, [proxy])
        manager.service.rotate.assert_not_awaited()
        manager.service.change_password.assert_not_awaited()
        manager.service.rotate_with_password.assert_not_awaited()
        manager.service.verify.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
