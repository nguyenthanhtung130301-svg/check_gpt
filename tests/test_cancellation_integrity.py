import asyncio
import unittest
from unittest.mock import Mock

from auth.dependencies import AuthContext
from jobs import TwoFAJob, TwoFAJobManager


class FakeJobRepository:
    def __init__(self):
        self.rows = {}
        self.logs = {}

    def list_all(self):
        return list(self.rows.values())

    def create(self, row):
        self.rows[row["id"]] = dict(row)

    def update_status(self, job_id, status, **values):
        if job_id not in self.rows:
            self.rows[job_id] = {"id": job_id}
        self.rows[job_id]["status"] = status
        self.rows[job_id].update(values)

    def get_logs(self, job_id):
        return self.logs.get(job_id, [])

    def append_log(self, job_id, line):
        if job_id not in self.rows:
            raise RuntimeError(f"FOREIGN KEY constraint failed for job {job_id}")
        self.logs.setdefault(job_id, []).append({"line": line})

    def delete(self, job_id):
        self.rows.pop(job_id, None)
        self.logs.pop(job_id, None)

    def delete_all(self, _job_type):
        count = len(self.rows)
        self.rows.clear()
        self.logs.clear()
        return count


class FakeSettingsRepository:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def list(self, _prefix):
        return dict(self.values)

    def set(self, key, value):
        self.values[key] = value

    def bulk_set(self, items):
        self.values.update(items)


class CancellationIntegrityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.job_repo = FakeJobRepository()
        self.settings_repo = FakeSettingsRepository({"twofa.max_concurrent": 2})
        self.manager = TwoFAJobManager(self.job_repo, self.settings_repo)
        self.admin = AuthContext(user_id=1, username="admin", role="admin", session_id=1, raw_token="tok_admin")
        self.user_a = AuthContext(user_id=2, username="user_a", role="collaborator", session_id=2, raw_token="tok_a")
        self.user_b = AuthContext(user_id=3, username="user_b", role="collaborator", session_id=3, raw_token="tok_b")

    async def test_stop_all_awaits_cleanup_before_returning(self):
        """stop_all phải await toàn bộ running tasks kết thúc dọn dẹp trước khi trả về."""
        cleanup_done = False
        cleanup_event = asyncio.Event()

        async def fake_run_with_cleanup():
            nonlocal cleanup_done
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                await asyncio.sleep(0.05)
                cleanup_done = True
                cleanup_event.set()
                raise

        task = asyncio.create_task(fake_run_with_cleanup())
        job = TwoFAJob(
            id="job_1",
            email="u1@test.com",
            password="p1",
            secret="S1",
            status="running",
            owner_user_id=1,
        )
        self.manager.jobs[job.id] = job
        self.manager._tasks[job.id] = task

        # Cho task bắt đầu chạy vào await sleep(10)
        await asyncio.sleep(0)

        # Gọi stop_all -> phải await cho đến khi cleanup_done = True
        await self.manager.stop_all(self.admin)
        self.assertTrue(cleanup_done)
        self.assertTrue(task.done())

    async def test_clear_denies_when_tasks_are_not_done(self):
        """clear() phải từ chối (ném ValueError) khi còn task chưa kết thúc."""
        release_event = asyncio.Event()

        async def pending_task():
            try:
                await release_event.wait()
            except asyncio.CancelledError:
                await release_event.wait()

        task = asyncio.create_task(pending_task())
        job = TwoFAJob(
            id="job_pending",
            email="up@test.com",
            password="p",
            secret="S",
            status="cancelled",
            owner_user_id=1,
        )
        self.manager.jobs[job.id] = job
        self.manager._tasks[job.id] = task

        with self.assertRaises(ValueError) as ctx:
            self.manager.clear(self.admin)
        self.assertIn("đang trong quá trình dừng", str(ctx.exception))

        # Giải phóng task
        release_event.set()
        await task
        # Sau khi task done, clear() phải thành công
        deleted = self.manager.clear(self.admin)
        self.assertEqual(deleted, 0)
        self.assertEqual(len(self.manager.jobs), 0)

    async def test_clear_user_isolation(self):
        """Task đang chạy của User B KHÔNG ĐƯỢC chặn User A dọn danh sách."""
        release_event = asyncio.Event()

        async def user_b_task():
            await release_event.wait()

        task_b = asyncio.create_task(user_b_task())
        job_b = TwoFAJob(
            id="job_b",
            email="b@test.com",
            password="p",
            secret="S",
            status="running",
            owner_user_id=self.user_b.user_id,
        )
        self.manager.jobs[job_b.id] = job_b
        self.manager._tasks[job_b.id] = task_b

        # User A có job đã stopped/cancelled
        job_a = TwoFAJob(
            id="job_a",
            email="a@test.com",
            password="p",
            secret="S",
            status="cancelled",
            owner_user_id=self.user_a.user_id,
        )
        self.manager.jobs[job_a.id] = job_a
        self.job_repo.create({"id": job_a.id, "job_type": "twofa"})

        # User A dọn danh sách của mình -> Phải thành công, không bị task của User B chặn!
        deleted_a = self.manager.clear(self.user_a)
        self.assertEqual(deleted_a, 1)
        self.assertNotIn("job_a", self.manager.jobs)
        self.assertIn("job_b", self.manager.jobs)

        # Dọn dẹp task B
        release_event.set()
        await task_b

    async def test_orphan_broadcast_and_foreign_key_guard(self):
        """Sau khi clear/delete, job không còn trong self.jobs thì broadcast bị chặn và log không ghi DB."""
        job = TwoFAJob(
            id="job_orphan",
            email="orphan@test.com",
            password="p",
            secret="S",
            status="running",
        )
        # Giả lập job đã bị xóa khỏi self.jobs
        sub = self.manager.subscribe(self.admin)

        # 1. Gọi _broadcast -> không được gửi về subscriber
        self.manager._broadcast(job)
        self.assertTrue(sub.queue.empty())

        # 2. Gọi _broadcast_job với snapshot -> cũng không được gửi
        self.manager._broadcast_job(job, {"type": "job", "job": job.snapshot()})
        self.assertTrue(sub.queue.empty())

    async def test_pick_next_job_id_drops_stale_ids_from_queue(self):
        """_pick_next_job_id phải drop các candidate_id rác đã bị xóa, không put ngược lại vào queue."""
        # Giả lập queue của admin có 1 id rác và 1 id hợp lệ
        stale_id = "deleted_job_id"
        valid_job = TwoFAJob(
            id="valid_job_id",
            email="v@test.com",
            password="p",
            secret="S",
            status="queued",
            worker_slot=1,
            owner_user_id=self.admin.user_id,
        )
        self.manager.jobs[valid_job.id] = valid_job
        self.manager._queues_by_user[self.admin.user_id].put_nowait(stale_id)
        self.manager._queues_by_user[self.admin.user_id].put_nowait(valid_job.id)
        self.manager._ready_users.append(self.admin.user_id)

        # Worker slot 1 pick
        found_id, uid = await self.manager._pick_next_job_id(slot_id=1)
        self.assertEqual(found_id, "valid_job_id")
        self.assertEqual(uid, self.admin.user_id)

        # Kiểm tra stale_id đã bị drop vĩnh viễn khỏi queue (queue rỗng)
        self.assertTrue(self.manager._queues_by_user[self.admin.user_id].empty())

    async def test_thread_task_cancellation_shielded(self):
        """Khi coroutine bọc thread bị cancel, thread_task phải được await kết thúc trước khi re-raise."""
        import time
        thread_finished = False

        def slow_sync_worker():
            nonlocal thread_finished
            time.sleep(0.08)
            thread_finished = True
            return "done"

        async def run_shielded():
            thread_task = asyncio.create_task(asyncio.to_thread(slow_sync_worker))
            try:
                return await asyncio.shield(thread_task)
            except asyncio.CancelledError:
                await thread_task
                raise

        caller_task = asyncio.create_task(run_shielded())
        await asyncio.sleep(0.01)
        caller_task.cancel()

        with self.assertRaises(asyncio.CancelledError):
            await caller_task

        # Sau khi caller_task bị cancel và await xong, thread phải kết thúc thực sự!
        self.assertTrue(thread_finished)


if __name__ == "__main__":
    unittest.main()
