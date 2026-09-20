import unittest
from unittest.mock import Mock, patch

from jobs import TwoFAJobManager
from server import _test_proxy_sync


class FakeJobRepository:
    def __init__(self):
        self.rows = {}

    def list_all(self):
        return []

    def create(self, row):
        self.rows[row["id"]] = dict(row)

    def update_status(self, job_id, status, **values):
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


class ProxyRotationTests(unittest.TestCase):
    def test_fifteen_accounts_rotate_across_ten_proxies(self):
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
        self.assertEqual(
            [job["proxy_slot"] for job in jobs],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5],
        )

    def test_retry_skips_failed_proxy_and_proxy_used_by_running_job(self):
        proxies = [f"http://127.0.0.1:{port}" for port in range(8001, 8004)]
        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({"twofa.proxy_pool": proxies}),
        )
        snapshots = manager.add([
            "failed@example.com|password|JBSWY3DPEHPK3PXP",
            "running@example.com|password|JBSWY3DPEHPK3PXP",
            "waiting@example.com|password|JBSWY3DPEHPK3PXP",
        ])
        failed = manager.jobs[snapshots[0]["id"]]
        running = manager.jobs[snapshots[1]["id"]]
        failed.status = "error"
        failed.error_kind = "technical_error"
        running.status = "running"

        retried = manager.retry(failed.id)

        self.assertEqual(retried["status"], "queued")
        self.assertEqual(retried["proxy_slot"], 3)
        self.assertEqual(failed.last_failed_proxy, proxies[0])
        self.assertIn(proxies[0], manager._active_proxy_cooldowns())

    def test_retry_waits_when_every_alternative_proxy_is_unavailable(self):
        proxies = [f"http://127.0.0.1:{port}" for port in range(8001, 8003)]
        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({"twofa.proxy_pool": proxies}),
        )
        snapshots = manager.add([
            "failed@example.com|password|JBSWY3DPEHPK3PXP",
            "running@example.com|password|JBSWY3DPEHPK3PXP",
        ])
        failed = manager.jobs[snapshots[0]["id"]]
        running = manager.jobs[snapshots[1]["id"]]
        failed.status = "error"
        failed.error_kind = "technical_error"
        running.status = "running"

        retried = manager.retry(failed.id)

        self.assertEqual(retried["status"], "queued")
        self.assertFalse(retried["has_proxy"])
        self.assertIsNone(manager._pick_available_proxy(failed, proxies))

    def test_random_strategy_assigns_at_runtime_from_available_proxies(self):
        proxies = [f"http://127.0.0.1:{port}" for port in range(8001, 8004)]
        manager = TwoFAJobManager(
            FakeJobRepository(),
            FakeSettingsRepository({
                "twofa.proxy_pool": proxies,
                "twofa.proxy_strategy": "random",
            }),
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

        with patch("jobs._PROXY_RANDOM.choice", return_value=(3, proxies[2])) as choice:
            selected = manager._pick_available_proxy(candidate, proxies)

        self.assertEqual(selected, (3, proxies[2]))
        choice.assert_called_once_with([(3, proxies[2])])

    def test_invalid_proxy_strategy_is_rejected(self):
        manager = TwoFAJobManager(FakeJobRepository(), FakeSettingsRepository({}))

        with self.assertRaisesRegex(ValueError, "Chiến lược proxy"):
            import asyncio
            asyncio.run(manager.update_settings({"twofa.proxy_strategy": "unknown"}))

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
