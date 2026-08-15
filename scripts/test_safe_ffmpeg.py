from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parent))
import safe_ffmpeg  # noqa: E402


class SafeFfmpegArgumentTests(unittest.TestCase):
    def test_accepts_bounded_main_stream_crop(self) -> None:
        safe_ffmpeg.validate_arguments(
            [
                "-i",
                r"C:\素材\课程.mp4",
                "-map",
                "0:v:0",
                "-map",
                "0:a:0?",
                "-t",
                "10",
                "-vf",
                "crop=960:540:0:0,scale=1280:720",
                r"C:\输出\片段.mp4",
            ]
        )

    def test_rejects_realtime_input(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                ["-re", "-i", "in.mp4", "-map", "0:v:0", "out.mp4"]
            )

    def test_rejects_unc_input(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                ["-i", r"\\server\share\in.mp4", "-map", "0:v:0", "out.mp4"]
            )

    def test_rejects_unc_and_protocol_outputs(self) -> None:
        for output in (
            r"\\server\share\out.mp4",
            "https://example.com/out.mp4",
        ):
            with self.subTest(output=output), self.assertRaises(
                safe_ffmpeg.SafetyError
            ):
                safe_ffmpeg.validate_arguments(
                    [
                        "-i",
                        r"C:\本地\in.mp4",
                        "-map",
                        "0:v:0",
                        output,
                    ]
                )

    def test_rejects_auxiliary_output_and_multipass_options(self) -> None:
        for prefix in (
            ["-progress", "https://example.com/status"],
            ["-passlogfile", r"\\server\share\passlog"],
            ["-pass", "1"],
        ):
            with self.subTest(prefix=prefix), self.assertRaises(
                safe_ffmpeg.SafetyError
            ):
                safe_ffmpeg.validate_arguments(
                    [
                        *prefix,
                        "-i",
                        r"C:\本地\in.mp4",
                        "-map",
                        "0:v:0",
                        r"C:\本地\out.mp4",
                    ]
                )

    @unittest.skipUnless(os.name == "nt", "Windows UNC 当前目录检查")
    def test_relative_targets_resolve_against_unc_cwd_and_are_rejected(self) -> None:
        with mock.patch.object(
            safe_ffmpeg.Path,
            "resolve",
            return_value=Path(r"\\server\share\relative.mp4"),
        ):
            with self.assertRaises(safe_ffmpeg.SafetyError):
                safe_ffmpeg._validate_local_target("relative.mp4", "输出")

    def test_rejects_file_url_unc_input(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                ["-i", "file://server/share/in.mp4", "-map", "0:v:0", "out.mp4"]
            )

    def test_rejects_even_local_file_url_input(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                ["-i", "file:///C:/local/in.mp4", "-map", "0:v:0", "out.mp4"]
            )

    def test_rejects_protocol_allow_or_deny_list_overrides(self) -> None:
        for option in ("-protocol_whitelist", "-protocol_blacklist"):
            with self.subTest(option=option), self.assertRaises(
                safe_ffmpeg.SafetyError
            ):
                safe_ffmpeg.validate_arguments(
                    [option, "file,http", "-i", "in.mp4", "-map", "0:v:0", "out.mp4"]
                )

    def test_rejects_network_input_protocol(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                ["-i", "https://example.test/in.mp4", "-map", "0:v:0", "out.mp4"]
            )

    def test_network_path_detection(self) -> None:
        self.assertTrue(safe_ffmpeg.is_network_path(r"\\server\share\in.mp4"))
        self.assertFalse(safe_ffmpeg.is_network_path(r"C:\本地\in.mp4"))
        if os.name == "nt":
            self.assertTrue(
                safe_ffmpeg.is_network_path(r"\\?\UNC\server\share\in.mp4")
            )
            self.assertFalse(safe_ffmpeg.is_network_path(r"\\?\C:\本地\in.mp4"))

    def test_requires_main_video_stream(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(["-i", "in.mp4", "out.mp4"])

    def test_main_stream_text_decoy_does_not_satisfy_mapping(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                ["-i", "in.mp4", "-vf", "drawtext=text='[0:v:0]'", "out.mp4"]
            )

    def test_rejects_unbounded_zoompan(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-vf",
                    "zoompan=z=1.2:d=1:s=1280x720",
                    "out.mp4",
                ]
            )

    def test_rejects_zoompan_frame_duplication(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-t",
                    "1",
                    "-vf",
                    "zoompan=z=1.2:d=30:s=1280x720",
                    "out.mp4",
                ]
            )

    def test_accepts_bounded_zoompan_d_one(self) -> None:
        safe_ffmpeg.validate_arguments(
            [
                "-i",
                "in.mp4",
                "-map",
                "0:v:0",
                "-t",
                "1",
                "-vf",
                "trim=duration=1,zoompan=z=1.2:d=1:s=1280x720",
                "out.mp4",
            ]
        )

    def test_each_zoompan_must_have_d_one(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-t",
                    "1",
                    "-vf",
                    "zoompan=z=1.1:d=2,zoompan=z=1.2:d=1",
                    "out.mp4",
                ]
            )

    def test_zoompan_duration_decoy_inside_expression_is_rejected(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-t",
                    "1",
                    "-vf",
                    "zoompan=z='x:d=1:x':d=2",
                    "out.mp4",
                ]
            )

    def test_rejects_frame_mixing_filter(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-vf",
                    "minterpolate=fps=60",
                    "out.mp4",
                ]
            )

    def test_rejects_frame_mixing_filter_with_stream_specifier(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-filter:v:0",
                    "tmix=frames=10",
                    "out.mp4",
                ]
            )

    def test_rejects_audio_frame_mixing_filter(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-af",
                    "afifo",
                    "out.mp4",
                ]
            )

    def test_rejects_audio_filter_with_stream_specifier(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-filter:a:0",
                    "afifo",
                    "out.mp4",
                ]
            )

    def test_rejects_filter_script_options(self) -> None:
        for option in (
            "-filter_script:v:0",
            "-filter_complex_script",
            "-/filter:v:0",
            "-/lavfi",
        ):
            with self.subTest(option=option), self.assertRaises(
                safe_ffmpeg.SafetyError
            ):
                safe_ffmpeg.validate_arguments(
                    ["-i", "in.mp4", "-map", "0:v:0", option, "filters.txt", "out.mp4"]
                )

    def test_zoompan_must_be_bounded_in_its_own_chain(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-filter_complex",
                    "[0:v:0]trim=duration=1[a];[0:v:0]zoompan=d=1[b]",
                    "-map",
                    "[b]",
                    "out.mp4",
                ]
            )

    def test_empty_stream_specifier_cannot_bypass_filter_checks(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-filter:",
                    "minterpolate=fps=60",
                    "out.mp4",
                ]
            )

    def test_other_output_t_does_not_bound_zoompan(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg.validate_arguments(
                [
                    "-i",
                    "in.mp4",
                    "-map",
                    "0:v:0",
                    "-t",
                    "1",
                    "one.mp4",
                    "-map",
                    "0:v:0",
                    "-vf",
                    "zoompan=z=1.2:d=1:s=1280x720",
                    "two.mp4",
                ]
            )

    def test_rejects_manifest_and_external_resource_filters(self) -> None:
        for arguments in (
            ["-f", "concat", "-i", "list.txt", "-map", "0:v:0", "out.mp4"],
            ["-i", "playlist.m3u8", "-map", "0:v:0", "out.mp4"],
            ["-f", "lavfi", "-i", "movie=https\\://example.com/a.mp4", "-vn", "out.wav"],
            ["-i", "in.mp4", "-map", "0:v:0", "-vf", "subtitles=remote.ass", "out.mp4"],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(
                safe_ffmpeg.SafetyError
            ):
                safe_ffmpeg.validate_arguments(arguments)

    def test_command_injects_nostdin_once(self) -> None:
        command = safe_ffmpeg.build_command("ffmpeg", ["-version"])
        self.assertEqual(command[:2], ["ffmpeg", "-nostdin"])
        command = safe_ffmpeg.build_command("ffmpeg", ["-nostdin", "-version"])
        self.assertEqual(command.count("-nostdin"), 1)


class SafeFfmpegRuntimeTests(unittest.TestCase):
    def test_file_sha256_supports_binary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "中文测试.bin"
            path.write_bytes(b"abc")
            self.assertEqual(
                safe_ffmpeg.file_sha256(path),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_memory_probe_returns_sensible_values(self) -> None:
        memory = safe_ffmpeg.get_memory_status()
        self.assertGreater(memory.total_physical, 0)
        self.assertGreaterEqual(memory.available_physical, 0)

    def test_ffmpeg_path_is_required_and_must_be_absolute(self) -> None:
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg._resolve_ffmpeg(None)
        with self.assertRaises(safe_ffmpeg.SafetyError):
            safe_ffmpeg._resolve_ffmpeg("ffmpeg.exe")

    @unittest.skipUnless(os.name == "nt", "Windows 可执行文件扩展名检查")
    def test_windows_rejects_ffmpeg_cmd_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            wrapper = Path(directory) / "ffmpeg.cmd"
            wrapper.write_text("@exit /b 0", encoding="utf-8")
            with self.assertRaises(safe_ffmpeg.SafetyError):
                safe_ffmpeg._resolve_ffmpeg(str(wrapper))

    def test_cli_requires_explicit_ffmpeg_path(self) -> None:
        with self.assertRaises(SystemExit):
            safe_ffmpeg.parse_args(["--diagnose"])

    def test_preflight_rejects_low_memory(self) -> None:
        low = safe_ffmpeg.MemoryStatus(
            total_physical=8 * safe_ffmpeg.GIB,
            available_physical=2 * safe_ffmpeg.GIB,
            commit_limit=16 * safe_ffmpeg.GIB,
            commit_available=12 * safe_ffmpeg.GIB,
        )
        with mock.patch.object(safe_ffmpeg, "get_memory_status", return_value=low):
            with self.assertRaises(safe_ffmpeg.SafetyError) as raised:
                safe_ffmpeg._preflight()
        self.assertEqual(raised.exception.exit_code, safe_ffmpeg.EXIT_RESOURCE_GUARD)

    def test_preflight_probe_failure_maps_to_resource_guard(self) -> None:
        with mock.patch.object(
            safe_ffmpeg, "get_memory_status", side_effect=OSError("probe failed")
        ):
            with self.assertRaises(safe_ffmpeg.SafetyError) as raised:
                safe_ffmpeg._preflight()
        self.assertEqual(raised.exception.exit_code, safe_ffmpeg.EXIT_RESOURCE_GUARD)

    def test_known_crashing_hash_is_rejected(self) -> None:
        digest = next(iter(safe_ffmpeg.KNOWN_CRASHING_FFMPEG_SHA256))
        with mock.patch.object(safe_ffmpeg, "file_sha256", return_value=digest):
            with mock.patch.object(safe_ffmpeg, "_start_guarded_process") as starter:
                with self.assertRaises(safe_ffmpeg.SafetyError) as guarded:
                    safe_ffmpeg.run_guarded("unused.exe", ["-version"])
            with self.assertRaises(safe_ffmpeg.SafetyError) as raised:
                safe_ffmpeg._reject_known_crashing_build("unused.exe")
        starter.assert_not_called()
        self.assertEqual(guarded.exception.exit_code, safe_ffmpeg.EXIT_RESOURCE_GUARD)
        self.assertEqual(raised.exception.exit_code, safe_ffmpeg.EXIT_RESOURCE_GUARD)

    def test_preflight_rejects_low_commit_and_accepts_exact_boundaries(self) -> None:
        low_commit = safe_ffmpeg.MemoryStatus(
            total_physical=16 * safe_ffmpeg.GIB,
            available_physical=4 * safe_ffmpeg.GIB,
            commit_limit=32 * safe_ffmpeg.GIB,
            commit_available=5 * safe_ffmpeg.GIB,
        )
        exact = safe_ffmpeg.MemoryStatus(
            total_physical=16 * safe_ffmpeg.GIB,
            available_physical=3 * safe_ffmpeg.GIB,
            commit_limit=32 * safe_ffmpeg.GIB,
            commit_available=6 * safe_ffmpeg.GIB,
        )
        with mock.patch.object(safe_ffmpeg, "list_ffmpeg_pids", return_value=[]):
            with mock.patch.object(safe_ffmpeg, "get_memory_status", return_value=low_commit):
                with self.assertRaises(safe_ffmpeg.SafetyError) as raised:
                    safe_ffmpeg._preflight()
            self.assertEqual(raised.exception.exit_code, safe_ffmpeg.EXIT_RESOURCE_GUARD)
            with mock.patch.object(safe_ffmpeg, "get_memory_status", return_value=exact):
                self.assertEqual(safe_ffmpeg._preflight(), exact)

    def test_native_child_exit_code_is_preserved(self) -> None:
        process = mock.Mock()
        process.poll.return_value = -1073741819
        process.wait.return_value = -1073741819
        job = mock.Mock()
        healthy = safe_ffmpeg.MemoryStatus(
            total_physical=16 * safe_ffmpeg.GIB,
            available_physical=8 * safe_ffmpeg.GIB,
            commit_limit=32 * safe_ffmpeg.GIB,
            commit_available=16 * safe_ffmpeg.GIB,
        )
        with mock.patch.object(safe_ffmpeg, "_reject_known_crashing_build"):
            with mock.patch.object(safe_ffmpeg, "exclusive_ffmpeg_lock", return_value=nullcontext()):
                with mock.patch.object(safe_ffmpeg, "_preflight", return_value=healthy):
                    with mock.patch.object(
                        safe_ffmpeg,
                        "_start_guarded_process",
                        return_value=(process, job),
                    ):
                        code = safe_ffmpeg.run_guarded("unused.exe", ["-version"])
        self.assertEqual(code, -1073741819)
        job.close.assert_called_once()

    def test_cross_process_lock_rejects_second_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "中文-ffmpeg.lock"
            module_dir = Path(safe_ffmpeg.__file__).resolve().parent
            code = (
                "import sys,time; from pathlib import Path; "
                "sys.path.insert(0, sys.argv[1]); "
                "from safe_ffmpeg import exclusive_ffmpeg_lock; "
                "guard=exclusive_ffmpeg_lock(Path(sys.argv[2])); "
                "guard.__enter__(); print('ready', flush=True); time.sleep(30)"
            )
            child = subprocess.Popen(
                [sys.executable, "-X", "utf8", "-c", code, str(module_dir), str(lock_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "ready")
                with self.assertRaises(safe_ffmpeg.SafetyError) as raised:
                    with safe_ffmpeg.exclusive_ffmpeg_lock(lock_path):
                        self.fail("第二个进程不应取得同一把锁")
                self.assertEqual(
                    raised.exception.exit_code, safe_ffmpeg.EXIT_ALREADY_RUNNING
                )
            finally:
                child.terminate()
                child.wait(timeout=3)
                if child.stdout is not None:
                    child.stdout.close()
                if child.stderr is not None:
                    child.stderr.close()

    def _run_with_fake_process(self, private_probe: object) -> tuple[object, object]:
        process = mock.Mock()
        process.pid = 12345
        process.poll.return_value = None
        job = mock.Mock()
        healthy = safe_ffmpeg.MemoryStatus(
            total_physical=16 * safe_ffmpeg.GIB,
            available_physical=8 * safe_ffmpeg.GIB,
            commit_limit=32 * safe_ffmpeg.GIB,
            commit_available=16 * safe_ffmpeg.GIB,
        )
        patches = (
            mock.patch.object(safe_ffmpeg, "_reject_known_crashing_build"),
            mock.patch.object(safe_ffmpeg, "exclusive_ffmpeg_lock", return_value=nullcontext()),
            mock.patch.object(safe_ffmpeg, "_preflight", return_value=healthy),
            mock.patch.object(
                safe_ffmpeg, "_start_guarded_process", return_value=(process, job)
            ),
            mock.patch.object(
                safe_ffmpeg, "get_process_private_bytes", side_effect=private_probe
            ),
            mock.patch.object(safe_ffmpeg, "_stop_process"),
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5] as stop:
            with self.assertRaises(safe_ffmpeg.SafetyError) as raised:
                safe_ffmpeg.run_guarded("unused.exe", ["-version"])
        self.assertEqual(raised.exception.exit_code, safe_ffmpeg.EXIT_RESOURCE_GUARD)
        self.assertTrue(stop.called)
        self.assertTrue(any(call.kwargs.get("immediate") for call in stop.call_args_list))
        job.close.assert_called_once()
        return process, job

    def test_unreadable_private_memory_fails_closed(self) -> None:
        self._run_with_fake_process(lambda _pid: None)

    def test_monitor_exception_fails_closed(self) -> None:
        self._run_with_fake_process(RuntimeError("probe failed"))

    @unittest.skipUnless(os.name == "nt", "Windows 专用私有内存检查")
    def test_current_process_private_memory_is_readable(self) -> None:
        private_bytes = safe_ffmpeg.get_process_private_bytes(os.getpid())
        self.assertIsNotNone(private_bytes)
        self.assertGreater(private_bytes or 0, 0)

    @unittest.skipUnless(os.name == "nt", "Windows Job Object 专用检查")
    def test_windows_job_has_required_kernel_limits(self) -> None:
        job = safe_ffmpeg.WindowsJob()
        try:
            flags, process_limit, job_limit = job.query_limits()
            self.assertEqual(
                flags & safe_ffmpeg._REQUIRED_JOB_LIMIT_FLAGS,
                safe_ffmpeg._REQUIRED_JOB_LIMIT_FLAGS,
            )
            self.assertEqual(process_limit, 5 * safe_ffmpeg.GIB)
            self.assertEqual(job_limit, 6 * safe_ffmpeg.GIB)
        finally:
            job.close()

    @unittest.skipUnless(os.name == "nt", "Windows Job Object 专用检查")
    def test_suspended_child_is_assigned_before_resume_and_killed_on_close(self) -> None:
        process, job = safe_ffmpeg._start_guarded_process(
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        self.assertIsNotNone(job)
        try:
            self.assertIsNone(process.poll())
            job.close()
            self.assertIsNotNone(process.wait(timeout=3))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            job.close()

    @unittest.skipUnless(os.name == "nt", "Windows Job Object 专用检查")
    def test_assignment_failure_kills_unassigned_suspended_child(self) -> None:
        class FakeProcess:
            pid = 24680
            _handle = 13579

            def __init__(self) -> None:
                self.alive = True
                self.kill_called = False

            def poll(self) -> int | None:
                return None if self.alive else safe_ffmpeg.EXIT_RESOURCE_GUARD

            def wait(self, timeout: float | None = None) -> int:
                if self.alive:
                    raise safe_ffmpeg.subprocess.TimeoutExpired("fake", timeout)
                return safe_ffmpeg.EXIT_RESOURCE_GUARD

            def kill(self) -> None:
                self.kill_called = True
                self.alive = False

        process = FakeProcess()
        job = mock.Mock()
        job.assign.side_effect = safe_ffmpeg.SafetyError("assign failed")
        with mock.patch.object(safe_ffmpeg, "WindowsJob", return_value=job), mock.patch.object(
            safe_ffmpeg.subprocess, "Popen", return_value=process
        ):
            with self.assertRaises(safe_ffmpeg.SafetyError):
                safe_ffmpeg._start_guarded_process([sys.executable, "-c", "pass"])
        self.assertTrue(process.kill_called)
        self.assertFalse(process.alive)
        job.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
