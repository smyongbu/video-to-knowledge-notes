import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


MODULE_PATH = Path(__file__).with_name("resumable_transcribe.py")
SPEC = importlib.util.spec_from_file_location("resumable_transcribe", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def close_loggers(*loggers):
    for logger in loggers:
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)


class ResumableTranscribeTests(unittest.TestCase):
    def test_chunk_plan_prefers_nearby_silence_and_uses_overlap(self):
        boundaries = MODULE.choose_boundaries(700, 300, 45, [287.0, 610.0])
        chunks = MODULE.build_chunks(boundaries, 5)
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0]["core_end"], 287.0)
        self.assertEqual(chunks[0]["end_boundary_source"], "silence")
        self.assertEqual(chunks[1]["extract_start"], 282.0)
        self.assertEqual(chunks[1]["core_end"], 610.0)

    def test_chunk_plan_falls_back_when_no_pause_is_nearby(self):
        boundaries = MODULE.choose_boundaries(700, 300, 45, [])
        self.assertEqual(boundaries[1]["time"], 300.0)
        self.assertEqual(boundaries[1]["source"], "time_fallback")

    def test_atomic_json_is_valid_utf8(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "进度.json"
            MODULE.atomic_json(path, {"状态": "已完成"})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["状态"], "已完成")
            self.assertFalse(list(path.parent.glob("*.tmp")))

    def test_normal_and_error_logs_are_separate_and_correlated(self):
        with tempfile.TemporaryDirectory() as directory:
            normal, error = MODULE.setup_logs(Path(directory), "test-operation")
            normal.info("操作=test-operation 正常事件")
            error.warning("操作=test-operation 可控失败")
            for handler in [*normal.handlers, *error.handlers]:
                handler.flush()
            normal_text = (Path(directory) / "运行.log").read_text(encoding="utf-8")
            error_text = (Path(directory) / "错误.log").read_text(encoding="utf-8")
            self.assertIn("正常事件", normal_text)
            self.assertNotIn("可控失败", normal_text)
            self.assertIn("可控失败", error_text)
            self.assertIn("test-operation", error_text)
            close_loggers(normal, error)

    def test_heartbeat_records_long_operation_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            normal, error = MODULE.setup_logs(Path(directory), "heartbeat-operation")
            heartbeat = MODULE.Heartbeat(normal, "heartbeat-operation", "耗时测试", interval=60)
            heartbeat.logger.info("操作=%s 阶段=%s 心跳 已运行=%d秒", heartbeat.operation_id, heartbeat.stage, 60)
            for handler in normal.handlers:
                handler.flush()
            text = (Path(directory) / "运行.log").read_text(encoding="utf-8")
            self.assertIn("心跳", text)
            self.assertIn("耗时测试", text)
            close_loggers(normal, error)

    def test_silence_detection_routes_ffmpeg_through_guard(self):
        completed = MODULE.subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="silence_start: 10.0\nsilence_end: 11.0",
        )
        with patch.object(MODULE.subprocess, "run", return_value=completed) as runner:
            points = MODULE.detect_silence_points(Path(r"C:\本地\课程.mp4"), r"D:\ffmpeg\ffmpeg.exe", -35, 0.6)
        command = runner.call_args.args[0]
        self.assertTrue(str(command[1]).endswith("safe_ffmpeg.py"))
        self.assertIn("--ffmpeg", command)
        self.assertIn("0:a:0", command)
        self.assertEqual(points, [10.5])

    def test_audio_extraction_routes_ffmpeg_through_guard(self):
        completed = MODULE.subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        chunk = {"extract_start": 12.5, "extract_end": 20.0}
        with tempfile.TemporaryDirectory() as directory:
            wav = Path(directory) / "中文分段.wav"
            with patch.object(MODULE.subprocess, "run", return_value=completed) as runner:
                with patch.object(MODULE.os, "replace") as replacer:
                    MODULE.extract_audio(
                        Path(r"C:\本地素材\中文课程.mp4"),
                        wav,
                        chunk,
                        r"D:\ffmpeg\ffmpeg.exe",
                    )
        command = runner.call_args.args[0]
        self.assertTrue(str(command[1]).endswith("safe_ffmpeg.py"))
        self.assertIn("--ffmpeg", command)
        self.assertIn("0:a:0", command)
        self.assertIn(r"C:\本地素材\中文课程.mp4", command)
        replacer.assert_called_once()

    def test_guard_exit_code_is_preserved(self):
        completed = MODULE.subprocess.CompletedProcess(
            args=[],
            returncode=MODULE.safe_ffmpeg.EXIT_RESOURCE_GUARD,
            stdout="",
            stderr="内存门槛未通过",
        )
        with patch.object(MODULE.subprocess, "run", return_value=completed):
            with self.assertRaises(MODULE.GuardedFfmpegError) as caught:
                MODULE.run_safe_ffmpeg(r"D:\ffmpeg\ffmpeg.exe", ["-version"])
        self.assertEqual(
            caught.exception.returncode,
            MODULE.safe_ffmpeg.EXIT_RESOURCE_GUARD,
        )
        self.assertIn("内存门槛未通过", str(caught.exception))

    def test_binary_preflight_exit_code_is_preserved_by_main(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            video = root / "中文课程.mp4"
            ffmpeg = root / "ffmpeg.exe"
            ffprobe = root / "ffprobe.exe"
            for path in (video, ffmpeg, ffprobe):
                path.write_bytes(b"test")
            args = SimpleNamespace(
                video=video,
                work_dir=root / "中文工作目录",
                model="small",
                language="zh",
                chunk_seconds=300,
                boundary_search_seconds=45,
                silence_min_seconds=0.6,
                silence_noise_db=-35.0,
                overlap_seconds=5,
                keep_audio=True,
                ffmpeg=ffmpeg,
                ffprobe=ffprobe,
            )
            normal = Mock()
            error = Mock()
            blocked = MODULE.safe_ffmpeg.SafetyError(
                "已知崩溃构建", MODULE.safe_ffmpeg.EXIT_RESOURCE_GUARD
            )
            with patch.object(MODULE, "parse_args", return_value=args):
                with patch.object(MODULE, "setup_logs", return_value=(normal, error)):
                    with patch.object(
                        MODULE.safe_ffmpeg,
                        "validate_ffmpeg_binary",
                        side_effect=blocked,
                    ):
                        code = MODULE.main()
        self.assertEqual(code, MODULE.safe_ffmpeg.EXIT_RESOURCE_GUARD)
        error.error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
