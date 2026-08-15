#!/usr/bin/env python3
"""将长视频分段转写，并在每段完成后保存可恢复进度。"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import traceback
import uuid

import safe_ffmpeg


VERSION = "1.2.0"


class GuardedFfmpegError(RuntimeError):
    """保留安全守卫退出码，避免把资源阻断误报成普通失败。"""

    def __init__(self, returncode: int, detail: str) -> None:
        super().__init__(f"受守卫保护的 FFmpeg 退出码 {returncode}：{detail}")
        self.returncode = int(returncode)


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def atomic_json(path: Path, data: object) -> None:
    atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2))


def fingerprint(path: Path) -> dict[str, object]:
    stat = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as source:
        digest.update(source.read(1024 * 1024))
        if stat.st_size > 1024 * 1024:
            source.seek(max(0, stat.st_size - 1024 * 1024))
            digest.update(source.read(1024 * 1024))
    return {
        "path": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "edge_sha256": digest.hexdigest(),
    }


def detect_silence_points(video: Path, ffmpeg: str, noise_db: float, minimum_seconds: float) -> list[float]:
    completed = run_safe_ffmpeg(
        ffmpeg,
        [
            "-hide_banner",
            "-nostats",
            "-i",
            str(video),
            "-map",
            "0:a:0",
            "-vn",
            "-af",
            f"silencedetect=noise={noise_db}dB:d={minimum_seconds}",
            "-f",
            "null",
            os.devnull,
        ],
    )
    points = []
    silence_start = None
    for match in re.finditer(r"silence_(start|end):\s*([0-9.]+)", completed.stderr):
        kind, value = match.group(1), float(match.group(2))
        if kind == "start":
            silence_start = value
        elif silence_start is not None and value - silence_start >= minimum_seconds:
            points.append((silence_start + value) / 2)
            silence_start = None
    return points


def choose_boundaries(
    duration: float,
    target_seconds: int,
    search_seconds: int,
    silence_points: list[float],
) -> list[dict[str, object]]:
    boundaries = [{"time": 0.0, "source": "start"}]
    current = 0.0
    minimum_tail = max(60.0, target_seconds * 0.25)
    minimum_span = max(30.0, target_seconds * 0.4)
    while duration - current > target_seconds + minimum_tail:
        target = current + target_seconds
        candidates = [
            point
            for point in silence_points
            if target - search_seconds <= point <= target + search_seconds
            and point - current >= minimum_span
            and duration - point >= minimum_tail
        ]
        if candidates:
            boundary = min(candidates, key=lambda point: abs(point - target))
            source = "silence"
        else:
            boundary = target
            source = "time_fallback"
        boundaries.append({"time": boundary, "source": source})
        current = boundary
    boundaries.append({"time": duration, "source": "end"})
    return boundaries


def build_chunks(boundaries: list[dict[str, object]], overlap_seconds: int) -> list[dict[str, object]]:
    chunks = []
    duration = float(boundaries[-1]["time"])
    for index in range(len(boundaries) - 1):
        core_start = float(boundaries[index]["time"])
        core_end = float(boundaries[index + 1]["time"])
        extract_start = max(0.0, core_start - (overlap_seconds if index else 0))
        extract_end = min(duration, core_end + (overlap_seconds if index < len(boundaries) - 2 else 0))
        chunks.append(
            {
                "index": index,
                "status": "pending",
                "core_start": core_start,
                "core_end": core_end,
                "extract_start": extract_start,
                "extract_end": extract_end,
                "end_boundary_source": boundaries[index + 1]["source"],
            }
        )
    return chunks


def setup_logs(log_dir: Path, operation_id: str) -> tuple[logging.Logger, logging.Logger]:
    log_dir.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    normal = logging.getLogger(f"normal.{operation_id}")
    error = logging.getLogger(f"error.{operation_id}")
    normal.setLevel(logging.INFO)
    error.setLevel(logging.WARNING)
    normal.propagate = False
    error.propagate = False

    for logger, filename in ((normal, "运行.log"), (error, "错误.log")):
        logger.handlers.clear()
        handler = RotatingFileHandler(
            log_dir / filename,
            maxBytes=2 * 1024 * 1024,
            backupCount=1,
            encoding="utf-8",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return normal, error


class Heartbeat:
    def __init__(self, logger: logging.Logger, operation_id: str, stage: str, interval: int = 30):
        self.logger = logger
        self.operation_id = operation_id
        self.stage = stage
        self.interval = interval
        self.started = time.monotonic()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self.stop_event.wait(self.interval):
            elapsed = time.monotonic() - self.started
            self.logger.info("操作=%s 阶段=%s 心跳 已运行=%.0f秒", self.operation_id, self.stage, elapsed)

    def __enter__(self) -> "Heartbeat":
        self.thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)


def run_safe_ffmpeg(ffmpeg: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    guard = Path(__file__).with_name("safe_ffmpeg.py")
    if not guard.is_file():
        raise RuntimeError(f"找不到 FFmpeg 安全守卫：{guard}")
    completed = subprocess.run(
        [sys.executable, str(guard), "--ffmpeg", ffmpeg, "--", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise GuardedFfmpegError(completed.returncode, detail)
    return completed


def probe_duration(video: Path, ffprobe: str) -> float:
    completed = subprocess.run(
        [ffprobe, "-v", "error", "-show_entries", "format=duration", "-of", "default=nw=1:nk=1", str(video)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode:
        raise RuntimeError(f"无法读取视频时长：{completed.stderr.strip()}")
    return float(completed.stdout.strip())


def probe_version_line(program: str) -> str:
    completed = subprocess.run(
        [program, "-version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode:
        raise RuntimeError(
            f"无法读取 {Path(program).name} 版本：{completed.stderr.strip()}"
        )
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"{Path(program).name} 没有返回可记录的版本信息。")
    return lines[0]


def load_or_create_manifest(
    manifest_path: Path,
    video: Path,
    duration: float,
    configuration: dict[str, object],
    chunks: list[dict[str, object]],
) -> dict[str, object]:
    current_fingerprint = fingerprint(video)
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("source") != current_fingerprint:
            raise RuntimeError("源视频已发生变化，不能沿用旧断点；请改用新的工作目录。")
        if manifest.get("configuration") != configuration:
            raise RuntimeError("转写配置与现有断点不同；请沿用原配置或改用新的工作目录。")
        return manifest

    manifest = {
        "schema_version": 1,
        "program_version": VERSION,
        "source": current_fingerprint,
        "duration": duration,
        "configuration": configuration,
        "status": "running",
        "chunks": chunks,
    }
    atomic_json(manifest_path, manifest)
    return manifest


def extract_audio(video: Path, wav_path: Path, chunk: dict[str, object], ffmpeg: str) -> None:
    temporary = wav_path.with_suffix(".part.wav")
    temporary.unlink(missing_ok=True)
    duration = float(chunk["extract_end"]) - float(chunk["extract_start"])
    try:
        run_safe_ffmpeg(
            ffmpeg,
            [
                "-hide_banner",
                "-loglevel",
                "error",
                "-ss",
                f"{float(chunk['extract_start']):.3f}",
                "-i",
                str(video),
                "-map",
                "0:a:0",
                "-t",
                f"{duration:.3f}",
                "-vn",
                "-ac",
                "1",
                "-ar",
                "16000",
                "-c:a",
                "pcm_s16le",
                "-y",
                str(temporary),
            ]
        )
        os.replace(temporary, wav_path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def transcribe_chunk(model: object, wav_path: Path, chunk: dict[str, object], language: str) -> dict[str, object]:
    segments, info = model.transcribe(
        str(wav_path),
        language=language,
        beam_size=5,
        vad_filter=True,
        word_timestamps=True,
        condition_on_previous_text=True,
    )
    base = float(chunk["extract_start"])
    core_start = float(chunk["core_start"])
    core_end = float(chunk["core_end"])
    items = []
    for segment in segments:
        absolute_start = base + float(segment.start)
        absolute_end = base + float(segment.end)
        midpoint = (absolute_start + absolute_end) / 2
        if midpoint < core_start or midpoint >= core_end:
            continue
        items.append(
            {
                "start": absolute_start,
                "end": absolute_end,
                "text": segment.text.strip(),
                "words": [
                    {
                        "start": None if word.start is None else base + float(word.start),
                        "end": None if word.end is None else base + float(word.end),
                        "word": word.word,
                    }
                    for word in (segment.words or [])
                ],
            }
        )
    return {"language": info.language, "segments": items}


def rebuild_outputs(work_dir: Path, manifest: dict[str, object]) -> None:
    all_segments = []
    for chunk in manifest["chunks"]:
        if chunk["status"] != "completed":
            continue
        path = work_dir / "chunks" / f"chunk-{int(chunk['index']):04d}.json"
        if path.exists():
            all_segments.extend(json.loads(path.read_text(encoding="utf-8"))["segments"])
    all_segments.sort(key=lambda item: item["start"])
    text_lines = [f"[{item['start']:8.2f} --> {item['end']:8.2f}] {item['text']}" for item in all_segments]
    atomic_json(work_dir / "transcript.partial.json", {"segments": all_segments})
    atomic_write(work_dir / "transcript.partial.txt", "\n".join(text_lines))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="分段、可续跑地转写长视频，并逐段保存结果。")
    parser.add_argument("video", type=Path, help="源视频路径")
    parser.add_argument("--work-dir", type=Path, required=True, help="断点、转写稿和日志目录")
    parser.add_argument("--model", default="small", help="faster-whisper 模型名称，默认 small")
    parser.add_argument("--language", default="zh", help="语言代码，默认 zh")
    parser.add_argument("--chunk-seconds", type=int, default=300, help="目标分段时长，默认 300 秒；不是硬切点")
    parser.add_argument("--boundary-search-seconds", type=int, default=45, help="在目标点前后搜索自然停顿的范围，默认 45 秒")
    parser.add_argument("--silence-min-seconds", type=float, default=0.6, help="可作为边界的最短静音，默认 0.6 秒")
    parser.add_argument("--silence-noise-db", type=float, default=-35.0, help="静音检测阈值，默认 -35 dB")
    parser.add_argument("--overlap-seconds", type=int, default=5, help="分段边界重叠时长，默认 5 秒")
    parser.add_argument("--keep-audio", action="store_true", help="完成后保留临时 WAV 分段")
    parser.add_argument("--ffmpeg", type=Path, required=True, help="可信 FFmpeg 的绝对路径")
    parser.add_argument("--ffprobe", type=Path, required=True, help="与 FFmpeg 同发行目录的 ffprobe 绝对路径")
    return parser.parse_args()


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = parse_args()
    operation_id = uuid.uuid4().hex[:12]
    work_dir = args.work_dir.resolve()
    if safe_ffmpeg.is_network_path(work_dir):
        print(
            "转写工作目录位于网络共享；请改用本地稳定工作目录，完成后再复制成品。",
            file=sys.stderr,
        )
        return safe_ffmpeg.EXIT_USAGE
    normal, error = setup_logs(work_dir / "logs", operation_id)
    manifest_path = work_dir / "progress.json"
    started = time.monotonic()
    normal.info("操作=%s 启动 版本=%s Python=%s", operation_id, VERSION, sys.version.split()[0])
    try:
        video = args.video.resolve(strict=True)
        if (
            args.chunk_seconds < 30
            or args.boundary_search_seconds < 0
            or args.silence_min_seconds <= 0
            or args.overlap_seconds < 0
            or args.overlap_seconds * 2 >= args.chunk_seconds
        ):
            raise ValueError("分段参数无效：目标时长至少 30 秒，搜索范围不可为负，静音时长须为正，重叠须小于目标时长的一半。")
        if safe_ffmpeg.is_network_path(video):
            raise RuntimeError("源视频位于网络共享；请先复制到本地稳定工作目录并核对 SHA-256。")
        ffmpeg = safe_ffmpeg.validate_ffmpeg_binary(str(args.ffmpeg))
        if not args.ffprobe.is_absolute() or safe_ffmpeg.is_network_path(args.ffprobe):
            raise safe_ffmpeg.SafetyError(
                "ffprobe 必须是本地磁盘上的绝对路径；禁止从 PATH 或网络共享启动。"
            )
        ffprobe_path = args.ffprobe.resolve(strict=True)
        expected_ffprobe = "ffprobe.exe" if os.name == "nt" else "ffprobe"
        if not ffprobe_path.is_file() or ffprobe_path.name.lower() != expected_ffprobe:
            raise safe_ffmpeg.SafetyError(
                f"--ffprobe 必须明确指向名为 {expected_ffprobe} 的可执行文件。"
            )
        if safe_ffmpeg.is_network_path(ffprobe_path):
            raise safe_ffmpeg.SafetyError("ffprobe 解析后的真实位置位于网络共享；拒绝启动。")
        ffprobe = str(ffprobe_path)
        if Path(ffmpeg).parent.resolve() != Path(ffprobe).parent.resolve():
            raise RuntimeError("ffmpeg 与 ffprobe 不在同一发行目录，拒绝混用版本。")

        work_dir.mkdir(parents=True, exist_ok=True)
        ffmpeg_version_result = run_safe_ffmpeg(ffmpeg, ["-version"])
        ffmpeg_version_lines = [
            line.strip()
            for line in (ffmpeg_version_result.stdout or ffmpeg_version_result.stderr).splitlines()
            if line.strip()
        ]
        if not ffmpeg_version_lines:
            raise RuntimeError("ffmpeg 没有返回可记录的版本信息。")
        ffmpeg_version = ffmpeg_version_lines[0]
        ffprobe_version = probe_version_line(ffprobe)
        normal.info(
            "操作=%s FFmpeg=%s FFprobe=%s",
            operation_id,
            ffmpeg_version,
            ffprobe_version,
        )
        duration = probe_duration(video, ffprobe)
        configuration = {
            "chunk_seconds": args.chunk_seconds,
            "boundary_search_seconds": args.boundary_search_seconds,
            "silence_min_seconds": args.silence_min_seconds,
            "silence_noise_db": args.silence_noise_db,
            "overlap_seconds": args.overlap_seconds,
            "model": args.model,
            "language": args.language,
            "ffmpeg_path": str(Path(ffmpeg).resolve()),
            "ffmpeg_sha256": safe_ffmpeg.file_sha256(ffmpeg),
            "ffmpeg_version": ffmpeg_version,
            "ffprobe_path": str(Path(ffprobe).resolve()),
            "ffprobe_sha256": safe_ffmpeg.file_sha256(ffprobe),
            "ffprobe_version": ffprobe_version,
        }
        silence_points = detect_silence_points(video, ffmpeg, args.silence_noise_db, args.silence_min_seconds)
        boundaries = choose_boundaries(duration, args.chunk_seconds, args.boundary_search_seconds, silence_points)
        chunks = build_chunks(boundaries, args.overlap_seconds)
        manifest = load_or_create_manifest(
            manifest_path,
            video,
            duration,
            configuration,
            chunks,
        )
        pending = [chunk for chunk in manifest["chunks"] if chunk["status"] != "completed"]
        silence_boundaries = sum(1 for chunk in manifest["chunks"] if chunk.get("end_boundary_source") == "silence")
        fallback_boundaries = sum(1 for chunk in manifest["chunks"] if chunk.get("end_boundary_source") == "time_fallback")
        normal.info(
            "操作=%s 视频时长=%.2f秒 总分段=%d 待处理=%d 自然停顿边界=%d 时间回退边界=%d",
            operation_id,
            duration,
            len(manifest["chunks"]),
            len(pending),
            silence_boundaries,
            fallback_boundaries,
        )

        if pending:
            try:
                from faster_whisper import WhisperModel
            except ImportError as exc:
                raise RuntimeError("缺少 faster-whisper，请在独立虚拟环境中安装 requirements.txt。") from exc
            with Heartbeat(normal, operation_id, "加载语音模型"):
                model = WhisperModel(args.model, device="cpu", compute_type="int8")
        else:
            model = None

        audio_dir = work_dir / "audio"
        chunks_dir = work_dir / "chunks"
        audio_dir.mkdir(exist_ok=True)
        chunks_dir.mkdir(exist_ok=True)
        for chunk in pending:
            index = int(chunk["index"])
            chunk_started = time.monotonic()
            wav_path = audio_dir / f"chunk-{index:04d}.wav"
            result_path = chunks_dir / f"chunk-{index:04d}.json"
            normal.info("操作=%s 分段=%d/%d 开始", operation_id, index + 1, len(manifest["chunks"]))
            if not wav_path.exists():
                extract_audio(video, wav_path, chunk, ffmpeg)
            with Heartbeat(normal, operation_id, f"转写分段 {index + 1}/{len(manifest['chunks'])}"):
                result = transcribe_chunk(model, wav_path, chunk, args.language)
            atomic_json(result_path, result)
            chunk["status"] = "completed"
            chunk["segment_count"] = len(result["segments"])
            chunk["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            atomic_json(manifest_path, manifest)
            rebuild_outputs(work_dir, manifest)
            if not args.keep_audio:
                wav_path.unlink(missing_ok=True)
            normal.info(
                "操作=%s 分段=%d/%d 完成 句段=%d 耗时=%.1f秒",
                operation_id,
                index + 1,
                len(manifest["chunks"]),
                len(result["segments"]),
                time.monotonic() - chunk_started,
            )

        manifest["status"] = "completed"
        manifest["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        atomic_json(manifest_path, manifest)
        partial_json = work_dir / "transcript.partial.json"
        partial_txt = work_dir / "transcript.partial.txt"
        if partial_json.exists():
            os.replace(partial_json, work_dir / "transcript.json")
        if partial_txt.exists():
            os.replace(partial_txt, work_dir / "transcript.txt")
        normal.info("操作=%s 全部完成 总耗时=%.1f秒", operation_id, time.monotonic() - started)
        print(f"转写完成：{work_dir / 'transcript.txt'}")
        return 0
    except KeyboardInterrupt:
        error.warning("操作=%s 用户或执行环境中断；已完成分段保留，可用同一命令续跑。", operation_id)
        print("转写已中断；已完成的分段和进度仍保留，可用同一命令续跑。", file=sys.stderr)
        return 130
    except GuardedFfmpegError as exc:
        error.error(
            "操作=%s FFmpeg安全守卫阻断 退出码=%d 消息=%s\n%s",
            operation_id,
            exc.returncode,
            exc,
            traceback.format_exc(),
        )
        print(f"转写未启动或已安全停止：{exc}；详见 {work_dir / 'logs' / '错误.log'}", file=sys.stderr)
        return exc.returncode
    except safe_ffmpeg.SafetyError as exc:
        error.error(
            "操作=%s FFmpeg二进制安全预检阻断 退出码=%d 消息=%s\n%s",
            operation_id,
            exc.exit_code,
            exc,
            traceback.format_exc(),
        )
        print(f"转写未启动：{exc}；详见 {work_dir / 'logs' / '错误.log'}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:
        error.error(
            "操作=%s 失败 类型=%s 消息=%s\n%s",
            operation_id,
            type(exc).__name__,
            exc,
            traceback.format_exc(),
        )
        print(f"转写失败：{exc}；详见 {work_dir / 'logs' / '错误.log'}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
