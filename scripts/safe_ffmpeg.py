#!/usr/bin/env python3
"""为视频笔记任务安全、串行地启动 FFmpeg。

该脚本只使用 Python 标准库，重点防止多实例并发、低内存启动和
单个 FFmpeg 进程的私有提交内存失控。Windows 上会把暂停状态的
子进程先加入带内核硬限制的 Job Object，再恢复执行；不修改父进程
或系统的全局错误报告设置，同时保留退出码和错误输出。
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence


GIB = 1024**3
MIB = 1024**2
MIN_AVAILABLE_PHYSICAL = 3 * GIB
MIN_COMMIT_HEADROOM = 6 * GIB
MAX_FFMPEG_PRIVATE = 5 * GIB
SOFT_STOP_FFMPEG_PRIVATE = 9 * GIB // 2
MAX_FFMPEG_JOB_MEMORY = 6 * GIB
RUNTIME_MIN_AVAILABLE_PHYSICAL = 512 * MIB
RUNTIME_MIN_COMMIT_HEADROOM = 2 * GIB
POLL_SECONDS = 1.0
LOCK_PATH = Path(tempfile.gettempdir()) / "codex-video-to-knowledge-notes-ffmpeg.lock"
KNOWN_CRASHING_FFMPEG_SHA256 = {
    "3da772e83fe1771b6af07b09d3c11b8cfc6f1ff4d498747ece4e70d3000b782b"
}

EXIT_USAGE = 64
EXIT_ALREADY_RUNNING = 73
EXIT_RESOURCE_GUARD = 75


class SafetyError(RuntimeError):
    def __init__(self, message: str, exit_code: int = EXIT_USAGE) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class MemoryStatus:
    total_physical: int
    available_physical: int
    commit_limit: int | None
    commit_available: int | None


def _configure_utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def _gib(value: int | None) -> str:
    if value is None:
        return "未知"
    return f"{value / GIB:.2f} GiB"


def _log(level: str, message: str) -> None:
    target = sys.stderr if level in {"警告", "错误"} else sys.stdout
    print(f"[安全 FFmpeg][{level}] {message}", file=target, flush=True)


if os.name == "nt":
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)

    class _MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    class _PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _MAX_PATH = 260
    _ULONG_PTR = wintypes.WPARAM

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", _ULONG_PTR),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * _MAX_PATH),
        ]

    class _THREADENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ThreadID", wintypes.DWORD),
            ("th32OwnerProcessID", wintypes.DWORD),
            ("tpBasePri", wintypes.LONG),
            ("tpDeltaPri", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
        ]

    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    _JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
    _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _REQUIRED_JOB_LIMIT_FLAGS = (
        _JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | _JOB_OBJECT_LIMIT_JOB_MEMORY
        | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    _CREATE_SUSPENDED = 0x00000004
    _TH32CS_SNAPTHREAD = 0x00000004
    _THREAD_SUSPEND_RESUME = 0x0002
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    _kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _kernel32.SetInformationJobObject.restype = wintypes.BOOL
    _kernel32.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    _kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateJobObject.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Process32FirstW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_PROCESSENTRY32W),
    ]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_PROCESSENTRY32W),
    ]
    _kernel32.Process32NextW.restype = wintypes.BOOL
    _kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _kernel32.Thread32First.restype = wintypes.BOOL
    _kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_THREADENTRY32)]
    _kernel32.Thread32Next.restype = wintypes.BOOL
    _kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenThread.restype = wintypes.HANDLE
    _kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    _kernel32.ResumeThread.restype = wintypes.DWORD
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_PROCESS_MEMORY_COUNTERS_EX),
        wintypes.DWORD,
    ]
    _psapi.GetProcessMemoryInfo.restype = wintypes.BOOL


    class WindowsJob:
        """将 FFmpeg 限制在不可逃逸的 Windows Job Object 中。"""

        def __init__(self) -> None:
            if ctypes.sizeof(ctypes.c_void_p) < 8:
                raise SafetyError(
                    "5 GiB 内核内存上限需要 64 位 Python；当前运行时不安全，拒绝启动。",
                    EXIT_RESOURCE_GUARD,
                )
            self.handle = _kernel32.CreateJobObjectW(None, None)
            if not self.handle:
                raise SafetyError(
                    f"无法创建 Windows 内存保护 Job：{ctypes.WinError(ctypes.get_last_error())}",
                    EXIT_RESOURCE_GUARD,
                )
            try:
                limits = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
                limits.BasicLimitInformation.LimitFlags = _REQUIRED_JOB_LIMIT_FLAGS
                limits.ProcessMemoryLimit = MAX_FFMPEG_PRIVATE
                limits.JobMemoryLimit = MAX_FFMPEG_JOB_MEMORY
                if not _kernel32.SetInformationJobObject(
                    self.handle,
                    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    ctypes.byref(limits),
                    ctypes.sizeof(limits),
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
            except Exception as exc:
                self.close()
                raise SafetyError(
                    f"无法配置 Windows 内核内存保护：{exc}",
                    EXIT_RESOURCE_GUARD,
                ) from exc

        def assign(self, process_handle: int) -> None:
            if not self.handle or not _kernel32.AssignProcessToJobObject(
                self.handle, wintypes.HANDLE(process_handle)
            ):
                raise SafetyError(
                    f"无法在运行前将 FFmpeg 加入 Windows 内存保护 Job："
                    f"{ctypes.WinError(ctypes.get_last_error())}",
                    EXIT_RESOURCE_GUARD,
                )

        def terminate(self, exit_code: int = EXIT_RESOURCE_GUARD) -> None:
            if self.handle and not _kernel32.TerminateJobObject(self.handle, exit_code):
                error = ctypes.get_last_error()
                if error:
                    raise ctypes.WinError(error)

        def query_limits(self) -> tuple[int, int, int]:
            limits = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            returned = wintypes.DWORD()
            if not self.handle or not _kernel32.QueryInformationJobObject(
                self.handle,
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
                ctypes.byref(returned),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            return (
                int(limits.BasicLimitInformation.LimitFlags),
                int(limits.ProcessMemoryLimit),
                int(limits.JobMemoryLimit),
            )

        def close(self) -> None:
            handle, self.handle = self.handle, None
            if handle:
                _kernel32.CloseHandle(handle)

        def __del__(self) -> None:
            try:
                self.close()
            except Exception:
                pass

else:
    WindowsJob = None  # type: ignore[misc, assignment]


def get_memory_status() -> MemoryStatus:
    if os.name == "nt":
        status = _MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(status)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise ctypes.WinError()
        return MemoryStatus(
            total_physical=int(status.ullTotalPhys),
            available_physical=int(status.ullAvailPhys),
            commit_limit=int(status.ullTotalPageFile),
            commit_available=int(status.ullAvailPageFile),
        )

    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        values: dict[str, int] = {}
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            key, _, raw = line.partition(":")
            match = re.search(r"\d+", raw)
            if match:
                values[key] = int(match.group()) * 1024
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", values.get("MemFree", 0))
        commit_limit = values.get("CommitLimit")
        committed = values.get("Committed_AS")
        commit_available = None
        if commit_limit is not None and committed is not None:
            commit_available = max(0, commit_limit - committed)
        return MemoryStatus(total, available, commit_limit, commit_available)

    raise SafetyError("当前系统不支持可靠的内存预检，拒绝绕过安全门槛。")


def get_process_private_bytes(pid: int) -> int | None:
    if os.name != "nt":
        status_path = Path(f"/proc/{pid}/status")
        if not status_path.exists():
            return None
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("VmData:"):
                match = re.search(r"\d+", line)
                return int(match.group()) * 1024 if match else None
        return None

    process_query_information = 0x0400
    process_vm_read = 0x0010
    handle = _kernel32.OpenProcess(
        process_query_information | process_vm_read, False, pid
    )
    if not handle:
        return None
    try:
        counters = _PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(counters)
        ok = _psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(counters), ctypes.sizeof(counters)
        )
        return int(counters.PrivateUsage) if ok else None
    finally:
        _kernel32.CloseHandle(handle)


def list_ffmpeg_pids() -> list[int]:
    if os.name != "nt":
        return []

    kernel32 = _kernel32
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    invalid_handle = ctypes.c_void_p(-1).value
    if snapshot == invalid_handle:
        raise ctypes.WinError()

    pids: list[int] = []
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ctypes.set_last_error(0)
        has_entry = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        if not has_entry:
            error = ctypes.get_last_error()
            if error != 18:  # ERROR_NO_MORE_FILES
                raise ctypes.WinError(error)
        while has_entry:
            if entry.szExeFile.lower() == "ffmpeg.exe":
                pids.append(int(entry.th32ProcessID))
            ctypes.set_last_error(0)
            has_entry = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
            if not has_entry:
                error = ctypes.get_last_error()
                if error not in {0, 18}:  # 正常枚举结束或 ERROR_NO_MORE_FILES
                    raise ctypes.WinError(error)
    finally:
        kernel32.CloseHandle(snapshot)
    return pids


@contextmanager
def exclusive_ffmpeg_lock(path: Path = LOCK_PATH) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)

        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise SafetyError(
                    "已有另一个受控 FFmpeg 任务正在运行；本次任务未启动。",
                    EXIT_ALREADY_RUNNING,
                ) from exc
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise SafetyError(
                    "已有另一个受控 FFmpeg 任务正在运行；本次任务未启动。",
                    EXIT_ALREADY_RUNNING,
                ) from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


def _filter_graphs(arguments: Sequence[str]) -> list[str]:
    values: list[str] = []
    for index, value in enumerate(arguments[:-1]):
        option = value.lower()
        if (
            option in {"-filter", "-filter_complex", "-lavfi"}
            or re.fullmatch(r"-(?:vf|af)(?::[^\s]*)?", option)
            or re.fullmatch(r"-filter(?::[^\s]*)+", option)
        ):
            values.append(arguments[index + 1])
    return values


def _filter_values(arguments: Sequence[str]) -> str:
    return "\n".join(_filter_graphs(arguments)).lower()


def _split_filter_text(text: str, separators: set[str]) -> list[str]:
    """按未转义、未被引号包围的指定分隔符拆分文本。"""

    parts: list[str] = []
    buffer: list[str] = []
    quote: str | None = None
    escaped = False
    for character in text:
        if escaped:
            buffer.append(character)
            escaped = False
            continue
        if character == "\\":
            buffer.append(character)
            escaped = True
            continue
        if quote:
            buffer.append(character)
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            buffer.append(character)
            continue
        if character in separators:
            parts.append("".join(buffer).strip())
            buffer.clear()
            continue
        buffer.append(character)
    parts.append("".join(buffer).strip())
    return [part for part in parts if part]


def _filter_nodes(graph: str) -> list[str]:
    """拆分一个滤镜图中的节点。"""

    return _split_filter_text(graph, {",", ";"})


def _filter_chains(graph: str) -> list[list[str]]:
    """按分号拆成独立链，再按逗号拆出同一链内的节点。"""

    chains: list[list[str]] = []
    for chain in _split_filter_text(graph, {";"}):
        nodes = _split_filter_text(chain, {","})
        if nodes:
            chains.append(nodes)
    return chains


def _filter_name_and_options(node: str) -> tuple[str, str]:
    without_labels = re.sub(r"^(?:\s*\[[^\]]+\])+\s*", "", node)
    without_labels = re.sub(r"(?:\s*\[[^\]]+\])+\s*$", "", without_labels)
    name, separator, options = without_labels.partition("=")
    return name.strip().lower(), options.strip() if separator else ""


def _zoompan_has_safe_duration(options: str) -> bool:
    durations: list[str] = []
    for field in _split_filter_text(options, {":"}):
        key, separator, value = field.partition("=")
        if separator and key.strip().lower() == "d":
            durations.append(value.strip())
    return len(durations) == 1 and durations[0] == "1"


def is_network_path(value: str | Path) -> bool:
    text = str(value)
    if os.name == "nt":
        lowered = text.lower()
        if lowered.startswith("\\\\?\\unc\\"):
            return True
        extended_drive = re.match(r"^\\\\\?\\([A-Za-z]:[\\/])", text)
        if extended_drive:
            drive_remote = 4
            return ctypes.windll.kernel32.GetDriveTypeW(extended_drive.group(1)) == drive_remote
    if text.startswith("\\\\") or text.startswith("//"):
        return True
    if os.name == "nt" and re.match(r"^[A-Za-z]:[\\/]", text):
        root = text[:3]
        drive_remote = 4
        return ctypes.windll.kernel32.GetDriveTypeW(root) == drive_remote
    return False


_NO_VALUE_OPTIONS = {
    "-accurate_seek",
    "-an",
    "-autoscale",
    "-benchmark",
    "-benchmark_all",
    "-bitexact",
    "-copyinkf",
    "-copyts",
    "-dn",
    "-hide_banner",
    "-n",
    "-noaccurate_seek",
    "-noautorotate",
    "-noautoscale",
    "-nostats",
    "-nostdin",
    "-shortest",
    "-sn",
    "-start_at_zero",
    "-stats",
    "-version",
    "-vn",
    "-xerror",
    "-y",
}

_VALUE_OPTIONS = {
    "-ac",
    "-ar",
    "-aspect",
    "-async",
    "-avoid_negative_ts",
    "-copytb",
    "-crf",
    "-filter_complex",
    "-filter_complex_threads",
    "-filter_threads",
    "-f",
    "-fps_mode",
    "-framerate",
    "-g",
    "-i",
    "-itsoffset",
    "-itsscale",
    "-keyint_min",
    "-lavfi",
    "-loglevel",
    "-loop",
    "-map",
    "-map_chapters",
    "-map_metadata",
    "-max_interleave_delta",
    "-max_muxing_queue_size",
    "-movflags",
    "-muxdelay",
    "-muxpreload",
    "-preset",
    "-r",
    "-s",
    "-sc_threshold",
    "-segment_format",
    "-segment_time",
    "-ss",
    "-stats_period",
    "-stream_loop",
    "-t",
    "-threads",
    "-to",
    "-tune",
    "-v",
    "-video_size",
    "-vsync",
}


def _option_takes_value(option: str) -> bool:
    lowered = option.lower()
    if lowered in _VALUE_OPTIONS:
        return True
    return bool(
        re.fullmatch(
            r"-(?:b|bsf|c|codec|compression_level|disposition|filter|frames|level|metadata|pix_fmt|profile|q|tag|vf|af)(?::[^\s]*)?",
            lowered,
        )
    )


def _parse_media_targets(arguments: Sequence[str]) -> tuple[list[str], list[str]]:
    """以失败关闭方式解析 `-i` 输入和位置型输出目标。"""

    inputs: list[str] = []
    outputs: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        lowered = token.lower()
        if lowered == "-i":
            if index + 1 >= len(arguments):
                raise SafetyError("-i 后缺少输入路径。")
            inputs.append(arguments[index + 1])
            index += 2
            continue
        if lowered in _NO_VALUE_OPTIONS:
            index += 1
            continue
        if _option_takes_value(lowered):
            if index + 1 >= len(arguments):
                raise SafetyError(f"{token} 后缺少参数值。")
            index += 2
            continue
        if token.startswith("-"):
            raise SafetyError(
                f"安全守卫尚未登记 FFmpeg 选项 {token}，无法可靠区分输出路径；"
                "请先更新守卫规则，不得绕过。"
            )
        outputs.append(token)
        index += 1
    return inputs, outputs


def _validate_local_target(value: str, role: str) -> None:
    if os.name == "nt" and value.lower() == "nul":
        return
    is_windows_drive = bool(re.match(r"^[A-Za-z]:[\\/]", value))
    is_extended_drive = bool(re.match(r"^\\\\\?\\[A-Za-z]:[\\/]", value))
    protocol = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", value)
    if protocol and not (is_windows_drive or is_extended_drive):
        raise SafetyError(
            f"{role}使用了未获准的 {protocol.group(1)}: 协议：{value}；"
            "只允许本地文件路径。"
        )
    if is_network_path(value):
        raise SafetyError(f"{role}位于网络共享：{value}；必须改用本地稳定工作目录。")
    try:
        resolved = Path(value).resolve(strict=False)
    except OSError as exc:
        raise SafetyError(f"无法解析{role}路径：{value}") from exc
    if is_network_path(resolved):
        raise SafetyError(
            f"{role}解析后位于网络共享：{resolved}；必须改用本地稳定工作目录。"
        )
    parent = resolved.parent
    try:
        resolved_parent = parent.resolve(strict=False)
    except OSError as exc:
        raise SafetyError(f"无法解析{role}父目录：{parent}") from exc
    if is_network_path(resolved_parent):
        raise SafetyError(
            f"{role}父目录解析后位于网络共享：{resolved_parent}；拒绝启动。"
        )


def validate_arguments(arguments: Sequence[str]) -> None:
    if not arguments:
        raise SafetyError("没有提供 FFmpeg 参数。")

    lowered = [value.lower() for value in arguments]
    protocol_controls = sorted(
        option
        for option in lowered
        if option in {"-protocol_whitelist", "-protocol_blacklist"}
    )
    if protocol_controls:
        raise SafetyError(
            "禁止覆盖 FFmpeg 输入协议白名单或黑名单："
            f"{', '.join(protocol_controls)}。"
        )
    filter_script_options = [
        option
        for option in lowered
        if re.fullmatch(r"-filter(?:_complex)?_script(?::[^\s]*)?", option)
        or re.fullmatch(
            r"-/(?:vf|af)(?::[^\s]*)?|-/filter(?::[^\s]*)*|-/filter_complex|-/lavfi",
            option,
        )
    ]
    if filter_script_options:
        raise SafetyError(
            "禁止使用外部 filter script/file；过滤器必须直接写入受检查的命令参数："
            f"{', '.join(filter_script_options)}。"
        )
    realtime_options = {"-re", "-readrate", "-readrate_initial_burst", "-readrate_catchup"}
    used_realtime = sorted(realtime_options.intersection(lowered))
    if used_realtime:
        raise SafetyError(
            f"视频笔记任务禁止使用实时读取参数：{', '.join(used_realtime)}。"
            "完整解码检查应快速运行，1× 目视播放交给播放器。"
        )

    inputs, outputs = _parse_media_targets(arguments)
    for source in inputs:
        _validate_local_target(source, "输入")
    for target in outputs:
        _validate_local_target(target, "输出")

    for source in inputs:
        suffix = Path(source).suffix.lower()
        if suffix in {".m3u", ".m3u8", ".mpd", ".sdp", ".pls", ".ffconcat"}:
            raise SafetyError(
                f"禁止把可间接引用网络资源的清单文件作为输入：{source}。"
                "请先把实际媒体文件完整下载并校验到本地。"
            )
        local_source = Path(source)
        if local_source.is_file():
            try:
                with local_source.open("rb") as stream:
                    header = stream.read(4096).lstrip().lower()
            except OSError as exc:
                raise SafetyError(f"无法安全检查输入文件头：{source}") from exc
            if (
                header.startswith(b"#extm3u")
                or header.startswith(b"ffconcat version")
                or header.startswith(b"<mpd")
            ):
                raise SafetyError(
                    f"输入内容是可间接引用其他资源的媒体清单：{source}；拒绝启动。"
                )

    for index, value in enumerate(arguments[:-1]):
        if value.lower() == "-f" and arguments[index + 1].lower() in {
            "concat",
            "hls",
            "dash",
            "sdp",
            "lavfi",
            "tee",
        }:
            raise SafetyError(
                f"禁止使用 {arguments[index + 1]} 清单/网络型输入格式；"
                "拼接请使用已显式列出的本地输入与 concat 滤镜。"
            )

    filters = _filter_values(arguments)
    forbidden_filters = [
        name
        for name in ("minterpolate", "tmix", "tblend", "xfade", "fifo", "afifo")
        if name in filters
    ]
    if forbidden_filters:
        raise SafetyError(
            "检测到会缓存、混合或补写多帧的高风险滤镜："
            f"{', '.join(forbidden_filters)}。请改用分段裁剪和普通拼接。"
        )

    externally_loaded_filters = []
    for graph in _filter_graphs(arguments):
        for node in _filter_nodes(graph):
            name, _ = _filter_name_and_options(node)
            if name in {"movie", "amovie", "subtitles", "ass", "zmq", "azmq"}:
                externally_loaded_filters.append(name)
    if externally_loaded_filters:
        raise SafetyError(
            "禁止使用会从滤镜图另行加载文件或网络资源的滤镜："
            f"{', '.join(sorted(set(externally_loaded_filters)))}。"
            "所有媒体必须作为已验证的本地 -i 输入显式传入。"
        )

    for graph in _filter_graphs(arguments):
        for chain in _filter_chains(graph):
            chain_has_trim = any(
                _filter_name_and_options(node)[0] == "trim"
                for node in chain
            )
            for node in chain:
                name, options = _filter_name_and_options(node)
                if name != "zoompan":
                    continue
                if not chain_has_trim:
                    raise SafetyError(
                        "每个 zoompan 所在的独立视频滤镜链都必须显式包含 trim；"
                        "不能用其他输出的 -t、-to 或帧数参数代替本链边界。"
                    )
                if not _zoompan_has_safe_duration(options):
                    raise SafetyError(
                        "每个 zoompan 节点都必须单独使用 d=1；禁止用其他节点的 d=1 伪装通过。"
                    )

    if "-hwaccel" in lowered:
        raise SafetyError("本 Skill 的稳定路径禁止自动或显式硬件加速；请使用软件解码与编码。")

    if inputs and "-vn" not in lowered:
        maps = [
            arguments[index + 1]
            for index, value in enumerate(arguments[:-1])
            if value == "-map"
        ]
        explicit_source = any(
            re.fullmatch(r"0:v:0\??", value.lower()) for value in maps
        )
        explicit_source = explicit_source or any(
            re.match(r"^\s*\[0:v:0\]", node, flags=re.IGNORECASE)
            for graph in _filter_graphs(arguments)
            for node in _filter_nodes(graph)
        )
        if not explicit_source:
            raise SafetyError(
                "必须明确选择主视频流 0:v:0；复杂滤镜应显式从 [0:v:0] 取流。"
            )


def build_command(ffmpeg_binary: str, arguments: Sequence[str]) -> list[str]:
    command = [ffmpeg_binary]
    if "-nostdin" not in [value.lower() for value in arguments]:
        command.append("-nostdin")
    command.extend(arguments)
    return command


def _resolve_ffmpeg(value: str | None) -> str:
    if not value:
        raise SafetyError("必须使用 --ffmpeg 指定可信 FFmpeg 的本地绝对路径；禁止从 PATH 自动选择。")
    path = Path(value)
    if not path.is_absolute():
        raise SafetyError("--ffmpeg 必须是本地绝对路径；禁止相对路径或 PATH 名称。")
    if is_network_path(path):
        raise SafetyError("FFmpeg 程序必须位于本地磁盘；禁止从网络共享启动。")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise SafetyError(f"找不到 FFmpeg：{path}") from exc
    if not resolved.is_file():
        raise SafetyError(f"FFmpeg 路径不是文件：{resolved}")
    if is_network_path(resolved):
        raise SafetyError("FFmpeg 解析后的真实位置位于网络共享；拒绝启动。")
    expected = "ffmpeg.exe" if os.name == "nt" else "ffmpeg"
    if resolved.name.lower() != expected:
        raise SafetyError(f"--ffmpeg 必须明确指向名为 {expected} 的可执行文件。")
    return str(resolved)


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_known_crashing_build(ffmpeg_binary: str) -> str:
    digest = file_sha256(ffmpeg_binary)
    if digest.lower() in KNOWN_CRASHING_FFMPEG_SHA256:
        raise SafetyError(
            "当前 FFmpeg 是已在同一代码位置重复崩溃的 2025-07-12 Git 快照，"
            "安全守卫拒绝启动。请先经用户同意更换可信稳定版，并保留旧版回滚。",
            EXIT_RESOURCE_GUARD,
        )
    return digest


def validate_ffmpeg_binary(ffmpeg_binary: str) -> str:
    """解析并校验 FFmpeg；上层脚本必须在启动 ffprobe 前调用。"""

    resolved = _resolve_ffmpeg(ffmpeg_binary)
    _reject_known_crashing_build(resolved)
    return resolved


def _preflight() -> MemoryStatus:
    try:
        status = get_memory_status()
    except Exception as exc:
        raise SafetyError(
            f"无法完成启动前内存安全检查：{exc}", EXIT_RESOURCE_GUARD
        ) from exc
    _log(
        "信息",
        "启动前内存："
        f"可用物理内存 {_gib(status.available_physical)}；"
        f"可用提交额度 {_gib(status.commit_available)}。",
    )
    if status.available_physical < MIN_AVAILABLE_PHYSICAL:
        raise SafetyError(
            "可用物理内存低于 3 GiB，拒绝启动 FFmpeg。请先释放内存后重试。",
            EXIT_RESOURCE_GUARD,
        )
    if (
        status.commit_available is not None
        and status.commit_available < MIN_COMMIT_HEADROOM
    ):
        raise SafetyError(
            "可用提交额度低于 6 GiB，拒绝启动 FFmpeg。请先释放内存后重试。",
            EXIT_RESOURCE_GUARD,
        )
    try:
        pids = list_ffmpeg_pids()
    except Exception as exc:
        raise SafetyError(
            f"无法完成启动前 FFmpeg 并发检查：{exc}", EXIT_RESOURCE_GUARD
        ) from exc
    if pids:
        raise SafetyError(
            f"检测到其他 FFmpeg 进程 {pids}；为避免并发，本次任务未启动。",
            EXIT_ALREADY_RUNNING,
        )
    return status


def _creation_flags(*, suspended: bool = False) -> int:
    if os.name != "nt":
        return 0
    flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    if suspended:
        flags |= _CREATE_SUSPENDED
    return flags


def _resume_suspended_process(pid: int) -> None:
    """恢复刚由 CREATE_SUSPENDED 创建的进程主线程。"""

    if os.name != "nt":
        return
    snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
    if snapshot == _INVALID_HANDLE_VALUE:
        raise ctypes.WinError(ctypes.get_last_error())
    resumed = 0
    entry = _THREADENTRY32()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        has_entry = _kernel32.Thread32First(snapshot, ctypes.byref(entry))
        while has_entry:
            if int(entry.th32OwnerProcessID) == pid:
                thread = _kernel32.OpenThread(
                    _THREAD_SUSPEND_RESUME, False, entry.th32ThreadID
                )
                if not thread:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    previous_count = _kernel32.ResumeThread(thread)
                    if previous_count == 0xFFFFFFFF:
                        raise ctypes.WinError(ctypes.get_last_error())
                    resumed += 1
                finally:
                    _kernel32.CloseHandle(thread)
            has_entry = _kernel32.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        _kernel32.CloseHandle(snapshot)
    if resumed < 1:
        raise SafetyError(
            "找不到暂停的 FFmpeg 主线程；为避免无保护运行，已拒绝启动。",
            EXIT_RESOURCE_GUARD,
        )


def _start_guarded_process(
    command: Sequence[str],
) -> tuple[subprocess.Popen[bytes], WindowsJob | None]:
    if os.name != "nt":
        return subprocess.Popen(command, stdin=subprocess.DEVNULL), None

    # Job 在子进程之前创建。子进程保持暂停，直至内核确认绑定了全部限制。
    job = WindowsJob()
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            creationflags=_creation_flags(suspended=True),
        )
        job.assign(int(process._handle))  # type: ignore[attr-defined]
        _resume_suspended_process(process.pid)
        return process, job
    except BaseException as exc:
        # 进程仍处于暂停状态；任何绑定/恢复失败都必须 fail-closed。
        if process is not None:
            try:
                job.terminate(EXIT_RESOURCE_GUARD)
            except OSError:
                pass
            try:
                process.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
                try:
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            try:
                still_alive = process.poll() is None
            except OSError:
                still_alive = True
            if still_alive:
                try:
                    process.kill()
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        job.close()
        if isinstance(exc, KeyboardInterrupt):
            raise
        if isinstance(exc, SafetyError):
            raise
        raise SafetyError(
            f"Windows 安全 Job 无法完成暂停启动、绑定或恢复：{exc}",
            EXIT_RESOURCE_GUARD,
        ) from exc


def _stop_process(
    process: subprocess.Popen[bytes],
    reason: str,
    job: WindowsJob | None = None,
    *,
    immediate: bool = False,
) -> None:
    _log("错误", reason)
    if immediate and job is not None:
        try:
            job.terminate(EXIT_RESOURCE_GUARD)
            process.wait(timeout=3)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        if process.poll() is not None:
            return
    except OSError:
        pass
    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            process.send_signal(signal.SIGINT)
        process.wait(timeout=8)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    if job is not None:
        try:
            job.terminate(EXIT_RESOURCE_GUARD)
            process.wait(timeout=3)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        process.terminate()
        process.wait(timeout=3)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    process.kill()
    process.wait(timeout=3)


def run_guarded(ffmpeg_binary: str, arguments: Sequence[str]) -> int:
    validate_arguments(arguments)
    _reject_known_crashing_build(ffmpeg_binary)
    command = build_command(ffmpeg_binary, arguments)

    with exclusive_ffmpeg_lock():
        _preflight()
        _log("信息", f"串行启动 FFmpeg：{ffmpeg_binary}")
        process, job = _start_guarded_process(command)
        peak_private = 0
        warned = False
        guard_triggered = False
        try:
            while process.poll() is None:
                private_bytes = get_process_private_bytes(process.pid)
                if private_bytes is None:
                    if process.poll() is not None:
                        break
                    raise SafetyError(
                        "无法读取 FFmpeg 私有内存；监控已失效，为避免失控已终止本段。",
                        EXIT_RESOURCE_GUARD,
                    )
                peak_private = max(peak_private, private_bytes)
                if private_bytes >= 4 * GIB and not warned:
                    warned = True
                    _log("警告", f"FFmpeg 私有内存已达到 {_gib(private_bytes)}。")
                if private_bytes >= SOFT_STOP_FFMPEG_PRIVATE:
                    guard_triggered = True
                    _stop_process(
                        process,
                        "FFmpeg 私有内存达到 4.5 GiB 提前停止线；已停止本段。"
                        "Windows 内核仍设有 5 GiB 不可越过上限。",
                        job,
                    )
                    break

                other_ffmpeg = [
                    pid for pid in list_ffmpeg_pids() if pid != process.pid
                ]
                if other_ffmpeg:
                    guard_triggered = True
                    _stop_process(
                        process,
                        f"运行期间检测到其他 FFmpeg 进程 {other_ffmpeg}；"
                        "已停止本任务以维持严格串行。",
                        job,
                    )
                    break

                memory = get_memory_status()
                commit_low = (
                    memory.commit_available is not None
                    and memory.commit_available < RUNTIME_MIN_COMMIT_HEADROOM
                )
                if (
                    memory.available_physical < RUNTIME_MIN_AVAILABLE_PHYSICAL
                    or commit_low
                ):
                    guard_triggered = True
                    _stop_process(
                        process,
                        "系统运行时内存安全余量不足；已停止本段，防止系统提交额度耗尽。",
                        job,
                    )
                    break
                time.sleep(POLL_SECONDS)
        except KeyboardInterrupt:
            _stop_process(process, "收到中断请求，正在正常停止 FFmpeg。", job)
            raise
        except Exception as exc:
            _stop_process(
                process,
                "FFmpeg 安全监控发生异常；已按 fail-closed 原则立即终止整个 Job。",
                job,
                immediate=True,
            )
            if isinstance(exc, SafetyError):
                raise
            raise SafetyError(
                f"FFmpeg 安全监控失效：{exc}", EXIT_RESOURCE_GUARD
            ) from exc
        finally:
            try:
                try:
                    still_alive = process.poll() is None
                except OSError:
                    still_alive = True
                if still_alive:
                    try:
                        _stop_process(
                            process,
                            "守卫即将退出，但 FFmpeg 仍在运行；已强制终止整个 Job。",
                            job,
                            immediate=True,
                        )
                    except Exception:
                        if job is not None:
                            try:
                                job.terminate(EXIT_RESOURCE_GUARD)
                            except OSError:
                                pass
                        try:
                            process.kill()
                            process.wait(timeout=3)
                        except (OSError, subprocess.TimeoutExpired):
                            pass
            finally:
                if job is not None:
                    job.close()

        return_code = process.wait()
        _log("信息", f"FFmpeg 峰值私有内存：{_gib(peak_private)}。")
        if guard_triggered:
            return EXIT_RESOURCE_GUARD
        if return_code != 0:
            _log("错误", f"FFmpeg 退出码为 {return_code}；本次处理不得判定成功。")
        return int(return_code)


def _diagnose(ffmpeg_binary: str) -> int:
    memory = get_memory_status()
    digest = file_sha256(ffmpeg_binary)
    print(f"FFmpeg: {ffmpeg_binary}")
    print(f"SHA-256: {digest}")
    print(
        "构建状态: "
        + ("已知重复崩溃，禁止生产使用" if digest in KNOWN_CRASHING_FFMPEG_SHA256 else "未列入已知崩溃清单")
    )
    print(f"可用物理内存: {_gib(memory.available_physical)}")
    print(f"可用提交额度: {_gib(memory.commit_available)}")
    print(f"现有 FFmpeg PID: {list_ffmpeg_pids() or '无'}")
    print(f"启动门槛: 物理内存 {_gib(MIN_AVAILABLE_PHYSICAL)}")
    print(f"轮询提前停止线: {_gib(SOFT_STOP_FFMPEG_PRIVATE)}")
    print(f"Windows 内核单进程硬上限: {_gib(MAX_FFMPEG_PRIVATE)}")
    print(f"Windows Job 总内存硬上限: {_gib(MAX_FFMPEG_JOB_MEMORY)}")
    return 0


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="串行、带内存门槛和内存守卫地运行 FFmpeg。"
    )
    parser.add_argument(
        "--ffmpeg",
        required=True,
        help="可信 FFmpeg 可执行文件的本地绝对路径（不会从 PATH 自动选择）。",
    )
    parser.add_argument("--diagnose", action="store_true", help="只显示安全状态，不启动。")
    parser.add_argument("ffmpeg_args", nargs=argparse.REMAINDER)
    namespace = parser.parse_args(argv)
    if namespace.ffmpeg_args[:1] == ["--"]:
        namespace.ffmpeg_args = namespace.ffmpeg_args[1:]
    return namespace


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8_console()
    namespace = parse_args(argv)
    try:
        ffmpeg_binary = _resolve_ffmpeg(namespace.ffmpeg)
        if namespace.diagnose:
            return _diagnose(ffmpeg_binary)
        return run_guarded(ffmpeg_binary, namespace.ffmpeg_args)
    except SafetyError as exc:
        _log("错误", str(exc))
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
