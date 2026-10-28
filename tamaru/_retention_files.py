"""Windows handle-based operations for the dormant retention engine.

There is deliberately no path-based unlink fallback. Unsupported SMB/filesystem
operations fail closed. No production caller instantiates this backend yet.
"""

from __future__ import annotations

from contextlib import contextmanager, ExitStack
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path

from .inventory import path_key, within


class UnsafeRetentionOperation(ValueError):
    pass


class _Info(C.Structure):
    _fields_ = [
        ("attributes", W.DWORD),
        ("created", W.FILETIME),
        ("accessed", W.FILETIME),
        ("modified", W.FILETIME),
        ("volume", W.DWORD),
        ("size_high", W.DWORD),
        ("size_low", W.DWORD),
        ("links", W.DWORD),
        ("index_high", W.DWORD),
        ("index_low", W.DWORD),
    ]


class _Rename(C.Structure):
    _fields_ = [
        ("replace", W.BOOL),
        ("root", W.HANDLE),
        ("length", W.DWORD),
        ("name", W.WCHAR * 1),
    ]


def _ticks(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


class _WindowsFiles:
    def __init__(self):
        if os.name != "nt":
            raise UnsafeRetentionOperation(
                "退避・完全削除の内部処理はWindows専用です。"
            )
        self.api = C.WinDLL("kernel32", use_last_error=True)
        self.api.CreateFileW.argtypes = [
            W.LPCWSTR,
            W.DWORD,
            W.DWORD,
            C.c_void_p,
            W.DWORD,
            W.DWORD,
            W.HANDLE,
        ]
        self.api.CreateFileW.restype = W.HANDLE
        self.api.GetFileInformationByHandle.argtypes = [W.HANDLE, C.POINTER(_Info)]
        self.api.GetFileInformationByHandle.restype = W.BOOL
        self.api.SetFileInformationByHandle.argtypes = [
            W.HANDLE,
            C.c_int,
            C.c_void_p,
            W.DWORD,
        ]
        self.api.SetFileInformationByHandle.restype = W.BOOL
        self.api.CloseHandle.argtypes = [W.HANDLE]
        self.api.CloseHandle.restype = W.BOOL

    @staticmethod
    def _path(path):
        text = os.path.abspath(path)
        if text.startswith("\\\\?\\"):
            return text
        return (
            "\\\\?\\UNC\\" + text[2:] if text.startswith("\\\\") else "\\\\?\\" + text
        )

    @contextmanager
    def _open(self, path, *, directory=False, mutate=False):
        access = 0x80 | (0x10000 if mutate else 0)  # READ_ATTRIBUTES, DELETE
        share = 3 if directory else (1 if mutate else 7)
        flags = 0x00200000 | (0x02000000 if directory else 0)  # OPEN_REPARSE_POINT
        handle = self.api.CreateFileW(
            self._path(path), access, share, None, 3, flags, None
        )
        if handle == C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        try:
            info = _Info()
            if not self.api.GetFileInformationByHandle(handle, C.byref(info)):
                raise C.WinError(C.get_last_error())
            if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
                raise UnsafeRetentionOperation(
                    "リンク・再解析ポイント・異なる種類の対象は処理できません。"
                )
            yield handle, info
        finally:
            self.api.CloseHandle(handle)

    @contextmanager
    def _parents(self, path):
        # Denying DELETE sharing on every ancestor prevents a checked directory
        # from being renamed/replaced by a junction while the operation runs.
        with ExitStack() as stack:
            for parent in reversed(Path(path).absolute().parent.parents):
                stack.enter_context(self._open(parent, directory=True))
            stack.enter_context(
                self._open(Path(path).absolute().parent, directory=True)
            )
            yield

    @staticmethod
    def _fingerprint(info):
        identity = (int(info.volume), int(info.index_high), int(info.index_low))
        if identity[1:] == (0, 0) or info.links != 1:
            raise UnsafeRetentionOperation(
                "安定したファイルIDを確認できないか、複数のハードリンクがあります。"
            )
        return {
            "identity": list(identity),
            "created": _ticks(info.created),
            "modified": _ticks(info.modified),
            "size": (int(info.size_high) << 32) | int(info.size_low),
        }

    def snapshot(self, path, root):
        if path_key(path) == path_key(root) or not within(path, root):
            raise UnsafeRetentionOperation("対象フォルダ外のパスです。")
        with self._parents(path), self._open(path) as (_, info):
            return self._fingerprint(info)

    def move(self, source, destination, root, expected):
        if path_key(source) == path_key(root) or not within(source, root):
            raise UnsafeRetentionOperation("対象フォルダ外のパスです。")
        with (
            self._parents(source),
            self._parents(destination),
            self._open(source, mutate=True) as (handle, info),
        ):
            if self._fingerprint(info) != expected:
                raise UnsafeRetentionOperation("確認後にファイルが変化しました。")
            encoded = self._path(destination).encode("utf-16-le")
            length = max(C.sizeof(_Rename), _Rename.name.offset + len(encoded) + 2)
            buffer = C.create_string_buffer(length)
            header = _Rename.from_buffer(buffer)
            header.replace = False
            header.root = None
            header.length = len(encoded)
            C.memmove(C.addressof(buffer) + _Rename.name.offset, encoded, len(encoded))
            if not self.api.SetFileInformationByHandle(handle, 3, buffer, length):
                # No cross-volume copy, overwrite, or path-based fallback.
                raise C.WinError(C.get_last_error())

    def purge(self, path, root, expected):
        if path_key(path) == path_key(root) or not within(path, root):
            raise UnsafeRetentionOperation("退避先の外にあるファイルです。")
        with self._parents(path), self._open(path, mutate=True) as (handle, info):
            if self._fingerprint(info) != expected:
                raise UnsafeRetentionOperation("退避後にファイルが変化しました。")
            delete = C.c_ubyte(1)  # FILE_DISPOSITION_INFO.DeleteFile is BOOLEAN.
            if not self.api.SetFileInformationByHandle(
                handle, 4, C.byref(delete), C.sizeof(delete)
            ):
                raise C.WinError(C.get_last_error())
