"""Public deletion facade: deliberately and unconditionally unavailable.

No settings key, environment variable, CLI argument or administrator role can
enable it. The private implementation is included for future development/tests.
"""

from . import _retention_engine  # noqa: F401 -- include dormant code in packaged builds


class DeletionDisabled(RuntimeError):
    pass


class DeletionService:
    @staticmethod
    def status():
        return {
            "implemented": True,
            "enabled": False,
            "activation": "requires_source_change",
        }

    @staticmethod
    def prepare(*args, **kwargs):
        raise DeletionDisabled("削除機能はこのバージョンでは実行できません。")

    @staticmethod
    def quarantine(*args, **kwargs):
        raise DeletionDisabled("削除機能はこのバージョンでは実行できません。")

    @staticmethod
    def purge(*args, **kwargs):
        raise DeletionDisabled("削除機能はこのバージョンでは実行できません。")
