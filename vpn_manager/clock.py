from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def current_usage_period() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


class SystemCalendar:
    def period(self) -> str:
        return current_usage_period()

    def timestamp(self) -> str:
        return utc_now()
