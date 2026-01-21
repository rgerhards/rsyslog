#!/usr/bin/env python3
import datetime
import sys


def estimate_year(current_year: int, current_month: int, incoming_month: int) -> int:
    incoming_month += 12
    if (incoming_month - current_month) == 1:
        if current_month == 12 and incoming_month == 13:
            return current_year + 1
    if (incoming_month - current_month) > 13:
        return current_year - 1
    return current_year


def format_contains_directive(fmt: str, directives: str) -> bool:
    i = 0
    while i < len(fmt):
        ch = fmt[i]
        if ch != '%':
            i += 1
            continue
        i += 1
        if i >= len(fmt):
            break
        ch = fmt[i]
        if ch == '%':
            i += 1
            continue
        if ch in ('E', 'O'):
            i += 1
            if i >= len(fmt):
                break
            ch = fmt[i]
        if ch in directives:
            return True
        i += 1
    return False


def parse(value: str, fmt: str) -> str:
    has_year = format_contains_directive(fmt, "YyGgC")
    has_tz = format_contains_directive(fmt, "z")

    dt = datetime.datetime.strptime(value, fmt)

    if not has_year:
        now = datetime.datetime.utcnow()
        dt = dt.replace(year=estimate_year(now.year, now.month, dt.month))

    if dt.tzinfo is None:
        if has_tz:
            # If format expected a timezone but strptime could not parse it,
            # fall back to UTC to mimic the rsyslog implementation.
            tzinfo = datetime.timezone.utc
        else:
            tzinfo = datetime.timezone.utc
        dt = dt.replace(tzinfo=tzinfo)

    offset = dt.utcoffset() or datetime.timedelta(0)
    offset_minutes = int(offset.total_seconds() // 60)

    if offset_minutes == 0:
        iso_dt = dt.astimezone(datetime.timezone.utc)
        return iso_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    tz = datetime.timezone(datetime.timedelta(minutes=offset_minutes))
    iso_dt = dt.astimezone(tz).replace(tzinfo=None)
    sign = '+' if offset_minutes >= 0 else '-'
    absolute = abs(offset_minutes)
    hours = absolute // 60
    minutes = absolute % 60
    return iso_dt.strftime("%Y-%m-%dT%H:%M:%S") + f"{sign}{hours:02d}:{minutes:02d}"


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: rscript_strptime_to_rfc3339_expect.py <timestamp> <format>", file=sys.stderr)
        return 1
    value = sys.argv[1]
    fmt = sys.argv[2]
    print(parse(value, fmt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
