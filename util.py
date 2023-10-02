import sys


DEFAULT_LINE_WIDTH = 120

# Based on https://stackoverflow.com/questions/13343700/
# TODO consider adding a decimal when < 10 (e.g. 1.7 GB)
def bytes2human(n: int) -> str:
    """
    >>> bytes2human(10000)
    "9K"
    >>> bytes2human(100001221)
    "95M"
    """
    symbols = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i + 1) * 10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            # if value < 10, include a single decimal
            value = float(int(value*10)/10) if value < 10 else int(value)
            return f"{value} {symbol}"
    return f"{n} {symbols[0]}"


def get_fixed_length_string(message: str, line_width: int) -> str:
    message = message[:line_width]  # truncate to the given width
    paddingLength = line_width-len(message)
    return message + " "*paddingLength


def print_message(message: str, line_width: int = DEFAULT_LINE_WIDTH, file=sys.stdout) -> None:
    print(get_fixed_length_string(message, line_width), end="\r", file=file)


def format_elapsed_time(seconds) -> str:
    return f"{int(seconds / 3600):02d}:{(int(seconds/60) % 60):02d}:{(int(seconds) % 60):02d}"
