import sys


DEFAULT_LINE_WIDTH = 120

# shamelessly copied from https://stackoverflow.com/questions/13343700/
# TODO consider adding a decimal when < 10 (e.g. 1.7 GB)
def bytes2human(n: int, format: str = "%(value)i%(symbol)s") -> str:
    """
    >>> bytes2human(10000)
    "9K"
    >>> bytes2human(100001221)
    "95M"
    """
    symbols = ("B", "K", "M", "G", "T", "P", "E", "Z", "Y")
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i + 1) * 10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return format % locals()
    return format % dict(symbol=symbols[0], value=n)


def get_fixed_length_string(message: str, line_width: int) -> str:
    message = message[:line_width]  # truncate to the given width
    paddingLength = line_width-len(message)
    return message + " "*paddingLength


def print_message(message: str, line_width: str = DEFAULT_LINE_WIDTH, file=sys.stdout):
    print(get_fixed_length_string(message, line_width), end="\r", file=file)