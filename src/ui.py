# src/ui.py

_NO_COLOR = False

def set_no_color(value: bool):
    global _NO_COLOR
    _NO_COLOR = bool(value)

def _c(code: str) -> str:
    if _NO_COLOR:
        return ''
    return f"\x1b[{code}m"

def _reset() -> str:
    return _c('0')

COLORS = {
    'blue':   '34',
    'green':  '32',
    'yellow': '33',
    'red':    '31',
    'white':  '37',
    'bold':   '1',
}

def _colorize(msg: str, color: str = None, bold: bool = False) -> str:
    if _NO_COLOR or (color is None and not bold):
        return msg
    parts = []
    if bold:
        parts.append(COLORS['bold'])
    if color in COLORS:
        parts.append(COLORS[color])
    return f"{_c(';'.join(parts))}{msg}{_reset()}" if parts else msg

def print_line(level: str, msg: str, src: str = None):
    level = (level or '').lower()
    if level == 'info':
        sym, col = '[*]', 'blue'
    elif level in ('ok', 'success', 'good'):
        sym, col = '[+]', 'green'
    elif level in ('warn', 'warning'):
        sym, col = '[!]', 'yellow'
    elif level in ('fail', 'error', 'err', 'bad'):
        sym, col = '[-]', 'red'
    else:
        sym, col = '[-]', 'red'

    prefix = f"[{src}] {sym}" if src else f"{sym}"
    out = f"{_colorize(prefix, col, bold=False)} {msg}"
    print(out, flush=True)

def info(msg: str, src: str = None):
    print_line('info', msg, src)

def success(msg: str, src: str = None):
    print_line('ok', msg, src)

def warn(msg: str, src: str = None):
    print_line('warn', msg, src)

def fail(msg: str, src: str = None):
    print_line('fail', msg, src)

def plain(msg: str):
    print(msg, flush=True)

def bold(msg: str):
    print(_colorize(msg, bold=True), flush=True)

