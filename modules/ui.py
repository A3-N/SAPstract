from termcolor import colored

def info(msg):
    print(f"{colored('[*]', 'cyan')} {msg}")

def success(msg):
    print(f"{colored('[+]', 'green')} {msg}")

def warn(msg):
    print(f"{colored('[!]', 'yellow')} {msg}")

def fail(msg):
    print(f"{colored('[-]', 'red')} {msg}")

def plain(msg):
    print(msg)

def bold(msg):
    print(colored(msg, attrs=["bold"]))

