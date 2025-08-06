from rich.console import Console
from rich.text import Text

console = Console()

def print_info(msg):
    console.print(Text("[*]", style="yellow"), msg)

def print_good(msg):
    console.print(Text("[+]", style="green"), msg)

def print_bad(msg):
    console.print(Text("[-]", style="red"), msg)

def print_summary(target, ports):
    console.print(Text("[*]", style="yellow"), "Target Summary")
    console.print(f"    Hostname        : {target}")
    console.print(f"    SAP Ports       : {', '.join(map(str, ports))}\n")

