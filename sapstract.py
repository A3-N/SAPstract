import argparse
from src.modules.enum import enum_sap

def main():
    parser = argparse.ArgumentParser(description="SAPstract - All in one SAP tool")
    subparsers = parser.add_subparsers(dest="command")

    enum_parser = subparsers.add_parser("enum", help="Fingerprint SAP web endpoints")
    enum_parser.add_argument("target", help="Target Host/IP (optionally with port and/or scheme)")
    enum_parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    enum_parser.add_argument("-p", "--pause", type=float, default=0, help="Delay between requests (seconds)")
    enum_parser.add_argument("-v", "--verbose", action="store_true", help="Show all results including errors")

    args = parser.parse_args()

    if args.command == "enum":
        enum_sap(args.target, args.pause, args.verbose, args.threads)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

