import argparse
from csc458_tester.sr_handler import Lab1Tester


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSC458 Lab 1 Tester")
    parser.add_argument(
        "--router_path",
        type=str,
        required=True,
        help="Path to the router executable (e.g., csc458-pa1/router/sr)",
    )
    parser.add_argument(
        "--logfile",
        type=str,
        default="sr-log.txt",
        help="Path to the log file (default: sr-log.txt)",
    )
    args = parser.parse_args()

    tester = Lab1Tester(args.router_path, args.logfile)

    print("Running CSC458 Lab 1 Tester...")
    tester.run()
    tester.summary()
