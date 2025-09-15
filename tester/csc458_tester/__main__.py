import argparse
import signal
import sys
from csc458_tester.sr_handler import Lab1Tester
from twisted.internet import reactor


def cleanup_handler(signum, frame):
    print("\nCleaning up...")
    reactor.callFromThread(do_cleanup)

def do_cleanup():
    import subprocess
    subprocess.run("killall -9 sr >/dev/null 2>&1", shell=True)
    subprocess.run("killall -9 sr_solution >/dev/null 2>&1", shell=True)
    subprocess.run("killall -9 sr_solution_arm >/dev/null 2>&1", shell=True)
    if reactor.running:
        reactor.stop()
    else:
        sys.exit(0)


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

    # Handle Ctrl+C gracefully
    signal.signal(signal.SIGINT, cleanup_handler)

    tester = Lab1Tester(args.router_path, args.logfile)

    print("Running CSC458 Lab 1 Tester...")
    tester.run()
    tester.summary()
