"""Command line: python3 -m pqproof COMMAND ...

    verify-receipt RECEIPT_DIR   recompute every SHA-256 of a hashed receipt (exit 0 when all match)
"""
import sys


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["verify-receipt"]:
        from .receipt import main as verify_main
        return verify_main(argv[1:])
    print(__doc__.strip())
    return 2


if __name__ == "__main__":
    sys.exit(main())
