"""
main.py — AutoTrust Entry Point
================================
Bootstrap sequence:
  1. Configure logging (console + rotating file)
  2. Ensure directory structure exists
  3. Initialise SQLite schema
  4. Launch Tkinter GUI

Run:
    python3 main.py

Project : AutoTrust — PKI-Based V2V Trust & Secure Communication System
Module  : ST6051CEM Practical Cryptography
"""

import logging
import logging.handlers
import os
import sys


def configure_logging():
    fmt  = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Console: INFO+
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(fmt))
    root.addHandler(ch)

    # Rotating file: DEBUG+
    log_path = os.path.join(os.path.dirname(__file__), "autotrust.log")
    fh = logging.handlers.RotatingFileHandler(
        log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(fmt))
    root.addHandler(fh)


def main():
    configure_logging()
    log = logging.getLogger(__name__)
    log.info("=" * 60)
    log.info("AutoTrust v%s — starting", "2.0.0")
    log.info("=" * 60)

    import config
    config.ensure_directories()
    log.info("Directories verified.")

    import database
    database.initialise()
    log.info("Database ready.")

    import tkinter as tk
    try:
        from gui.dashboard import AutoTrustApp
        app = AutoTrustApp()
        log.info("GUI launched.")
        app.mainloop()
    except tk.TclError as exc:
        log.critical("Tkinter error: %s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Interrupted by user.")
    finally:
        log.info("AutoTrust shut down.")


if __name__ == "__main__":
    main()
