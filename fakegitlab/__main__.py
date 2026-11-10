"""
Standalone entry point: ``python -m fakegitlab``.

Every option can also be provided through environment variables, which is how
the Docker Compose service is configured:

==========================  ===================  ==================
Option                      Environment          Default
==========================  ===================  ==================
``--host``                  FAKE_GITLAB_HOST     127.0.0.1
``--port``                  FAKE_GITLAB_PORT     8080
``--scenario``              FAKE_GITLAB_SCENARIO default
``--external-url``          FAKE_GITLAB_EXTERNAL_URL (derived from request)
``--log-level``             FAKE_GITLAB_LOG_LEVEL INFO
==========================  ===================  ==================
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading

from fakegitlab.scenario import ScenarioError, available_scenarios
from fakegitlab.server import FakeGitLab


def _parse(argv: list[str] | None) -> argparse.Namespace:
    env = os.environ.get
    p = argparse.ArgumentParser(prog="python -m fakegitlab", description="Run the Fake GitLab REST API v4 server.")
    p.add_argument("--host", default=env("FAKE_GITLAB_HOST", "127.0.0.1"), help="Bind address.")
    p.add_argument("--port", type=int, default=int(env("FAKE_GITLAB_PORT", "8080")), help="Bind port (0 = random).")
    p.add_argument("--scenario", default=env("FAKE_GITLAB_SCENARIO", "default"), help="Scenario name or file path.")
    p.add_argument(
        "--external-url",
        default=env("FAKE_GITLAB_EXTERNAL_URL") or None,
        help="Base URL used in web_url/Link values (default: derived from the request Host).",
    )
    p.add_argument(
        "--log-level",
        default=env("FAKE_GITLAB_LOG_LEVEL", "INFO"),
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Request log verbosity.",
    )
    p.add_argument("--list-scenarios", action="store_true", help="Print available scenarios and exit.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the server until SIGINT/SIGTERM."""
    args = _parse(argv)

    if args.list_scenarios:
        print("\n".join(available_scenarios()))
        return 0

    logging.basicConfig(level=args.log_level, format="[fake-gitlab] %(asctime)s %(levelname)s %(message)s")
    # Werkzeug's access log duplicates our journal lines.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)

    try:
        fake = FakeGitLab(args.scenario, host=args.host, port=args.port, external_url=args.external_url)
    except ScenarioError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    stop = threading.Event()

    def _on_signal(signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    fake.start()
    print(
        f"Fake GitLab is up: {fake.url}\n"
        f"  scenario : {fake.scenario.name} ({len(fake.scenario.projects)} projects)\n"
        f"  token    : {fake.token}\n"
        f"  journal  : {fake.url}/__admin/requests\n"
        f"Press Ctrl+C to stop.",
        flush=True,
    )
    try:
        while not stop.wait(0.5):
            pass
    finally:
        fake.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
