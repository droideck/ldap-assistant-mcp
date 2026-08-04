"""Regression tests for Docker/Podman selection in the DS helper scripts.

The tests use a fake container CLI and temporary script copies. They never
inspect or mutate real containers, volumes, networks, or server configs.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _write_fake_cli(tmp_path: Path, name: str) -> tuple[Path, Path]:
    cli = tmp_path / name
    log = tmp_path / f"{name}.log"
    cli.write_text(
        """#!/bin/bash
printf '%s\\n' "$*" >> "$FAKE_CLI_LOG"

case "$1" in
  info)
    exit "${FAKE_INFO_EXIT:-0}"
    ;;
  inspect)
    if [[ "$*" == *'.Config.Labels'* ]]; then
      printf '%s\\n' "${FAKE_OWNER:-ds-scripts}"
      exit "${FAKE_OWNER_EXIT:-0}"
    fi
    exit "${FAKE_CONTAINER_INSPECT_EXIT:-1}"
    ;;
  volume)
    case "$2" in
      create)
        exit "${FAKE_VOLUME_CREATE_EXIT:-0}"
        ;;
      inspect)
        if [[ "$*" == *'.Labels'* ]]; then
          printf '%s\\n' "${FAKE_VOLUME_OWNER:-ds-scripts}"
          exit "${FAKE_VOLUME_OWNER_EXIT:-0}"
        fi
        exit "${FAKE_VOLUME_INSPECT_EXIT:-1}"
        ;;
      rm)
        exit "${FAKE_VOLUME_RM_EXIT:-0}"
        ;;
    esac
    ;;
  rm)
    exit "${FAKE_RM_EXIT:-0}"
    ;;
  run|start|stop|exec|cp)
    exit 0
    ;;
esac

exit 0
""",
        encoding="utf-8",
    )
    cli.chmod(0o755)
    return cli, log


def _environment(**overrides: str) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("DS_CLI", None)
    env.update(overrides)
    return env


def _run_script(
    script: Path,
    *args: str,
    env: dict[str, str] | None = None,
    cwd: Path = REPO_ROOT,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(script), *args],
        cwd=cwd,
        env=env or _environment(),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )


def _run_common_function(
    tmp_path: Path,
    cli_name: str,
) -> tuple[subprocess.CompletedProcess[str], str]:
    cli, log = _write_fake_cli(tmp_path, cli_name)
    command = (
        f"source {shlex.quote(str(SCRIPTS_DIR / 'ds-common.sh'))}; "
        "require_container_cli; "
        "create_ds_container ds-unit 4389 4636 password dc=example,dc=com"
    )
    result = subprocess.run(
        ["/bin/bash", "-c", command],
        cwd=REPO_ROOT,
        env=_environment(DS_CLI=str(cli), FAKE_CLI_LOG=str(log)),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    return result, log.read_text(encoding="utf-8")


def test_status_fails_when_selected_cli_is_missing(tmp_path: Path) -> None:
    missing = tmp_path / "missing-container-cli"
    result = _run_script(
        SCRIPTS_DIR / "ds-dev.sh",
        "status",
        env=_environment(DS_CLI=str(missing)),
    )

    assert result.returncode != 0
    assert "command not found" in result.stderr
    assert "not created" not in result.stdout


def test_status_fails_when_selected_engine_is_unavailable(tmp_path: Path) -> None:
    cli, log = _write_fake_cli(tmp_path, "docker")
    result = _run_script(
        SCRIPTS_DIR / "ds-dev.sh",
        "status",
        env=_environment(
            DS_CLI=str(cli),
            FAKE_CLI_LOG=str(log),
            FAKE_INFO_EXIT="1",
        ),
    )

    assert result.returncode != 0
    assert "engine is unavailable" in result.stderr
    assert "not created" not in result.stdout


def test_offline_status_validates_runtime_before_inspection(tmp_path: Path) -> None:
    missing = tmp_path / "missing-container-cli"
    result = _run_script(
        SCRIPTS_DIR / "ds-offline-setup.sh",
        "status",
        env=_environment(DS_CLI=str(missing)),
    )

    assert result.returncode != 0
    assert "command not found" in result.stderr
    assert "Offline mode testing environment status" not in result.stdout


def test_help_does_not_require_a_container_runtime(tmp_path: Path) -> None:
    missing = tmp_path / "missing-container-cli"
    env = _environment(DS_CLI=str(missing))

    dev = _run_script(SCRIPTS_DIR / "ds-dev.sh", "help", env=env)
    offline = _run_script(SCRIPTS_DIR / "ds-offline-setup.sh", "help", env=env)

    assert dev.returncode == 0
    assert offline.returncode == 0


def test_docker_is_the_deterministic_default(tmp_path: Path) -> None:
    cli, log = _write_fake_cli(tmp_path, "docker")
    env = _environment(
        PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        FAKE_CLI_LOG=str(log),
    )

    result = _run_script(SCRIPTS_DIR / "ds-dev.sh", "status", env=env)

    assert result.returncode == 0
    calls = log.read_text(encoding="utf-8")
    assert "info" in calls
    assert "inspect ds-dev-1" in calls
    assert cli.name == "docker"


def test_explicit_podman_selection_is_preserved(tmp_path: Path) -> None:
    cli, log = _write_fake_cli(tmp_path, "podman")
    result = _run_script(
        SCRIPTS_DIR / "ds-dev.sh",
        "status",
        env=_environment(DS_CLI=str(cli), FAKE_CLI_LOG=str(log)),
    )

    assert result.returncode == 0
    calls = log.read_text(encoding="utf-8")
    assert "info" in calls
    assert "inspect ds-dev-1" in calls


def test_docker_container_gets_explicit_host_gateway(tmp_path: Path) -> None:
    result, calls = _run_common_function(tmp_path, "docker")

    assert result.returncode == 0, result.stderr
    assert "--add-host host.docker.internal:host-gateway" in calls


def test_podman_container_uses_runtime_provided_host_alias(tmp_path: Path) -> None:
    result, calls = _run_common_function(tmp_path, "podman")

    assert result.returncode == 0, result.stderr
    assert "--add-host" not in calls


def test_failed_cleanup_keeps_generated_config(tmp_path: Path) -> None:
    copied_scripts = tmp_path / "scripts"
    copied_scripts.mkdir()
    shutil.copy2(SCRIPTS_DIR / "ds-common.sh", copied_scripts / "ds-common.sh")
    shutil.copy2(SCRIPTS_DIR / "ds-dev.sh", copied_scripts / "ds-dev.sh")

    config = tmp_path / "servers.json"
    config.write_text("sentinel\n", encoding="utf-8")
    cli, log = _write_fake_cli(tmp_path, "docker")
    result = _run_script(
        copied_scripts / "ds-dev.sh",
        "remove",
        cwd=tmp_path,
        env=_environment(
            DS_CLI=str(cli),
            FAKE_CLI_LOG=str(log),
            FAKE_CONTAINER_INSPECT_EXIT="0",
            FAKE_RM_EXIT="1",
        ),
    )

    assert result.returncode != 0
    assert config.read_text(encoding="utf-8") == "sentinel\n"
