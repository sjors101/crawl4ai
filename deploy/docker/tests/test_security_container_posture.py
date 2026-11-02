"""
R7 container/deployment posture - static parse of the deployment artifacts.

These assert the hardening is declared in the Dockerfile / docker-compose.yml /
supervisord.conf. The RUNTIME acceptance gate (the hardened image builds,
Chromium starts without --no-sandbox under userns/seccomp, the read-only rootfs
+ tmpfs work, redis truly requires auth) needs an actual `docker build` + boot
and is tracked as build-gated; it is out of scope for this offline suite.
"""

import os
import re

import pytest

pytestmark = pytest.mark.posture

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
DOCKER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _read(path):
    with open(path) as f:
        return f.read()


@pytest.fixture(scope="module")
def dockerfile():
    return _read(os.path.join(REPO_ROOT, "Dockerfile"))


@pytest.fixture(scope="module")
def compose():
    return _read(os.path.join(REPO_ROOT, "docker-compose.yml"))


@pytest.fixture(scope="module")
def supervisord():
    return _read(os.path.join(DOCKER_DIR, "supervisord.conf"))


class TestDockerfile:
    def test_no_redis_expose(self, dockerfile):
        # No active EXPOSE 6379 line (commented references are fine).
        for line in dockerfile.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert not re.match(r"EXPOSE\s+.*\b6379\b", stripped), \
                "redis port 6379 must not be EXPOSEd"

    def test_app_dir_root_owned_readonly(self, dockerfile):
        assert "chown -R root:root ${APP_HOME}" in dockerfile
        assert "chmod -R a-w ${APP_HOME}" in dockerfile

    def test_artifact_dir_created_0700(self, dockerfile):
        assert "/var/lib/crawl4ai/outputs" in dockerfile
        assert "chmod 700 /var/lib/crawl4ai/outputs" in dockerfile

    def test_playwright_headless_shell_is_copied_to_runtime_cache(self, dockerfile):
        # Playwright launches chromium_headless_shell for headless crawls. The
        # image runs as appuser, so both Chromium artifacts must be copied out
        # of root's install cache.
        cache_copy = re.search(
            r"cp -r(?P<artifacts>(?:(?!&&).)*)/home/appuser/\.cache/ms-playwright/",
            dockerfile,
            re.DOTALL,
        )
        assert cache_copy, "Dockerfile must copy Playwright artifacts into appuser's cache"
        assert "chromium-*" in cache_copy.group("artifacts")
        assert "chromium_headless_shell-*" in cache_copy.group("artifacts")

    def test_runs_as_non_root(self, dockerfile):
        assert re.search(r"^USER\s+appuser", dockerfile, re.MULTILINE)

    def test_redis_pinned_past_rediShell(self, dockerfile):
        # 7.2.7 is vulnerable to CVE-2025-49844 (Lua UAF RCE) et al.; the 7.2
        # line is fixed from 7.2.11.
        m = re.search(r'ARG REDIS_VERSION="6:7\.2\.(\d+)-', dockerfile)
        assert m, "Redis must stay pinned to a 7.2.x release"
        assert int(m.group(1)) >= 11

    def test_redis_pin_survives_dist_upgrade(self, dockerfile):
        # dist-upgrade used to replace the pinned 7.2.x with the newest major.
        assert "apt-mark hold redis-server redis-tools" in dockerfile
        assert dockerfile.index("apt-mark hold") < dockerfile.index("dist-upgrade -y")

    def test_redis_signing_key_fingerprint_verified(self, dockerfile):
        assert "ARG REDIS_GPG_FINGERPRINT=54318FA4052D1E61A6B6F7BB5F4349D6BF53AA0C" in dockerfile
        assert '"$actual" != "$REDIS_GPG_FINGERPRINT"' in dockerfile
        assert "curl -fsSL https://packages.redis.io/gpg | gpg --dearmor" not in dockerfile

    def test_build_source_and_toolchain_removed(self, dockerfile):
        assert "rm -rf /tmp/project" in dockerfile
        purge = re.search(r"apt-get purge -y --auto-remove(?P<pkgs>[^&]*)", dockerfile)
        assert purge, "build toolchain must be purged from the runtime image"
        for pkg in ("build-essential", "git", "wget", "python3-dev"):
            assert pkg in purge.group("pkgs")

    def test_kernel_headers_and_dev_packages_purged(self, dockerfile):
        purge = re.search(r"apt-get purge -y --auto-remove(?P<pkgs>[^&]*)", dockerfile)
        for pkg in ("linux-libc-dev", "libc6-dev", "libjpeg-dev"):
            assert pkg in purge.group("pkgs")

    def test_supervisor_not_from_apt(self, dockerfile):
        # apt's supervisor pulls in Debian's python3.11 (a second interpreter).
        assert not re.search(r"^\s+supervisor\s*\\?$", dockerfile, re.MULTILINE)
        reqs = _read(os.path.join(DOCKER_DIR, "requirements.txt"))
        assert re.search(r"^supervisor>=", reqs, re.MULTILINE)

    def test_only_chromium_installed(self, dockerfile):
        assert re.search(r"playwright install --with-deps chromium\b", dockerfile)


class TestDockerignore:
    """Docker reads .dockerignore only from the build-context root (".")."""

    @pytest.fixture(scope="class")
    def dockerignore(self):
        path = os.path.join(REPO_ROOT, ".dockerignore")
        assert os.path.exists(path), "root .dockerignore is required (context is '.')"
        return [l.strip() for l in _read(path).splitlines()
                if l.strip() and not l.lstrip().startswith("#")]

    def test_default_deny(self, dockerignore):
        assert dockerignore[0] == "*"

    def test_secrets_and_vcs_excluded(self, dockerignore):
        for pat in ("**/.env", "**/.env.*", "**/*.env", "**/.git",
                    "**/.claude", "deploy/docker/tests/"):
            assert pat in dockerignore, pat

    def test_no_stale_nested_dockerignore(self):
        # A nested copy is silently ignored and gives false assurance.
        assert not os.path.exists(os.path.join(DOCKER_DIR, ".dockerignore"))


class TestSupervisord:
    def test_redis_requires_password(self, supervisord):
        assert "--requirepass" in supervisord

    def test_redis_bound_loopback_with_optional_ipv6(self, supervisord):
        assert "--bind 127.0.0.1 -::1" in supervisord

    def test_gunicorn_bind_is_env_driven(self, supervisord):
        # entrypoint.sh resolves GUNICORN_BIND (loopback unless a credential).
        assert "ENV_GUNICORN_BIND" in supervisord

    def test_gunicorn_request_limits(self, supervisord):
        assert "--limit-request-line" in supervisord


class TestCompose:
    def test_cap_drop_all(self, compose):
        assert "cap_drop" in compose and "ALL" in compose

    def test_no_new_privileges(self, compose):
        assert "no-new-privileges:true" in compose

    def test_read_only_rootfs(self, compose):
        assert re.search(r"read_only:\s*true", compose)

    def test_no_host_dev_shm_bind(self, compose):
        assert "/dev/shm:/dev/shm" not in compose
        assert "shm_size" in compose

    def test_pids_limit(self, compose):
        # Parse, don't grep: a raw-text search matched the word "pids_limit"
        # inside a comment and guarded nothing. The cap lives under
        # deploy.resources.limits (not pids_limit) for Compose v5 compatibility.
        import yaml

        base = yaml.safe_load(compose)["x-base-config"]
        assert "pids_limit" not in base
        assert base["deploy"]["resources"]["limits"]["pids"] == 512

    def test_read_only_runtime_tmpfs_are_appuser_owned(self, compose):
        assert "/var/lib/redis:uid=999,gid=999,mode=0700" in compose
        assert "/var/lib/crawl4ai/outputs:uid=999,gid=999,mode=0700" in compose
        assert "/home/appuser/.crawl4ai:uid=999,gid=999,mode=0700" in compose
        assert "/home/appuser/.gunicorn:uid=999,gid=999,mode=0700" in compose

    def test_playwright_cache_is_not_shadowed(self, compose):
        assert "/home/appuser/.cache\n" not in compose
        assert "/home/appuser/.cache/url_seeder:uid=999,gid=999,mode=0700" in compose


class TestEntrypoint:
    def test_entrypoint_exists_and_resolves_bind(self):
        src = _read(os.path.join(DOCKER_DIR, "entrypoint.sh"))
        assert "GUNICORN_BIND" in src and "REDIS_PASSWORD" in src
        assert "127.0.0.1" in src  # loopback default when no credential


class TestSandboxOptOut:
    def test_default_keeps_no_sandbox(self, server_module, monkeypatch):
        monkeypatch.setattr(server_module, "CHROMIUM_SANDBOX", False)
        assert "--no-sandbox" in server_module._browser_extra_args()

    def test_opt_in_drops_no_sandbox(self, server_module, monkeypatch):
        # CRAWL4AI_CHROMIUM_SANDBOX=true -> run the renderer sandboxed.
        monkeypatch.setattr(server_module, "CHROMIUM_SANDBOX", True)
        assert "--no-sandbox" not in server_module._browser_extra_args()
        # other flags are preserved
        assert "--disable-dev-shm-usage" in server_module._browser_extra_args()
