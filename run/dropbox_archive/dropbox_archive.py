#!/usr/bin/env python3
"""Archive teslausb recordings to a folder in Dropbox.

Usage:
  dropbox_archive.py authorize [--app-key KEY] [--print]
  dropbox_archive.py import-credentials
  dropbox_archive.py check
  dropbox_archive.py status
  dropbox_archive.py upload DIR LIST [DIR LIST ...]

Files larger than one chunk are uploaded in a Dropbox upload session. The
session and the amount uploaded so far are saved after every chunk, so an
upload that is interrupted, for example because the car drove out of wifi
range, continues where it left off the next time Dropbox is reachable,
instead of starting over. Dropbox keeps upload sessions for 48 hours.

Each uploaded file is checked against the content hash that Dropbox reports
before the local copy is removed.

Only the Python standard library is used. See doc/SetupDropbox.md.
"""

import argparse
import base64
import collections
import hashlib
import http.client
import io
import json
import os
import random
import secrets
import shlex
import signal
import ssl
import stat
import subprocess
import sys
import time
import traceback
import urllib.parse

API_URL = os.environ.get("DROPBOX_API_URL", "https://api.dropboxapi.com")
CONTENT_URL = os.environ.get("DROPBOX_CONTENT_URL", "https://content.dropboxapi.com")
AUTHORIZE_URL = "https://www.dropbox.com/oauth2/authorize"

SCRIPT = os.path.abspath(__file__)
DEFAULT_STATE_DIR = "/mutable/dropbox"
CREDENTIALS_FILE = "credentials.json"
SESSIONS_FILE = "sessions.json"
LEDGER_FILE = "uploaded.jsonl"
LOCK_FILE = "lock"

MIB = 1024 * 1024
# Dropbox content hashes are computed over 4 MiB blocks.
HASH_BLOCK_SIZE = 4 * MIB
DEFAULT_CHUNK_MB = 8
# A single request must not upload more than 150 MB.
MAX_CHUNK_MB = 140
# Upload sessions expire 48 hours after they were started, so don't try to
# resume one that is about to expire.
SESSION_MAX_AGE = 46 * 3600
DEFAULT_OFFLINE_TIMEOUT = 120
SOCKET_TIMEOUT = 60
SEND_BLOCK_SIZE = 64 * 1024
MAX_ATTEMPTS = 8
# How often a single request may lose its connection to Dropbox before the
# connection is considered too unreliable to continue.
MAX_DROPOUTS = 5
REACHABILITY_INTERVAL = 5
TOKEN_REFRESH_MARGIN = 300
REQUIRED_SCOPES = ("files.content.write", "files.metadata.read")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_NO_SPACE = 4
EXIT_NO_CREDENTIALS = 5
EXIT_UNREACHABLE = 75  # EX_TEMPFAIL: try again when Dropbox is reachable

# Archive the most valuable recordings first, in case the upload is cut short.
PRIORITY = {"SavedClips": 0, "SentryClips": 1, "TeslaTrackMode": 2}


def log(message):
    try:
        print(message, flush=True)
    except UnicodeEncodeError:
        log(message.encode("ascii", "backslashreplace").decode("ascii"))
    except OSError:
        pass


def _sleep(seconds):
    time.sleep(seconds)


def _size(num_bytes):
    if num_bytes >= 1024 * MIB:
        return "%.1f GB" % (num_bytes / (1024 * MIB))
    return "%.1f MB" % (num_bytes / MIB)


def _duration(seconds):
    hours, rest = divmod(int(round(seconds)), 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return "%dh%dm%ds" % (hours, minutes, seconds)
    if minutes:
        return "%dm%ds" % (minutes, seconds)
    return "%ds" % seconds


class ArchiveError(Exception):
    """A problem that stops the whole run. exit_code says how the run ends."""
    exit_code = EXIT_FAILED


class AuthError(ArchiveError):
    exit_code = EXIT_AUTH


class NoSpaceError(ArchiveError):
    exit_code = EXIT_NO_SPACE


class UnreachableError(ArchiveError):
    exit_code = EXIT_UNREACHABLE


class ConfigError(ArchiveError):
    exit_code = EXIT_USAGE


class ServiceError(ArchiveError):
    """Dropbox kept failing even though it was reachable."""


class CertificateError(ArchiveError):
    def __init__(self, error):
        ArchiveError.__init__(
            self, "TLS certificate verification failed (%s). Is the clock right? It is now %s."
            % (error, time.strftime("%Y-%m-%d %H:%M:%S %Z")))


class FileError(Exception):
    """A problem with one file. Other files can still be archived."""


class NetworkError(Exception):
    """A request failed before a response was received."""


class Terminated(BaseException):
    pass


class ApiError(Exception):
    """An error response from Dropbox."""

    def __init__(self, status, body, retry_after=None):
        self.status = status
        self.summary = ""
        self.error = None
        try:
            parsed = json.loads(body.decode("utf-8")) if body else None
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and "error_summary" in parsed:
            self.summary = str(parsed["error_summary"])
            self.error = parsed.get("error")
        elif body:
            self.summary = body.decode("utf-8", "replace").strip()[:300]
        if retry_after is None and status == 429:
            retry_after = _seconds_or_none(self.find("retry_after"))
        self.retry_after = retry_after
        Exception.__init__(self, "HTTP %d %s" % (status, self.summary or "(no details)"))

    def has(self, tag):
        """Whether tag is part of the error, e.g. 'conflict' in 'path/conflict/file/'."""
        return tag in self.summary.split("/")

    def find(self, key):
        return _find_key(self.error, key)

    @property
    def transient(self):
        return self.status == 429 or self.status >= 500 or self.has("too_many_write_operations")


class _AccessTokenRejected(Exception):
    def __init__(self, error):
        Exception.__init__(self, error.summary)
        self.error = error


def _find_key(value, key):
    if isinstance(value, dict):
        if key in value:
            return value[key]
        children = list(value.values())
    elif isinstance(value, list):
        children = value
    else:
        return None
    for child in children:
        found = _find_key(child, key)
        if found is not None:
            return found
    return None


def _seconds_or_none(value):
    try:
        return max(1, min(300, int(value)))
    except (TypeError, ValueError):
        return None


def _retry_after(response):
    return _seconds_or_none(response.getheader("Retry-After"))


def _header_json(value):
    # Dropbox-API-Arg must be plain ASCII, with DEL escaped as well.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).replace("\x7f", "\\u007f")


def _oauth_error(body):
    try:
        parsed = json.loads(body.decode("utf-8"))
    except ValueError:
        return body.decode("utf-8", "replace").strip()[:300]
    if isinstance(parsed, dict):
        error = str(parsed.get("error", ""))
        description = parsed.get("error_description")
        return "%s: %s" % (error, description) if description else error
    return str(parsed)


class HttpClient:
    """Sends POST requests, keeping one connection per host alive between requests."""

    def __init__(self, timeout=None):
        self.timeout = timeout or SOCKET_TIMEOUT
        self._connections = {}
        self._ssl_context = None

    def _connect(self, parts):
        if parts.scheme == "https":
            if self._ssl_context is None:
                self._ssl_context = ssl.create_default_context()
            return http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=self.timeout,
                                               context=self._ssl_context, blocksize=SEND_BLOCK_SIZE)
        return http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=self.timeout,
                                          blocksize=SEND_BLOCK_SIZE)

    def post(self, base_url, path, headers, body):
        parts = urllib.parse.urlsplit(base_url)
        key = (parts.scheme, parts.netloc)
        url = parts.path.rstrip("/") + path
        headers = dict(headers)
        headers["Content-Length"] = str(len(body))
        while True:
            connection = self._connections.pop(key, None)
            reused = connection is not None
            if not reused:
                connection = self._connect(parts)
            try:
                # Sending the body from a file object makes http.client send it
                # in small blocks, so the socket timeout limits how long a
                # transfer may stall, rather than how long the request may take.
                connection.request("POST", url, body=io.BytesIO(body), headers=headers)
                response = connection.getresponse()
                data = response.read()
            except ssl.SSLCertVerificationError as e:
                connection.close()
                raise CertificateError(e)
            except (OSError, http.client.HTTPException) as e:
                connection.close()
                if reused and isinstance(e, ConnectionError):
                    # The server closed the idle connection, try a new one.
                    continue
                raise NetworkError("%s: %s" % (type(e).__name__, e))
            if response.will_close:
                connection.close()
            else:
                self._connections[key] = connection
            return response.status, response, data

    def close(self):
        for connection in self._connections.values():
            connection.close()
        self._connections.clear()


Credentials = collections.namedtuple("Credentials", "app_key refresh_token app_secret source")


class Dropbox:
    """Calls the Dropbox API, refreshing the access token and retrying failed
    requests as needed. When a request fails because Dropbox is unreachable,
    it waits up to offline_timeout seconds for the connection to come back."""

    def __init__(self, credentials, http=None, reachable=None, offline_timeout=DEFAULT_OFFLINE_TIMEOUT):
        self.credentials = credentials
        self.http = http or HttpClient()
        self.reachable = reachable or (lambda: True)
        self.offline_timeout = offline_timeout
        self._access_token = None
        self._token_expires = 0.0

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.http.close()

    def call(self, route, arg=None, data=None, before_retry=None):
        """Calls an API route. Routes that upload file contents take the
        contents as data, all others must be called without data.
        before_retry is called before the request is sent again after it
        failed."""

        def attempt():
            try:
                return self._call_once(route, arg, data)
            except _AccessTokenRejected:
                # The access token expired or was revoked early, get a new one.
                self._access_token = None
                try:
                    return self._call_once(route, arg, data)
                except _AccessTokenRejected as e:
                    raise AuthError("Dropbox rejected a new access token (%s)" % e)

        return self._retrying(route, attempt, before_retry)

    def _call_once(self, route, arg, data):
        headers = {"Authorization": "Bearer " + self._token()}
        if data is not None:
            headers["Dropbox-API-Arg"] = _header_json(arg)
            headers["Content-Type"] = "application/octet-stream"
            base, body = CONTENT_URL, data
        else:
            headers["Content-Type"] = "application/json"
            base, body = API_URL, json.dumps(arg).encode("utf-8")
        status, response, payload = self.http.post(base, "/2/" + route, headers, body)
        if status == 200:
            return json.loads(payload.decode("utf-8")) if payload.strip() else None
        error = ApiError(status, payload, _retry_after(response))
        if status == 401:
            if error.has("expired_access_token") or error.has("invalid_access_token"):
                raise _AccessTokenRejected(error)
            scope = error.find("required_scope")
            if scope:
                raise AuthError("The Dropbox app doesn't have the '%s' permission. Enable it on the Permissions "
                                "tab in the Dropbox App Console, then run '%s authorize' again."
                                % (scope, SCRIPT))
            raise AuthError("Dropbox refused access (%s)" % error.summary)
        if status == 403:
            raise AuthError("Dropbox refused access (%s)" % error.summary)
        raise error

    def _token(self):
        if self._access_token is None or time.monotonic() > self._token_expires - TOKEN_REFRESH_MARGIN:
            self._retrying("refreshing the access token", self._refresh_token)
        return self._access_token

    def _refresh_token(self):
        form = {
            "grant_type": "refresh_token",
            "refresh_token": self.credentials.refresh_token,
            "client_id": self.credentials.app_key,
        }
        if self.credentials.app_secret:
            form["client_secret"] = self.credentials.app_secret
        status, response, payload = self.http.post(
            API_URL, "/oauth2/token", {"Content-Type": "application/x-www-form-urlencoded"},
            urllib.parse.urlencode(form).encode("ascii"))
        if status == 200:
            result = json.loads(payload.decode("utf-8"))
            self._access_token = result["access_token"]
            self._token_expires = time.monotonic() + int(result.get("expires_in", 14400))
            return
        if status in (400, 401, 403):
            raise AuthError("Dropbox did not accept the credentials from %s (%s). Authorize teslausb again "
                            "with '%s authorize'." % (self.credentials.source, _oauth_error(payload), SCRIPT))
        raise ApiError(status, payload, _retry_after(response))

    def _retrying(self, what, func, before_retry=None):
        attempts = 0
        dropouts = 0
        while True:
            try:
                return func()
            except NetworkError as e:
                failure, delay = e, None
            except ApiError as e:
                if not e.transient:
                    raise
                failure, delay = e, e.retry_after
            if self.reachable():
                attempts += 1
                if attempts >= MAX_ATTEMPTS:
                    raise ServiceError("%s failed %d times, last error: %s" % (what, attempts, failure))
                if delay is None:
                    delay = min(60, 2 ** attempts) * random.uniform(0.75, 1.25)
                log("%s failed (%s), retrying in %ds" % (what, failure, delay))
                _sleep(delay)
            else:
                dropouts += 1
                if dropouts > MAX_DROPOUTS:
                    # unlike UnreachableError, not worth trying again right away
                    raise ArchiveError("the connection to Dropbox keeps dropping")
                self._wait_until_reachable(what)
                attempts = 0
            if before_retry is not None:
                before_retry()

    def _wait_until_reachable(self, what):
        log("Dropbox is unreachable (%s), waiting up to %ds for it to come back"
            % (what, self.offline_timeout))
        deadline = time.monotonic() + self.offline_timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UnreachableError("Dropbox has been unreachable for %ds" % self.offline_timeout)
            _sleep(min(REACHABILITY_INTERVAL, remaining))
            if self.reachable():
                log("Dropbox is reachable again")
                return


class ContentHasher:
    """Computes a Dropbox content hash: the SHA-256 of the concatenated SHA-256
    digests of each 4 MiB block of the file."""

    def __init__(self):
        self._overall = hashlib.sha256()
        self._block = hashlib.sha256()
        self._block_used = 0

    def update(self, data):
        view = memoryview(data)
        while len(view):
            take = min(HASH_BLOCK_SIZE - self._block_used, len(view))
            self._block.update(view[:take])
            self._block_used += take
            view = view[take:]
            if self._block_used == HASH_BLOCK_SIZE:
                self._overall.update(self._block.digest())
                self._block = hashlib.sha256()
                self._block_used = 0

    def hexdigest(self):
        overall = self._overall.copy()
        if self._block_used:
            overall.update(self._block.digest())
        return overall.hexdigest()


class Source:
    """Reads parts of a file being uploaded, and computes its content hash
    along the way. When an upload resumes partway through a file, the part
    uploaded earlier is read from disk to complete the hash."""

    def __init__(self, f, size):
        self.f = f
        self.size = size
        self._hasher = ContentHasher()
        self._hashed = 0

    def read(self, offset, length):
        self._hash_up_to(offset)
        data = self._read_exactly(offset, length)
        end = offset + length
        if end > self._hashed:
            self._hasher.update(memoryview(data)[self._hashed - offset:])
            self._hashed = end
        return data

    def content_hash(self):
        self._hash_up_to(self.size)
        self.f.seek(self.size)
        if self.f.read(1):
            raise FileError("the file grew while it was being uploaded")
        return self._hasher.hexdigest()

    def _hash_up_to(self, offset):
        while self._hashed < offset:
            data = self._read_exactly(self._hashed, min(HASH_BLOCK_SIZE, offset - self._hashed))
            self._hasher.update(data)
            self._hashed += len(data)

    def _read_exactly(self, offset, length):
        self.f.seek(offset)
        data = self.f.read(length)
        if len(data) != length:
            raise FileError("the file changed while it was being uploaded")
        return data


def _ensure_private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _write_atomically(path, data):
    """Replaces path with data, so that after a crash or power loss it holds
    either the old or the new contents."""
    temp = path + ".tmp"
    if os.path.lexists(temp):
        os.unlink(temp)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(data)
        while len(view):
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, path)
    try:
        dir_fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def _write_json(path, value):
    _write_atomically(path, (json.dumps(value, indent=1, sort_keys=True) + "\n").encode("utf-8"))


class SessionStore:
    """Upload sessions in progress, saved so an interrupted upload can resume.

    A session is only resumed for the same file: same path in the list of
    files to archive, same size and same modification time."""

    def __init__(self, path):
        self.path = path
        self.sessions = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                entries = json.load(f)["sessions"]
            for entry in entries:
                self.sessions[(entry["root"], entry["path"])] = entry
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError) as e:
            log("Ignoring unreadable upload state in %s: %s" % (path, e))
            self.sessions = {}

    def get(self, identity, dest):
        root, relpath, size, mtime_ns = identity
        entry = self.sessions.get((root, relpath))
        if (entry is None or entry.get("size") != size or entry.get("mtime_ns") != mtime_ns
                or entry.get("dest") != dest or not isinstance(entry.get("session_id"), str)):
            return None
        if time.time() - entry.get("created", 0) >= SESSION_MAX_AGE:
            return None
        offset = entry.get("offset")
        if not isinstance(offset, int) or not 0 < offset <= size:
            return None
        return entry

    def put(self, identity, dest, session_id, offset):
        root, relpath, size, mtime_ns = identity
        self.sessions[(root, relpath)] = {
            "root": root, "path": relpath, "size": size, "mtime_ns": mtime_ns, "dest": dest,
            "session_id": session_id, "offset": offset, "created": time.time(),
        }
        self._save()

    def update(self, identity, offset):
        entry = self.sessions.get(identity[:2])
        if entry is not None and entry["offset"] != offset:
            entry["offset"] = offset
            self._save()

    def remove(self, identity):
        if self.sessions.pop(identity[:2], None) is not None:
            self._save()

    def prune(self, pending):
        """Forgets sessions for files that no longer need archiving, and
        sessions that have expired."""
        now = time.time()
        keep = {key: entry for key, entry in self.sessions.items()
                if key in pending and now - entry.get("created", 0) < SESSION_MAX_AGE}
        if len(keep) != len(self.sessions):
            self.sessions = keep
            self._save()

    def _save(self):
        _write_json(self.path, {"sessions": list(self.sessions.values())})


class Ledger:
    """Files recently stored in Dropbox.

    archiveloop only records which files were archived after archive-clips.sh
    exits, so when power is lost during a run, the files uploaded in that run
    are offered again in the next. The ledger recognizes them, so they don't
    have to be uploaded a second time. Entries for files that are no longer
    offered for archiving were recorded by archiveloop, and are dropped, as
    are entries for earlier versions of a file, like a trigger file that is
    created again for every run."""

    def __init__(self, path, pending):
        self.path = path
        self.entries = {}
        found = 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    found += 1
                    try:
                        entry = json.loads(line)
                        key = (entry["root"], entry["path"])
                    except (ValueError, KeyError, TypeError):
                        # e.g. a partially written line after a power loss
                        continue
                    if key in pending:
                        self.entries[key] = entry
        except FileNotFoundError:
            pass
        except OSError as e:
            log("Ignoring unreadable %s: %s" % (path, e))
        if found != len(self.entries):
            self._rewrite()

    def _rewrite(self):
        lines = "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in self.entries.values())
        _write_atomically(self.path, lines.encode("utf-8"))

    def has(self, identity, dest):
        entry = self.entries.get(identity[:2])
        return (entry is not None and entry.get("size") == identity[2] and entry.get("mtime_ns") == identity[3]
                and entry.get("dest") == dest)

    def add(self, identity, dest, stored_as, content_hash):
        root, relpath, size, mtime_ns = identity
        entry = {"root": root, "path": relpath, "size": size, "mtime_ns": mtime_ns, "dest": dest,
                 "stored_as": stored_as, "content_hash": content_hash, "time": int(time.time())}
        if identity[:2] in self.entries:
            self.entries[identity[:2]] = entry
            self._rewrite()
            return
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.entries[identity[:2]] = entry


Job = collections.namedtuple("Job", "root relpath")


def _clean_relpath(relpath):
    while relpath.startswith("./"):
        relpath = relpath[2:]
    if not relpath or relpath.startswith("/") or any(p in ("", ".", "..") for p in relpath.split("/")):
        return None
    return relpath


def read_jobs(pairs):
    """Reads the files to archive from (directory, list file) pairs. Each list
    file names files relative to its directory, one per line."""
    jobs = []
    seen = set()
    for root, list_file in pairs:
        batch = []
        with open(list_file, "rb") as f:
            for line in f:
                relpath = _clean_relpath(os.fsdecode(line.rstrip(b"\r\n")))
                if relpath is None:
                    if line.strip():
                        log("Ignoring invalid entry in %s: %r" % (list_file, line))
                    continue
                job = Job(root, relpath)
                if job not in seen:
                    seen.add(job)
                    batch.append(job)
        batch.sort(key=lambda job: PRIORITY.get(job.relpath.split("/", 1)[0], len(PRIORITY)))
        jobs.extend(batch)
    return jobs


def _dropbox_root(value):
    parts = [part for part in value.strip().split("/") if part]
    if any(part in (".", "..") for part in parts):
        raise ConfigError("DROPBOX_PATH must not contain '.' or '..': %r" % value)
    return "/" + "/".join(parts) if parts else ""


def _destination():
    value = os.environ.get("DROPBOX_PATH")
    if value is None:
        raise ConfigError("DROPBOX_PATH is not set")
    return _dropbox_root(value)


def _client_modified(mtime):
    # Leave out timestamps that are clearly wrong (Tesla firmware has been
    # known to write dates far in the future).
    if not 946684800 <= mtime <= time.time() + 86400:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))


def _commit_info(dest, client_modified, autorename=False):
    # mode "add" never overwrites. Uploading a file that Dropbox already has
    # with the same contents is not a conflict, so re-uploading after an
    # interruption is harmless.
    commit = {"path": dest, "mode": "add", "autorename": autorename, "mute": True}
    if client_modified:
        commit["client_modified"] = client_modified
    return commit


def _raise_if_fatal(error):
    if error.has("insufficient_space"):
        raise NoSpaceError("Dropbox is full")
    if error.has("no_write_permission"):
        raise AuthError("Dropbox doesn't allow writing to the archive folder (%s)" % error.summary)


def _remove_source(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        log("WARNING: %s was archived, but could not be removed: %s" % (path, e))


class Stats:
    def __init__(self):
        self.uploaded = 0
        self.already = 0
        self.missing = 0
        self.failed = 0
        self.bytes_sent = 0


class Uploader:
    """Moves files to Dropbox: each file is removed once it is safely stored
    in Dropbox, which is how archiveloop tells which files were archived."""

    def __init__(self, dbx, dest_root, state_dir, chunk_size):
        self.dbx = dbx
        self.dest_root = dest_root
        self.state_dir = state_dir
        self.chunk_size = chunk_size
        self.sessions = SessionStore(os.path.join(state_dir, SESSIONS_FILE))
        self.ledger = None
        self.stats = Stats()

    def run(self, pairs):
        try:
            jobs = read_jobs(pairs)
        except OSError as e:
            log("Could not read the list of files to archive: %s" % e)
            return EXIT_FAILED
        pending = set(jobs)
        self.sessions.prune(pending)
        self.ledger = Ledger(os.path.join(self.state_dir, LEDGER_FILE), pending)
        log("Archiving %d file(s) to the Dropbox folder %s" % (len(jobs), self.dest_root or "/"))
        started = time.monotonic()
        done = 0
        result = EXIT_OK
        try:
            for job in jobs:
                try:
                    self._archive(job)
                except FileError as e:
                    self._failed(job, e)
                except ApiError as e:
                    _raise_if_fatal(e)
                    self._failed(job, e)
                except ArchiveError:
                    raise
                except OSError as e:
                    self._failed(job, e)
                except Exception:
                    self._failed(job, "unexpected error:\n" + traceback.format_exc().rstrip())
                done += 1
        except ArchiveError as e:
            log("Dropbox archiving stopped: %s" % e)
            result = e.exit_code
        finally:
            self._log_summary(len(jobs), done, time.monotonic() - started)
        if result == EXIT_OK and self.stats.failed:
            result = EXIT_FAILED
        return result

    def _failed(self, job, error):
        self.stats.failed += 1
        log("Could not archive %s: %s" % (job.relpath, error))

    def _log_summary(self, total, done, elapsed):
        s = self.stats
        log("Dropbox: archived %d of %d file(s) in %s (%d uploaded, %s sent; %d already in Dropbox), "
            "%d failed, %d missing, %d not attempted"
            % (s.uploaded + s.already, total, _duration(elapsed), s.uploaded, _size(s.bytes_sent), s.already,
               s.failed, s.missing, total - done))

    def _archive(self, job):
        path = os.path.join(job.root, job.relpath)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            # e.g. the snapshot holding it was deleted to free up space
            log("Skipping %s, it no longer exists" % job.relpath)
            self.stats.missing += 1
            return
        if not stat.S_ISREG(st.st_mode):
            raise FileError("not a regular file")
        identity = (job.root, job.relpath, st.st_size, st.st_mtime_ns)
        dest = self.dest_root + "/" + job.relpath
        if self.ledger.has(identity, dest):
            log("%s was already uploaded" % job.relpath)
            _remove_source(path)
            self.stats.already += 1
            return
        started = time.monotonic()
        with open(path, "rb") as f:
            source = Source(f, st.st_size)
            client_modified = _client_modified(st.st_mtime)
            if st.st_size <= self.chunk_size:
                metadata, sent = self._upload_whole(source, dest, client_modified)
            else:
                metadata, sent = self._upload_in_chunks(source, identity, dest, client_modified, job.relpath)
            content_hash = source.content_hash()
        self.stats.bytes_sent += sent
        self._verify(metadata, st.st_size, content_hash)
        self.ledger.add(identity, dest, metadata.get("path_display", dest), content_hash)
        _remove_source(path)
        self.stats.uploaded += 1
        elapsed = time.monotonic() - started
        log("Uploaded %s (%s in %s, %.1f MB/s)"
            % (job.relpath, _size(st.st_size), _duration(elapsed), sent / MIB / max(elapsed, 0.001)))

    def _upload_whole(self, source, dest, client_modified):
        data = source.read(0, source.size)
        try:
            return self.dbx.call("files/upload", _commit_info(dest, client_modified), data), len(data)
        except ApiError as e:
            if not e.has("conflict"):
                raise
            session_id = e.find("upload_session_id")
        log("A different file already exists at %s in Dropbox, keeping both" % dest)
        commit = _commit_info(dest, client_modified, autorename=True)
        if isinstance(session_id, str):
            # Dropbox kept the uploaded data, so it only needs to be committed.
            cursor = {"session_id": session_id, "offset": source.size}
            try:
                return self.dbx.call("files/upload_session/finish", {"cursor": cursor, "commit": commit}, b""), len(data)
            except ApiError as e:
                if not (e.has("not_found") or e.has("closed") or e.has("incorrect_offset")):
                    raise
        return self.dbx.call("files/upload", commit, data), 2 * len(data)

    def _upload_in_chunks(self, source, identity, dest, client_modified, relpath):
        size = source.size
        saved = self.sessions.get(identity, dest)
        if saved:
            session_id, offset = saved["session_id"], saved["offset"]
            log("Resuming the upload of %s at %s of %s" % (relpath, _size(offset), _size(size)))
        else:
            session_id, offset = None, 0
        check = saved is not None
        sent = 0
        autorename = False
        corrections = 0
        restarts = 0
        while True:
            finishing = False
            try:
                if session_id is None:
                    data = source.read(0, self.chunk_size)
                    session_id = self.dbx.call("files/upload_session/start", {"close": False}, data)["session_id"]
                    offset = len(data)
                    sent += len(data)
                    self.sessions.put(identity, dest, session_id, offset)
                    corrections = 0
                elif check:
                    check = False
                    self._check_session(session_id, offset)
                # The last part of the file is sent with the commit.
                while size - offset > self.chunk_size:
                    data = source.read(offset, self.chunk_size)
                    cursor = {"session_id": session_id, "offset": offset}
                    self.dbx.call("files/upload_session/append_v2", {"cursor": cursor, "close": False}, data,
                                  before_retry=lambda cursor=cursor: self._check_session(**cursor))
                    offset += len(data)
                    sent += len(data)
                    self.sessions.update(identity, offset)
                    corrections = 0
                data = source.read(offset, size - offset)
                cursor = {"session_id": session_id, "offset": offset}
                commit = _commit_info(dest, client_modified, autorename)
                finishing = True
                metadata = self.dbx.call("files/upload_session/finish", {"cursor": cursor, "commit": commit}, data,
                                         before_retry=lambda cursor=cursor: self._check_session(**cursor))
                sent += len(data)
                self.sessions.remove(identity)
                return metadata, sent
            except ApiError as e:
                correct = e.find("correct_offset")
                if e.has("incorrect_offset") and isinstance(correct, int) and 0 < correct <= size and corrections < 5:
                    # Dropbox has a different amount of data than expected, e.g.
                    # because the response to a request that went through was
                    # lost. Continue from where Dropbox is.
                    corrections += 1
                    offset = correct
                    self.sessions.update(identity, offset)
                    continue
                if e.has("conflict") and finishing and not autorename:
                    log("A different file already exists at %s in Dropbox, keeping both" % dest)
                    # The data sent with the failed commit was added to the session.
                    autorename = True
                    offset = size
                    continue
                if not (e.has("not_found") or e.has("closed") or e.has("incorrect_offset")):
                    raise
                # The session might be gone because it was committed, even
                # though the response to the commit was lost.
                existing = self._existing_copy(dest, source)
                if existing:
                    self.sessions.remove(identity)
                    return existing, sent
                restarts += 1
                if restarts > 2:
                    raise FileError("the Dropbox upload session keeps failing (%s)" % e.summary)
                log("The upload session for %s can't be used anymore (%s), starting over" % (relpath, e.summary))
                self.sessions.remove(identity)
                session_id, offset, corrections = None, 0, 0

    def _check_session(self, session_id, offset):
        """Checks that Dropbox has offset bytes of the upload session, without
        sending data. Dropbox may reject a request that does have data before
        reading it all, and the connection can then be closed before the error
        arrives, so offset errors would go unnoticed."""
        cursor = {"session_id": session_id, "offset": offset}
        try:
            self.dbx.call("files/upload_session/append_v2", {"cursor": cursor, "close": False}, b"")
        except ApiError as e:
            if e.has("incorrect_offset") or e.has("not_found") or e.has("closed"):
                raise
            log("Could not check the upload session (%s)" % e)

    def _existing_copy(self, dest, source):
        try:
            metadata = self.dbx.call("files/get_metadata", {"path": dest})
        except ApiError as e:
            if e.has("not_found"):
                return None
            raise
        if (metadata.get(".tag") == "file" and metadata.get("size") == source.size
                and metadata.get("content_hash") == source.content_hash()):
            return metadata
        return None

    def _verify(self, metadata, size, content_hash):
        if not isinstance(metadata, dict):
            raise FileError("unexpected response from Dropbox: %r" % (metadata,))
        remote_hash = metadata.get("content_hash")
        if metadata.get("size") == size and remote_hash in (None, content_hash):
            return
        log("The copy in Dropbox doesn't match (size %s, expected %d; content hash %s, expected %s), deleting it"
            % (metadata.get("size"), size, remote_hash, content_hash))
        try:
            self.dbx.call("files/delete_v2", {"path": metadata.get("id") or metadata["path_lower"],
                                              "parent_rev": metadata["rev"]})
        except (ApiError, KeyError) as e:
            log("Could not delete the bad copy: %s" % e)
        raise FileError("the uploaded file failed verification")


def _credentials_from_file(state_dir):
    path = os.path.join(state_dir, CREDENTIALS_FILE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("app_key") and data.get("refresh_token"):
            return Credentials(data["app_key"], data["refresh_token"], data.get("app_secret") or None, path)
        log("Ignoring %s, it doesn't contain an app key and refresh token" % path)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, AttributeError) as e:
        log("Ignoring unreadable %s: %s" % (path, e))
    return None


def _credentials_from_env():
    app_key = os.environ.get("DROPBOX_APP_KEY", "").strip()
    refresh_token = os.environ.get("DROPBOX_REFRESH_TOKEN", "").strip()
    if app_key and refresh_token:
        return Credentials(app_key, refresh_token, os.environ.get("DROPBOX_APP_SECRET", "").strip() or None,
                           "the setup variables")
    return None


def load_credentials(state_dir):
    """The credentials stored by authorize or import-credentials, or else the
    ones given by the DROPBOX_* setup variables."""
    return _credentials_from_file(state_dir) or _credentials_from_env()


def _setup_token_marker(refresh_token):
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def _stored_setup_token_marker(state_dir):
    """Identifies the DROPBOX_REFRESH_TOKEN that was last stored by
    import-credentials, even if authorize replaced it since."""
    try:
        with open(os.path.join(state_dir, CREDENTIALS_FILE), "r", encoding="utf-8") as f:
            return json.load(f).get("setup_token_sha256")
    except (OSError, ValueError, AttributeError):
        return None


def save_credentials(state_dir, credentials, account_id=None, from_setup_variables=False):
    _ensure_private_dir(state_dir)
    path = os.path.join(state_dir, CREDENTIALS_FILE)
    if from_setup_variables:
        marker = _setup_token_marker(credentials.refresh_token)
    else:
        marker = _stored_setup_token_marker(state_dir)
    data = {"app_key": credentials.app_key, "refresh_token": credentials.refresh_token,
            "saved": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if credentials.app_secret:
        data["app_secret"] = credentials.app_secret
    if account_id:
        data["account_id"] = account_id
    if marker:
        data["setup_token_sha256"] = marker
    _write_json(path, data)
    return path


def _account_name(account):
    name = (account.get("name") or {}).get("display_name", "unknown")
    return "%s (%s)" % (name, account.get("email", "no email address"))


def _credentials_work(credentials):
    try:
        with Dropbox(credentials) as dbx:
            dbx.call("users/get_current_account")
        return True
    except (ArchiveError, ApiError):
        return False


def _free_space(usage):
    try:
        allocation = usage["allocation"]
        if allocation[".tag"] == "individual":
            return allocation["allocated"] - usage["used"]
        if allocation.get("user_within_team_space_allocated"):
            return allocation["user_within_team_space_allocated"] - usage["used"]
        return allocation["allocated"] - allocation["used"]
    except (KeyError, TypeError):
        return None


def _int_setting(name, default, low, high):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = None
    if value is None or not low <= value <= high:
        log("Ignoring %s=%r, it must be a number from %d to %d" % (name, raw, low, high))
        return default
    return value


def _chunk_size():
    megabytes = _int_setting("DROPBOX_CHUNK_SIZE_MB", DEFAULT_CHUNK_MB, 4, MAX_CHUNK_MB)
    if megabytes % 4:
        log("Ignoring DROPBOX_CHUNK_SIZE_MB=%d, it must be a multiple of 4" % megabytes)
        megabytes = DEFAULT_CHUNK_MB
    return megabytes * MIB


def _lock(state_dir):
    import fcntl
    fd = os.open(os.path.join(state_dir, LOCK_FILE), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _reachability_check(script, host):
    """A function that runs archive-is-reachable.sh, which also checks the wifi
    network when DROPBOX_WIFI_SSIDS is set."""
    if not script or not os.access(script, os.X_OK):
        return None

    def reachable():
        try:
            return subprocess.run([script, host], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=30).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    return reachable


def cmd_authorize(args):
    app_key = (args.app_key or os.environ.get("DROPBOX_APP_KEY") or "").strip()
    if not app_key:
        app_key = input("Dropbox app key: ").strip()
    if not app_key:
        log("The app key of your Dropbox app is needed, see doc/SetupDropbox.md")
        return EXIT_USAGE
    # PKCE lets teslausb refresh its access token without the app secret.
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    query = urllib.parse.urlencode({
        "client_id": app_key,
        "response_type": "code",
        "token_access_type": "offline",
        "code_challenge": challenge.rstrip(b"=").decode("ascii"),
        "code_challenge_method": "S256",
    })
    log("1. Open this link in a web browser, and sign in to Dropbox if asked:")
    log("")
    log("   %s?%s" % (AUTHORIZE_URL, query))
    log("")
    log("2. Click 'Allow' (you may have to click 'Continue' first).")
    log("3. Copy the access code that Dropbox shows.")
    code = input("4. Paste the access code here, and press Enter: ").strip()
    if not code:
        return EXIT_USAGE
    form = {"code": code, "grant_type": "authorization_code", "client_id": app_key, "code_verifier": verifier}
    http = HttpClient()
    try:
        try:
            status, _, payload = http.post(API_URL, "/oauth2/token",
                                           {"Content-Type": "application/x-www-form-urlencoded"},
                                           urllib.parse.urlencode(form).encode("ascii"))
        except NetworkError as e:
            log("Could not reach Dropbox: %s" % e)
            return EXIT_FAILED
        if status != 200:
            log("Dropbox did not accept the access code: %s" % _oauth_error(payload))
            return EXIT_AUTH
        tokens = json.loads(payload.decode("utf-8"))
        if not tokens.get("refresh_token"):
            log("Dropbox did not provide a refresh token")
            return EXIT_AUTH
        granted = set(tokens.get("scope", "").split())
        missing = [scope for scope in REQUIRED_SCOPES if granted and scope not in granted]
        if missing:
            log("WARNING: teslausb wasn't given the %s permission(s). Enable them on the Permissions tab in the "
                "Dropbox App Console, then authorize again." % ", ".join(missing))
        credentials = Credentials(app_key, tokens["refresh_token"], None, "authorization")
        account = Dropbox(credentials, http).call("users/get_current_account")
    finally:
        http.close()
    log("Linked to the Dropbox account of %s" % _account_name(account))
    if args.print:
        log("Add these lines to teslausb_setup_variables.conf:")
        log("export DROPBOX_APP_KEY=%s" % shlex.quote(app_key))
        log("export DROPBOX_REFRESH_TOKEN=%s" % shlex.quote(credentials.refresh_token))
        return EXIT_OK
    try:
        path = save_credentials(args.state_dir, credentials, tokens.get("account_id"))
    except OSError as e:
        log("Could not save the credentials in %s: %s" % (args.state_dir, e))
        log("(To authorize on another computer, use --print.)")
        return EXIT_FAILED
    log("Saved the Dropbox credentials in %s" % path)
    return EXIT_OK


def cmd_import_credentials(args):
    credentials = _credentials_from_env()
    if credentials is None:
        log("DROPBOX_APP_KEY and DROPBOX_REFRESH_TOKEN must both be set")
        return EXIT_USAGE
    stored = _credentials_from_file(args.state_dir)
    if (stored and stored.refresh_token != credentials.refresh_token
            and _stored_setup_token_marker(args.state_dir) == _setup_token_marker(credentials.refresh_token)):
        log("Keeping the stored Dropbox credentials, which replaced DROPBOX_REFRESH_TOKEN when teslausb was "
            "authorized again. Remove DROPBOX_REFRESH_TOKEN from the setup variables, or delete %s to use it "
            "instead." % stored.source)
        return EXIT_OK
    try:
        with Dropbox(credentials) as dbx:
            account = dbx.call("users/get_current_account")
    except AuthError as e:
        if stored and stored.refresh_token != credentials.refresh_token and _credentials_work(stored):
            log("WARNING: DROPBOX_REFRESH_TOKEN was not accepted (%s). Keeping the credentials stored in %s, "
                "which still work." % (e, stored.source))
            return EXIT_OK
        log(str(e))
        return EXIT_AUTH
    path = save_credentials(args.state_dir, credentials, account.get("account_id"), from_setup_variables=True)
    log("Stored the Dropbox credentials for %s in %s" % (_account_name(account), path))
    return EXIT_OK


def cmd_check(args):
    credentials = load_credentials(args.state_dir)
    if credentials is None:
        log("teslausb has not been authorized to use Dropbox. Run '%s authorize', or set DROPBOX_APP_KEY and "
            "DROPBOX_REFRESH_TOKEN (see doc/SetupDropbox.md)." % SCRIPT)
        return EXIT_NO_CREDENTIALS
    dest_root = _destination()
    with Dropbox(credentials) as dbx:
        log("Using the Dropbox account of %s" % _account_name(dbx.call("users/get_current_account")))
        app_key = os.environ.get("DROPBOX_APP_KEY", "").strip()
        if app_key and app_key != credentials.app_key:
            log("WARNING: DROPBOX_APP_KEY is not the app teslausb was authorized for. Run '%s authorize' to "
                "switch to it." % SCRIPT)
        free = _free_space(dbx.call("users/get_space_usage"))
        if free is not None:
            log("Free space in Dropbox: %s" % _size(max(free, 0)))
            if free < 5 * 1024 * MIB:
                log("WARNING: Dropbox is almost full")
        if dest_root:
            try:
                dbx.call("files/create_folder_v2", {"path": dest_root, "autorename": False})
                log("Created the Dropbox folder %s" % dest_root)
            except ApiError as e:
                if not (e.has("conflict") and e.has("folder")):
                    raise
        test_file = dest_root + "/.teslausb-write-test"
        dbx.call("files/upload", {"path": test_file, "mode": "overwrite", "mute": True}, b"teslausb write test\n")
        dbx.call("files/delete_v2", {"path": test_file})
    log("Recordings will be archived to the Dropbox folder %s" % (dest_root or "/"))
    return EXIT_OK


def cmd_status(args):
    credentials = load_credentials(args.state_dir)
    if credentials is None:
        log("ERROR: no Dropbox credentials found")
    else:
        log("Dropbox credentials: %s (app key %s...)" % (credentials.source, credentials.app_key[:4]))
    log("Dropbox folder: %s" % os.environ.get("DROPBOX_PATH", "(DROPBOX_PATH is not set)"))
    ssids = [ssid for ssid in os.environ.get("DROPBOX_WIFI_SSIDS", "").split("|") if ssid]
    if ssids:
        log("Archiving only on %d specific wifi network(s)" % len(ssids))
    sessions = SessionStore(os.path.join(args.state_dir, SESSIONS_FILE)).sessions.values()
    log("Interrupted uploads that can be resumed: %d" % len(sessions))
    for entry in sessions:
        age = time.time() - entry.get("created", 0)
        log("  %s: %s of %s, started %s ago%s"
            % (entry.get("path"), _size(entry.get("offset", 0)), _size(entry.get("size", 0)), _duration(age),
               " (expired)" if age >= SESSION_MAX_AGE else ""))
    return EXIT_OK


def cmd_upload(args):
    if not args.pairs or len(args.pairs) % 2:
        log("upload needs pairs of arguments: DIR LIST [DIR LIST ...]")
        return EXIT_USAGE
    credentials = load_credentials(args.state_dir)
    if credentials is None:
        log("teslausb has not been authorized to use Dropbox. Run '%s authorize'." % SCRIPT)
        return EXIT_AUTH
    dest_root = _destination()
    _ensure_private_dir(args.state_dir)
    lock = _lock(args.state_dir)
    if lock is None:
        log("Another Dropbox upload is already running")
        return EXIT_FAILED
    try:
        reachable = _reachability_check(args.reachability_script,
                                        os.environ.get("ARCHIVE_SERVER") or "api.dropboxapi.com")
        offline_timeout = _int_setting("DROPBOX_OFFLINE_TIMEOUT", DEFAULT_OFFLINE_TIMEOUT, 0, 86400)
        with Dropbox(credentials, reachable=reachable, offline_timeout=offline_timeout) as dbx:
            uploader = Uploader(dbx, dest_root, args.state_dir, _chunk_size())
            return uploader.run(list(zip(args.pairs[0::2], args.pairs[1::2])))
    finally:
        os.close(lock)


def _terminate(signum, frame):
    raise Terminated()


def main(argv=None):
    parser = argparse.ArgumentParser(description="Archive teslausb recordings to Dropbox.")
    parser.add_argument("--state-dir", default=os.environ.get("DROPBOX_STATE_DIR") or DEFAULT_STATE_DIR,
                        help="where credentials and upload progress are kept (default: %(default)s)")
    commands = parser.add_subparsers(dest="command")
    command = commands.add_parser("authorize", help="link teslausb to a Dropbox account")
    command.add_argument("--app-key", help="the app key of your Dropbox app (default: $DROPBOX_APP_KEY)")
    command.add_argument("--print", action="store_true",
                         help="print the credentials as setup variables instead of saving them")
    command.set_defaults(func=cmd_authorize)
    command = commands.add_parser("import-credentials",
                                  help="store the credentials from DROPBOX_APP_KEY and DROPBOX_REFRESH_TOKEN")
    command.set_defaults(func=cmd_import_credentials)
    command = commands.add_parser("check", help="check the credentials and the archive folder")
    command.set_defaults(func=cmd_check)
    command = commands.add_parser("status", help="show the configuration and interrupted uploads")
    command.set_defaults(func=cmd_status)
    command = commands.add_parser("upload", help="archive files, removing each once it is in Dropbox")
    command.add_argument("--reachability-script",
                         default=os.path.join(os.path.dirname(SCRIPT), "archive-is-reachable.sh"))
    command.add_argument("pairs", nargs="*", metavar="DIR LIST")
    command.set_defaults(func=cmd_upload)
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_USAGE

    previous_handler = signal.signal(signal.SIGTERM, _terminate)
    try:
        return args.func(args)
    except ArchiveError as e:
        log(str(e))
        return e.exit_code
    except ApiError as e:
        log("Dropbox error: %s" % e)
        return EXIT_FAILED
    except OSError as e:
        log("Error: %s" % e)
        return EXIT_FAILED
    except Terminated:
        log("Stopped, upload progress has been saved")
        return 128 + signal.SIGTERM
    except (KeyboardInterrupt, EOFError):
        log("Interrupted")
        return 130
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


if __name__ == "__main__":
    sys.exit(main())
