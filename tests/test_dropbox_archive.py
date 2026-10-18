#!/usr/bin/env python3
"""Tests for run/dropbox_archive, against a fake Dropbox server.

Run with: python3 -m unittest discover -s tests -p 'test_*.py'
"""

import base64
import hashlib
import http.server
import importlib.util
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.parse
from unittest import mock

sys.dont_write_bytecode = True

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_DIR = os.path.join(REPO, "run", "dropbox_archive")


def load_module():
    spec = importlib.util.spec_from_file_location("dropbox_archive", os.path.join(MODULE_DIR, "dropbox_archive.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dba = load_module()

MIB = 1024 * 1024


def reference_content_hash(data):
    """The algorithm from https://www.dropbox.com/developers/reference/content-hash"""
    block = 4 * MIB
    digests = b"".join(hashlib.sha256(data[i:i + block]).digest() for i in range(0, len(data), block))
    return hashlib.sha256(digests).hexdigest()


def pattern(size, seed=0):
    start = seed % 251
    return (bytes(range(251)) * (size // 251 + 2))[start:start + size]


class Conflict(Exception):
    pass


class NoSpace(Exception):
    pass


def api_error(status, summary, error):
    return status, {"error_summary": summary, "error": error}


class FakeDropbox:
    """Imitates the parts of the Dropbox API that dropbox_archive.py uses,
    with the semantics documented in the Dropbox API specification."""

    APP_KEY = "test-app-key"
    REFRESH_TOKEN = "test-refresh-token"

    def __init__(self):
        self.lock = threading.RLock()
        self.files = {}
        self.folders = set()
        self.sessions = {}
        self.refresh_tokens = {self.REFRESH_TOKEN: self.APP_KEY}
        self.access_tokens = {}
        self.auth_codes = {}
        self.faults = []
        self.requests = []
        self.quota = None
        self.online = True
        self.corrupt_next_commit = False
        # Reject requests with a wrong upload session or offset before reading
        # their data, and close the connection.
        self.early_reject = False
        self._counter = 0

    def next_id(self):
        self._counter += 1
        return self._counter

    def add_fault(self, route, action, times=1, skip=0, **details):
        """Makes the (skip+1)th and following matching requests misbehave."""
        self.faults.append(dict(route=route, action=action, times=times, skip=skip, **details))

    def take_fault(self, route):
        with self.lock:
            for fault in self.faults:
                if fault["route"] == route and fault["times"] > 0:
                    if fault["skip"] > 0:
                        fault["skip"] -= 1
                        continue
                    fault["times"] -= 1
                    return fault
        return None

    def requests_for(self, route):
        return [r for r in self.requests if r[0] == route]

    def bytes_received(self, since=0):
        return sum(r[2] for r in self.requests[since:] if r[2])

    def put_file(self, path, data):
        with self.lock:
            number = self.next_id()
            self.files[path.lower()] = {"path": path, "data": bytes(data), "rev": "%09x" % (0x100000000 + number),
                                        "id": "id:file%d" % number, "client_modified": None}

    def remote(self, path):
        entry = self.files.get(path.lower())
        return entry["data"] if entry else None

    def metadata(self, entry):
        return {".tag": "file", "name": entry["path"].rsplit("/", 1)[-1], "path_lower": entry["path"].lower(),
                "path_display": entry["path"], "id": entry["id"], "rev": entry["rev"], "size": len(entry["data"]),
                "content_hash": reference_content_hash(entry["data"]), "client_modified": entry["client_modified"]}

    def handle(self, route, headers, body):
        with self.lock:
            if route == "/oauth2/token":
                return self.token({k: v[0] for k, v in urllib.parse.parse_qs(body.decode("ascii")).items()})
            authorization = headers.get("Authorization", "")
            token = authorization[len("Bearer "):] if authorization.startswith("Bearer ") else None
            if token not in self.access_tokens:
                return api_error(401, "invalid_access_token/", {".tag": "invalid_access_token"})
            if self.access_tokens[token]:
                return api_error(401, "expired_access_token/", {".tag": "expired_access_token"})
            if "Dropbox-API-Arg" in headers:
                assert headers["Content-Type"] == "application/octet-stream"
                arg = json.loads(headers["Dropbox-API-Arg"])
            else:
                assert headers["Content-Type"] == "application/json"
                arg, body = json.loads(body.decode("utf-8")), None
            self.requests.append((route, arg, None if body is None else len(body)))
            return getattr(self, "route_" + route[len("/2/"):].replace("/", "_"))(arg, body)

    def token(self, form):
        if form.get("grant_type") == "refresh_token":
            if self.refresh_tokens.get(form.get("refresh_token")) != form.get("client_id"):
                return 400, {"error": "invalid_grant", "error_description": "refresh token is invalid or revoked"}
            self.requests.append(("/oauth2/token", None, None))
            return 200, {"access_token": self.new_access_token(), "token_type": "bearer", "expires_in": 14400}
        if form.get("grant_type") == "authorization_code":
            verifier = form.get("code_verifier", "").encode("ascii")
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier).digest()).rstrip(b"=").decode("ascii")
            if self.auth_codes.pop(form.get("code"), None) != (form.get("client_id"), challenge):
                return 400, {"error": "invalid_grant", "error_description": "code doesn't exist or has expired"}
            refresh_token = "refresh-%d" % self.next_id()
            self.refresh_tokens[refresh_token] = form["client_id"]
            return 200, {"access_token": self.new_access_token(), "refresh_token": refresh_token,
                         "expires_in": 14400, "token_type": "bearer", "account_id": "dbid:test", "uid": "12345",
                         "scope": "account_info.read files.content.write files.metadata.read"}
        return 400, {"error": "unsupported_grant_type"}

    def new_access_token(self):
        token = "access-%d" % self.next_id()
        self.access_tokens[token] = False
        return token

    def expire_tokens(self):
        with self.lock:
            for token in self.access_tokens:
                self.access_tokens[token] = True

    def commit(self, commit, data):
        path = commit["path"]
        mode = commit.get("mode", "add")
        mode = mode[".tag"] if isinstance(mode, dict) else mode
        existing = self.files.get(path.lower())
        if existing is not None:
            if existing["data"] == data and not commit.get("strict_conflict"):
                # "If the target path refers to a file with identical contents,
                # nothing gets written; no conflict."
                return self.metadata(existing)
            if mode != "overwrite":
                if not commit.get("autorename"):
                    raise Conflict()
                stem, dot, extension = path.rpartition(".")
                number = 1
                while ("%s (%d).%s" % (stem, number, extension)).lower() in self.files:
                    number += 1
                path = "%s (%d).%s" % (stem, number, extension)
        if self.quota is not None and sum(len(f["data"]) for f in self.files.values()) + len(data) > self.quota:
            raise NoSpace()
        if self.corrupt_next_commit:
            self.corrupt_next_commit = False
            data = bytes([data[0] ^ 1]) + data[1:]
        self.put_file(path, data)
        entry = self.files[path.lower()]
        entry["client_modified"] = commit.get("client_modified")
        return self.metadata(entry)

    def route_users_get_current_account(self, arg, body):
        return 200, {"account_id": "dbid:test", "name": {"display_name": "Test User"}, "email": "test@example.com"}

    def route_users_get_space_usage(self, arg, body):
        used = sum(len(f["data"]) for f in self.files.values())
        return 200, {"used": used, "allocation": {".tag": "individual", "allocated": self.quota or 2 << 40}}

    def route_files_upload(self, arg, body):
        try:
            return 200, self.commit(arg, body)
        except Conflict:
            session_id = "session-%d" % self.next_id()
            self.sessions[session_id] = bytearray(body)
            return api_error(409, "path/conflict/file/..", {".tag": "path", "reason": {
                ".tag": "conflict", "conflict": {".tag": "file"}}, "upload_session_id": session_id})
        except NoSpace:
            return api_error(409, "path/insufficient_space/..", {".tag": "path", "reason": {
                ".tag": "insufficient_space"}, "upload_session_id": "unused"})

    def route_files_upload_session_start(self, arg, body):
        session_id = "session-%d" % self.next_id()
        self.sessions[session_id] = bytearray(body)
        return 200, {"session_id": session_id}

    def session_error(self, cursor):
        data = self.sessions.get(cursor["session_id"])
        if data is None:
            return api_error(409, "not_found/...", {".tag": "not_found"})
        if cursor["offset"] != len(data):
            return api_error(409, "incorrect_offset/...", {".tag": "incorrect_offset", "correct_offset": len(data)})
        return None

    def route_files_upload_session_append_v2(self, arg, body):
        error = self.session_error(arg["cursor"])
        if error:
            return error
        self.sessions[arg["cursor"]["session_id"]].extend(body)
        return 200, None

    def route_files_upload_session_finish(self, arg, body):
        cursor = arg["cursor"]
        data = self.sessions.get(cursor["session_id"])
        if data is None:
            return api_error(409, "lookup_failed/not_found/..", {".tag": "lookup_failed", "lookup_failed": {
                ".tag": "not_found"}})
        if cursor["offset"] != len(data):
            return api_error(409, "lookup_failed/incorrect_offset/..", {".tag": "lookup_failed", "lookup_failed": {
                ".tag": "incorrect_offset", "correct_offset": len(data)}})
        # "Data has already been appended to the upload session" even if the commit fails.
        data.extend(body)
        try:
            metadata = self.commit(arg["commit"], bytes(data))
        except Conflict:
            return api_error(409, "path/conflict/file/..", {".tag": "path", "path": {
                ".tag": "conflict", "conflict": {".tag": "file"}}})
        except NoSpace:
            return api_error(409, "path/insufficient_space/..", {".tag": "path", "path": {
                ".tag": "insufficient_space"}})
        del self.sessions[cursor["session_id"]]
        return 200, metadata

    def route_files_get_metadata(self, arg, body):
        entry = self.files.get(arg["path"].lower())
        if entry is None:
            return api_error(409, "path/not_found/.", {".tag": "path", "path": {".tag": "not_found"}})
        return 200, self.metadata(entry)

    def route_files_delete_v2(self, arg, body):
        path = arg["path"]
        key = next((k for k, f in self.files.items() if f["id"] == path), None) if path.startswith("id:") else path.lower()
        entry = self.files.get(key)
        if entry is None:
            return api_error(409, "path_lookup/not_found/.", {".tag": "path_lookup", "path_lookup": {".tag": "not_found"}})
        if arg.get("parent_rev") not in (None, entry["rev"]):
            return api_error(409, "path_write/conflict/file/.", {".tag": "path_write"})
        del self.files[key]
        return 200, {"metadata": self.metadata(entry)}

    def route_files_create_folder_v2(self, arg, body):
        path = arg["path"]
        if path.lower() in self.folders:
            return api_error(409, "path/conflict/folder/.", {".tag": "path", "path": {".tag": "conflict"}})
        self.folders.add(path.lower())
        return 200, {"metadata": {"name": path.rsplit("/", 1)[-1], "path_display": path, "id": "id:folder"}}


class FakeHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        fake = self.server.fake
        if not fake.online:
            # like a dropped wifi connection: no response at all
            self.close_connection = True
            return
        if fake.early_reject and self.path in ("/2/files/upload_session/append_v2", "/2/files/upload_session/finish"):
            with fake.lock:
                error = fake.session_error(json.loads(self.headers["Dropbox-API-Arg"])["cursor"])
            if error and int(self.headers["Content-Length"]):
                self.respond(error[0], json.dumps(error[1]).encode("utf-8"))
                self.close_connection = True
                return
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        fault = fake.take_fault(self.path)
        action = fault["action"] if fault else None
        if action in ("disconnect", "go_offline"):
            fake.online = action != "go_offline"
            self.close_connection = True
            return
        if action == "status":
            self.respond(fault["status"], fault.get("body", b"{}"), fault.get("headers"))
            return
        if action == "expire_tokens":
            fake.expire_tokens()
        status, payload = fake.handle(self.path, self.headers, body)
        if action in ("lose_response", "lose_response_go_offline"):
            fake.online = action != "lose_response_go_offline"
            self.close_connection = True
            return
        self.respond(status, json.dumps(payload).encode("utf-8"))

    def respond(self, status, payload, headers=None):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class FakeServer:
    def __init__(self):
        self.fake = FakeDropbox()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeHandler)
        self.httpd.daemon_threads = True
        self.httpd.fake = self.fake
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, args=(0.05,), daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class FakeServerTestCase(unittest.TestCase):
    def setUp(self):
        self.server = FakeServer()
        self.addCleanup(self.server.close)
        self.fake = self.server.fake
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)


class UploaderTest(FakeServerTestCase):
    def setUp(self):
        super().setUp()
        self.logs = []
        self.sleeps = []
        for name, value in [("API_URL", self.server.url), ("CONTENT_URL", self.server.url),
                            ("REACHABILITY_INTERVAL", 0.01), ("log", self.logs.append), ("_sleep", self.fast_sleep)]:
            patcher = mock.patch.object(dba, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.state_dir = os.path.join(self.tmp, "state")
        os.mkdir(self.state_dir)
        # Like archiveloop: the files to archive are symlinks into snapshots.
        self.snapshot = os.path.join(self.tmp, "snapshot")
        self.source = os.path.join(self.tmp, "merged")
        self.lists = 0

    def fast_sleep(self, seconds):
        self.sleeps.append(seconds)
        time.sleep(min(seconds, 0.01))

    def add_file(self, relpath, data, mtime=1760000000):
        target = os.path.join(self.snapshot, relpath)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(data)
        os.utime(target, (mtime, mtime))
        self.link(relpath)
        return data

    def link(self, relpath, root=None):
        link = os.path.join(root or self.source, relpath)
        os.makedirs(os.path.dirname(link), exist_ok=True)
        if not os.path.lexists(link):
            os.symlink(os.path.join(self.snapshot, relpath), link)

    def is_pending(self, relpath):
        return os.path.lexists(os.path.join(self.source, relpath))

    def write_list(self, relpaths):
        self.lists += 1
        path = os.path.join(self.tmp, "list%d.txt" % self.lists)
        with open(path, "w") as f:
            f.write("".join(relpath + "\n" for relpath in relpaths))
        return path

    def uploader(self, chunk_size=64 * 1024, offline_timeout=1):
        credentials = dba.Credentials(FakeDropbox.APP_KEY, FakeDropbox.REFRESH_TOKEN, None, "test")
        dbx = dba.Dropbox(credentials, reachable=lambda: self.fake.online, offline_timeout=offline_timeout)
        self.addCleanup(dbx.http.close)
        return dba.Uploader(dbx, "/TeslaCam", self.state_dir, chunk_size)

    def run_upload(self, relpaths, **kwargs):
        self.last_uploader = self.uploader(**kwargs)
        return self.last_uploader.run([(self.source, self.write_list(relpaths))])

    def saved_sessions(self):
        with open(os.path.join(self.state_dir, "sessions.json")) as f:
            return json.load(f)["sessions"]

    def assert_archived(self, relpath, data):
        self.assertEqual(self.fake.remote("/TeslaCam/" + relpath), data)
        self.assertFalse(self.is_pending(relpath))
        # only the link is removed, never the recording it points to
        self.assertTrue(os.path.exists(os.path.join(self.snapshot, relpath)))


class ContentHashTest(unittest.TestCase):
    def test_matches_reference_implementation(self):
        for size in (0, 1, 4 * MIB - 1, 4 * MIB, 4 * MIB + 1, 9 * MIB + 12345):
            data = pattern(size)
            hasher = dba.ContentHasher()
            for start in range(0, size, 1000003):
                hasher.update(data[start:start + 1000003])
            self.assertEqual(hasher.hexdigest(), reference_content_hash(data), "size %d" % size)

    def test_hash_is_complete_when_reading_out_of_order(self):
        import io
        data = pattern(9 * MIB)
        source = dba.Source(io.BytesIO(data), len(data))
        source.read(5 * MIB, 4 * MIB)
        source.read(5 * MIB, 4 * MIB)
        self.assertEqual(source.content_hash(), reference_content_hash(data))


class UploadTest(UploaderTest):
    def test_uploads_small_and_chunked_files(self):
        small = self.add_file("SavedClips/2026-10-17_10-00-00/event.json", b'{"reason": "user_interaction_dashcam"}')
        large = self.add_file("SavedClips/2026-10-17_10-00-00/2026-10-17_09-59-00-front.mp4", pattern(200 * 1024))
        self.assertEqual(self.run_upload(["SavedClips/2026-10-17_10-00-00/event.json",
                                          "SavedClips/2026-10-17_10-00-00/2026-10-17_09-59-00-front.mp4"]), 0)
        self.assert_archived("SavedClips/2026-10-17_10-00-00/event.json", small)
        self.assert_archived("SavedClips/2026-10-17_10-00-00/2026-10-17_09-59-00-front.mp4", large)
        routes = [r[0].rsplit("/2/files/", 1)[-1] for r in self.fake.requests if r[0].startswith("/2/files/")]
        self.assertEqual(routes, ["upload", "upload_session/start", "upload_session/append_v2",
                                  "upload_session/append_v2", "upload_session/finish"])
        commit = self.fake.requests[-1][1]["commit"]
        self.assertEqual(commit["mode"], "add")
        self.assertEqual(commit["client_modified"], "2025-10-09T08:53:20Z")
        self.assertTrue(commit["mute"])
        self.assertEqual(self.saved_sessions(), [])
        self.assertEqual(self.last_uploader.stats.uploaded, 2)

    def test_most_important_recordings_go_first(self):
        names = ["RecentClips/2026-10-17/2026-10-17_09-00-00-front.mp4",
                 "SentryClips/2026-10-17_11-00-00/2026-10-17_10-59-00-front.mp4",
                 "SavedClips/2026-10-17_12-00-00/2026-10-17_11-59-00-front.mp4"]
        for name in names:
            self.add_file(name, b"x" * 100)
        self.assertEqual(self.run_upload(names), 0)
        uploaded = [r[1]["path"] for r in self.fake.requests_for("/2/files/upload")]
        self.assertEqual(uploaded, ["/TeslaCam/" + name for name in reversed(names)])

    def test_trigger_files_are_uploaded_after_the_clips(self):
        self.add_file("SavedClips/2026-10-17_12-00-00/2026-10-17_11-59-00-front.mp4", b"clip")
        triggers = os.path.join(self.tmp, "triggers")
        os.makedirs(os.path.join(triggers, "SavedClips"))
        open(os.path.join(triggers, "SavedClips", "ARCHIVE_UPLOADED"), "w").close()
        result = self.uploader().run([
            (self.source, self.write_list(["SavedClips/2026-10-17_12-00-00/2026-10-17_11-59-00-front.mp4"])),
            (triggers, self.write_list(["SavedClips/ARCHIVE_UPLOADED"]))])
        self.assertEqual(result, 0)
        uploaded = [r[1]["path"] for r in self.fake.requests_for("/2/files/upload")]
        self.assertEqual(uploaded[-1], "/TeslaCam/SavedClips/ARCHIVE_UPLOADED")
        self.assertEqual(self.fake.remote("/TeslaCam/SavedClips/ARCHIVE_UPLOADED"), b"")
        self.assertFalse(os.path.exists(os.path.join(triggers, "SavedClips", "ARCHIVE_UPLOADED")))

    def test_folder_names_with_spaces_and_accents(self):
        data = self.add_file("SavedClips/2026-10-17_10-00-00/event.json", b"{}")
        uploader = self.uploader()
        uploader.dest_root = dba._dropbox_root(" Tesla Cam/Müller\x7f/ ")
        self.assertEqual(uploader.run([(self.source, self.write_list(["SavedClips/2026-10-17_10-00-00/event.json"]))]), 0)
        self.assertEqual(self.fake.remote("/Tesla Cam/Müller\x7f/SavedClips/2026-10-17_10-00-00/event.json"), data)

    def test_unsafe_list_entries_are_ignored(self):
        self.add_file("SavedClips/a.mp4", b"a")
        self.assertEqual(self.run_upload(["../outside", "/etc/passwd", "SavedClips/../../x", "./SavedClips/a.mp4"]), 0)
        self.assertEqual([r[1]["path"] for r in self.fake.requests_for("/2/files/upload")], ["/TeslaCam/SavedClips/a.mp4"])
        self.assertTrue(any("Ignoring invalid entry" in line for line in self.logs))

    def test_missing_recordings_are_skipped(self):
        self.link("SavedClips/gone.mp4")
        self.add_file("SavedClips/here.mp4", b"here")
        self.assertEqual(self.run_upload(["SavedClips/gone.mp4", "SavedClips/here.mp4"]), 0)
        self.assertTrue(self.is_pending("SavedClips/gone.mp4"))
        self.assertEqual(self.last_uploader.stats.missing, 1)
        self.assert_archived("SavedClips/here.mp4", b"here")


class ResumeTest(UploaderTest):
    NAME = "SentryClips/2026-10-17_10-00-00/2026-10-17_09-59-00-back.mp4"

    def interrupted_upload(self, data):
        """Uploads data, losing the connection during the third append."""
        self.add_file(self.NAME, data)
        self.fake.add_fault("/2/files/upload_session/append_v2", "go_offline", skip=2)
        self.assertEqual(self.run_upload([self.NAME], offline_timeout=0.2), dba.EXIT_UNREACHABLE)
        self.assertTrue(self.is_pending(self.NAME))
        self.assertIsNone(self.fake.remote("/TeslaCam/" + self.NAME))
        [session] = self.saved_sessions()
        self.assertEqual(session["offset"], 3 * 64 * 1024)
        self.fake.online = True
        return session

    def test_resumes_where_the_previous_run_stopped(self):
        data = pattern(10 * 64 * 1024 + 1000)
        session = self.interrupted_upload(data)
        received = len(self.fake.requests)
        self.assertEqual(self.run_upload([self.NAME]), 0)
        self.assert_archived(self.NAME, data)
        # only the part that wasn't uploaded yet was sent again
        self.assertEqual(self.fake.bytes_received(received), len(data) - session["offset"])
        self.assertEqual(len(self.fake.requests_for("/2/files/upload_session/start")), 1)
        self.assertTrue(any("Resuming the upload" in line for line in self.logs))
        self.assertEqual(self.saved_sessions(), [])

    def test_continues_when_the_connection_comes_back_quickly(self):
        data = self.add_file(self.NAME, pattern(6 * 64 * 1024))
        self.fake.add_fault("/2/files/upload_session/append_v2", "go_offline", skip=1)
        threading.Timer(0.3, setattr, (self.fake, "online", True)).start()
        self.assertEqual(self.run_upload([self.NAME], offline_timeout=10), 0)
        self.assert_archived(self.NAME, data)
        self.assertIn("Dropbox is reachable again", self.logs)

    def test_lost_response_is_corrected_with_the_offset_dropbox_reports(self):
        data = self.add_file(self.NAME, pattern(6 * 64 * 1024 + 5))
        self.fake.add_fault("/2/files/upload_session/append_v2", "lose_response", skip=1)
        self.assertEqual(self.run_upload([self.NAME]), 0)
        self.assert_archived(self.NAME, data)

    def test_dropped_connection_is_retried(self):
        data = self.add_file(self.NAME, pattern(6 * 64 * 1024 + 5))
        self.fake.add_fault("/2/files/upload_session/append_v2", "disconnect", times=2, skip=1)
        self.assertEqual(self.run_upload([self.NAME]), 0)
        self.assert_archived(self.NAME, data)

    def test_stale_offset_is_corrected_before_resuming(self):
        data = self.add_file(self.NAME, pattern(10 * 64 * 1024 + 9))
        # the third append reaches Dropbox, but the response doesn't come back
        self.fake.add_fault("/2/files/upload_session/append_v2", "lose_response_go_offline", skip=2)
        self.assertEqual(self.run_upload([self.NAME], offline_timeout=0.2), dba.EXIT_UNREACHABLE)
        [session] = self.saved_sessions()
        self.assertEqual(session["offset"], 3 * 64 * 1024)
        self.fake.online = True
        self.fake.early_reject = True
        received = len(self.fake.requests)
        self.assertEqual(self.run_upload([self.NAME]), 0)
        self.assert_archived(self.NAME, data)
        self.assertEqual(self.fake.bytes_received(received), len(data) - 4 * 64 * 1024)

    def early_rejected_upload(self):
        data = self.add_file(self.NAME, pattern(2 * 16 * MIB + 5))
        self.fake.early_reject = True
        self.fake.add_fault("/2/files/upload_session/append_v2", "lose_response")
        return data, self.run_upload([self.NAME], chunk_size=16 * MIB)

    def test_offset_is_corrected_when_dropbox_rejects_before_reading_data(self):
        data, result = self.early_rejected_upload()
        self.assertEqual(result, 0)
        self.assert_archived(self.NAME, data)

    def test_early_rejection_is_reproduced(self):
        # Without checking the session first, the test above fails.
        with mock.patch.object(dba.Uploader, "_check_session", lambda *args, **kwargs: None), \
                mock.patch.object(dba, "MAX_ATTEMPTS", 3):
            self.assertEqual(self.early_rejected_upload()[1], dba.EXIT_FAILED)
        self.assertTrue(any("failed 3 times" in line and "BrokenPipeError" in line for line in self.logs), self.logs)

    def test_lost_response_to_the_commit_is_recognized(self):
        data = self.add_file(self.NAME, pattern(3 * 64 * 1024 + 5))
        self.fake.add_fault("/2/files/upload_session/finish", "lose_response")
        self.assertEqual(self.run_upload([self.NAME]), 0)
        self.assert_archived(self.NAME, data)
        self.assertEqual(len(self.fake.requests_for("/2/files/upload_session/start")), 1)
        self.assertEqual(len(self.fake.requests_for("/2/files/get_metadata")), 1)

    def test_starts_over_when_dropbox_expired_the_session(self):
        data = pattern(8 * 64 * 1024)
        self.interrupted_upload(data)
        self.fake.sessions.clear()
        self.assertEqual(self.run_upload([self.NAME]), 0)
        self.assert_archived(self.NAME, data)
        self.assertTrue(any("starting over" in line for line in self.logs))

    def test_session_older_than_48_hours_is_not_resumed(self):
        data = pattern(8 * 64 * 1024)
        session = self.interrupted_upload(data)
        path = os.path.join(self.state_dir, "sessions.json")
        session["created"] -= 47 * 3600
        with open(path, "w") as f:
            json.dump({"sessions": [session]}, f)
        received = len(self.fake.requests)
        self.assertEqual(self.run_upload([self.NAME]), 0)
        self.assert_archived(self.NAME, data)
        new_requests = self.fake.requests[received:]
        self.assertFalse([r for r in new_requests if r[1] and r[1].get("cursor", {}).get("session_id") == session["session_id"]])

    def test_changed_file_is_not_resumed(self):
        self.interrupted_upload(pattern(8 * 64 * 1024))
        data = self.add_file(self.NAME, pattern(8 * 64 * 1024, seed=3), mtime=1760000100)
        self.assertEqual(self.run_upload([self.NAME]), 0)
        self.assert_archived(self.NAME, data)
        self.assertEqual(len(self.fake.requests_for("/2/files/upload_session/start")), 2)


class FailureTest(UploaderTest):
    def test_expired_access_token_is_refreshed(self):
        data = self.add_file("SavedClips/a.mp4", pattern(5 * 64 * 1024))
        self.fake.add_fault("/2/files/upload_session/append_v2", "expire_tokens", skip=1)
        self.assertEqual(self.run_upload(["SavedClips/a.mp4"]), 0)
        self.assert_archived("SavedClips/a.mp4", data)
        self.assertEqual(len(self.fake.requests_for("/oauth2/token")), 2)

    def test_revoked_credentials_stop_the_run(self):
        self.add_file("SavedClips/a.mp4", b"a")
        self.fake.refresh_tokens.clear()
        self.assertEqual(self.run_upload(["SavedClips/a.mp4"]), dba.EXIT_AUTH)
        self.assertTrue(self.is_pending("SavedClips/a.mp4"))
        self.assertTrue(any("authorize" in line for line in self.logs))

    def test_rate_limit_is_respected(self):
        data = self.add_file("SavedClips/a.mp4", b"a")
        self.fake.add_fault("/2/files/upload", "status", status=429, headers={"Retry-After": "7"},
                            body=b'{"error_summary": "too_many_requests/..", "error": {"reason": {".tag": "too_many_requests"}}}')
        self.assertEqual(self.run_upload(["SavedClips/a.mp4"]), 0)
        self.assert_archived("SavedClips/a.mp4", data)
        self.assertIn(7, self.sleeps)

    def test_gives_up_when_the_connection_keeps_dropping(self):
        self.add_file("SavedClips/a.mp4", pattern(3 * 64 * 1024))
        self.fake.add_fault("/2/files/upload_session/append_v2", "disconnect", times=1000)
        uploader = self.uploader()
        flapping = itertools.cycle([False, True])
        uploader.dbx.reachable = lambda: next(flapping)
        # not EXIT_UNREACHABLE, which would have archiveloop try again right away
        self.assertEqual(uploader.run([(self.source, self.write_list(["SavedClips/a.mp4"]))]), dba.EXIT_FAILED)
        self.assertTrue(any("keeps dropping" in line for line in self.logs))
        self.assertTrue(self.is_pending("SavedClips/a.mp4"))

    def test_persistent_server_errors_stop_the_run(self):
        self.add_file("SavedClips/a.mp4", b"a")
        self.add_file("SavedClips/b.mp4", b"b")
        self.fake.add_fault("/2/files/upload", "status", status=503, times=100)
        with mock.patch.object(dba, "MAX_ATTEMPTS", 3):
            self.assertEqual(self.run_upload(["SavedClips/a.mp4", "SavedClips/b.mp4"]), dba.EXIT_FAILED)
        self.assertTrue(self.is_pending("SavedClips/a.mp4") and self.is_pending("SavedClips/b.mp4"))
        self.assertEqual(len(self.fake.requests_for("/2/files/upload")), 0)
        self.assertTrue(any("2 not attempted" in line for line in self.logs))

    def test_upload_that_fails_verification_is_deleted_and_kept_locally(self):
        self.add_file("SavedClips/a.mp4", pattern(1000))
        self.fake.corrupt_next_commit = True
        self.assertEqual(self.run_upload(["SavedClips/a.mp4"]), dba.EXIT_FAILED)
        self.assertTrue(self.is_pending("SavedClips/a.mp4"))
        self.assertEqual(self.fake.files, {})
        self.assertEqual(len(self.fake.requests_for("/2/files/delete_v2")), 1)

    def test_full_dropbox_stops_the_run(self):
        self.add_file("SavedClips/a.mp4", pattern(1000))
        self.add_file("SavedClips/b.mp4", pattern(1000))
        self.fake.quota = 500
        self.assertEqual(self.run_upload(["SavedClips/a.mp4", "SavedClips/b.mp4"]), dba.EXIT_NO_SPACE)
        self.assertTrue(self.is_pending("SavedClips/a.mp4") and self.is_pending("SavedClips/b.mp4"))
        self.assertEqual(len(self.fake.requests_for("/2/files/upload")), 1)


class ExistingFileTest(UploaderTest):
    def test_identical_file_in_dropbox_is_not_duplicated(self):
        data = self.add_file("SavedClips/a.mp4", pattern(1000))
        self.fake.put_file("/TeslaCam/SavedClips/a.mp4", data)
        self.assertEqual(self.run_upload(["SavedClips/a.mp4"]), 0)
        self.assert_archived("SavedClips/a.mp4", data)
        self.assertEqual(len(self.fake.files), 1)

    def test_different_file_in_dropbox_is_kept(self):
        data = self.add_file("SavedClips/a.mp4", pattern(1000))
        self.fake.put_file("/TeslaCam/SavedClips/a.mp4", b"something else")
        self.assertEqual(self.run_upload(["SavedClips/a.mp4"]), 0)
        self.assertEqual(self.fake.remote("/TeslaCam/SavedClips/a.mp4"), b"something else")
        self.assertEqual(self.fake.remote("/TeslaCam/SavedClips/a (1).mp4"), data)
        self.assertFalse(self.is_pending("SavedClips/a.mp4"))
        # the data that was already uploaded was committed, not sent again
        self.assertEqual(len(self.fake.requests_for("/2/files/upload")), 1)
        self.assertEqual(self.fake.requests_for("/2/files/upload_session/finish")[0][2], 0)

    def test_different_file_in_dropbox_is_kept_for_chunked_upload(self):
        data = self.add_file("SavedClips/a.mp4", pattern(3 * 64 * 1024 + 7))
        self.fake.put_file("/TeslaCam/SavedClips/a.mp4", b"something else")
        self.assertEqual(self.run_upload(["SavedClips/a.mp4"]), 0)
        self.assertEqual(self.fake.remote("/TeslaCam/SavedClips/a (1).mp4"), data)
        self.assertEqual(self.fake.bytes_received(), len(data))

    def test_files_uploaded_before_a_power_loss_are_not_uploaded_again(self):
        names = ["SavedClips/a.mp4", "SavedClips/b.mp4"]
        for name in names:
            self.add_file(name, pattern(100 * 1024))
        self.assertEqual(self.run_upload(names), 0)
        # archiveloop's record of what was archived was lost, so the same
        # files are offered again
        for name in names:
            self.link(name)
        received = len(self.fake.requests)
        self.assertEqual(self.run_upload(names), 0)
        self.assertEqual(self.fake.requests[received:], [])
        self.assertFalse(self.is_pending("SavedClips/a.mp4") or self.is_pending("SavedClips/b.mp4"))
        self.assertEqual(self.last_uploader.stats.already, 2)
        # entries for files archiveloop did record are dropped
        self.add_file("SavedClips/c.mp4", b"c")
        self.assertEqual(self.run_upload(["SavedClips/c.mp4"]), 0)
        with open(os.path.join(self.state_dir, "uploaded.jsonl")) as f:
            self.assertEqual([json.loads(line)["path"] for line in f], ["SavedClips/c.mp4"])

    def test_trigger_files_dont_make_the_ledger_grow(self):
        triggers = os.path.join(self.tmp, "triggers")
        os.makedirs(os.path.join(triggers, "SavedClips"))
        for run in range(3):
            trigger = os.path.join(triggers, "SavedClips", "ARCHIVE_UPLOADED")
            open(trigger, "w").close()
            os.utime(trigger, (1760000000 + run, 1760000000 + run))
            self.assertEqual(self.uploader().run([(triggers, self.write_list(["SavedClips/ARCHIVE_UPLOADED"]))]), 0)
        with open(os.path.join(self.state_dir, "uploaded.jsonl")) as f:
            self.assertEqual(len(f.readlines()), 1)

    def test_files_are_uploaded_again_when_the_destination_changed(self):
        self.add_file("SavedClips/a.mp4", b"a")
        self.assertEqual(self.run_upload(["SavedClips/a.mp4"]), 0)
        self.link("SavedClips/a.mp4")
        uploader = self.uploader()
        uploader.dest_root = "/Elsewhere"
        self.assertEqual(uploader.run([(self.source, self.write_list(["SavedClips/a.mp4"]))]), 0)
        self.assertEqual(self.fake.remote("/Elsewhere/SavedClips/a.mp4"), b"a")


class CommandTest(UploaderTest):
    def args(self, **values):
        return types.SimpleNamespace(state_dir=self.state_dir, **values)

    def env(self, **values):
        patcher = mock.patch.dict(os.environ, values)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("DROPBOX_APP_KEY", "DROPBOX_REFRESH_TOKEN", "DROPBOX_APP_SECRET"):
            if name not in values:
                os.environ.pop(name, None)

    def store_credentials(self, refresh_token=FakeDropbox.REFRESH_TOKEN):
        dba.save_credentials(self.state_dir, dba.Credentials(FakeDropbox.APP_KEY, refresh_token, None, "test"))

    def fake_input(self, prompt):
        url = next(line.strip() for line in self.logs if "oauth2/authorize" in line)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertEqual(query["token_access_type"], ["offline"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.fake.auth_codes["the-code"] = (query["client_id"][0], query["code_challenge"][0])
        return "the-code"

    def test_authorize_saves_private_credentials(self):
        self.env()
        with mock.patch("builtins.input", self.fake_input):
            self.assertEqual(dba.cmd_authorize(self.args(app_key="my-app", print=False)), 0)
        path = os.path.join(self.state_dir, "credentials.json")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.state_dir).st_mode & 0o777, 0o700)
        credentials = dba.load_credentials(self.state_dir)
        self.assertEqual(credentials.app_key, "my-app")
        self.assertEqual(self.fake.refresh_tokens[credentials.refresh_token], "my-app")
        self.assertIn("Linked to the Dropbox account of Test User (test@example.com)", self.logs)

    def test_authorize_can_print_setup_variables_instead(self):
        self.env()
        with mock.patch("builtins.input", self.fake_input):
            self.assertEqual(dba.cmd_authorize(self.args(app_key="my-app", print=True)), 0)
        self.assertFalse(os.path.exists(os.path.join(self.state_dir, "credentials.json")))
        self.assertIn("export DROPBOX_APP_KEY=my-app", self.logs)
        self.assertTrue(any(line.startswith("export DROPBOX_REFRESH_TOKEN=refresh-") for line in self.logs))

    def test_authorize_rejects_a_wrong_code(self):
        self.env()
        with mock.patch("builtins.input", lambda prompt: "wrong-code"):
            self.assertEqual(dba.cmd_authorize(self.args(app_key="my-app", print=False)), dba.EXIT_AUTH)
        self.assertIsNone(dba.load_credentials(self.state_dir))

    def test_check_creates_the_folder_and_tests_writing(self):
        self.env(DROPBOX_PATH="/TeslaCam/")
        self.store_credentials()
        self.assertEqual(dba.cmd_check(self.args()), 0)
        self.assertIn("/teslacam", self.fake.folders)
        self.assertEqual(self.fake.files, {})
        self.assertEqual([r[1]["path"] for r in self.fake.requests_for("/2/files/upload")],
                         ["/TeslaCam/.teslausb-write-test"])
        self.assertEqual(dba.cmd_check(self.args()), 0)

    def test_check_without_credentials(self):
        self.env(DROPBOX_PATH="/TeslaCam")
        self.assertEqual(dba.cmd_check(self.args()), dba.EXIT_NO_CREDENTIALS)

    def test_import_credentials(self):
        self.env(DROPBOX_APP_KEY=FakeDropbox.APP_KEY, DROPBOX_REFRESH_TOKEN=FakeDropbox.REFRESH_TOKEN)
        self.assertEqual(dba.cmd_import_credentials(self.args()), 0)
        self.assertEqual(dba._credentials_from_file(self.state_dir).refresh_token, FakeDropbox.REFRESH_TOKEN)

    def test_import_keeps_working_credentials_over_rejected_ones(self):
        self.store_credentials()
        self.env(DROPBOX_APP_KEY=FakeDropbox.APP_KEY, DROPBOX_REFRESH_TOKEN="revoked-token")
        self.assertEqual(dba.cmd_import_credentials(self.args()), 0)
        self.assertEqual(dba._credentials_from_file(self.state_dir).refresh_token, FakeDropbox.REFRESH_TOKEN)
        self.fake.refresh_tokens.clear()
        self.assertEqual(dba.cmd_import_credentials(self.args()), dba.EXIT_AUTH)

    def test_setup_does_not_undo_a_later_authorization(self):
        self.env(DROPBOX_APP_KEY=FakeDropbox.APP_KEY, DROPBOX_REFRESH_TOKEN=FakeDropbox.REFRESH_TOKEN)
        self.assertEqual(dba.cmd_import_credentials(self.args()), 0)
        with mock.patch("builtins.input", self.fake_input):
            self.assertEqual(dba.cmd_authorize(self.args(app_key="other-app", print=False)), 0)
        authorized = dba._credentials_from_file(self.state_dir)
        self.assertEqual(authorized.app_key, "other-app")
        # running setup again, with the same setup variables
        self.assertEqual(dba.cmd_import_credentials(self.args()), 0)
        self.assertEqual(dba._credentials_from_file(self.state_dir), authorized)
        # changing DROPBOX_REFRESH_TOKEN does take effect
        self.fake.refresh_tokens["new-token"] = FakeDropbox.APP_KEY
        self.env(DROPBOX_APP_KEY=FakeDropbox.APP_KEY, DROPBOX_REFRESH_TOKEN="new-token")
        self.assertEqual(dba.cmd_import_credentials(self.args()), 0)
        self.assertEqual(dba._credentials_from_file(self.state_dir).refresh_token, "new-token")

    def test_status_does_not_reveal_secrets(self):
        self.env(DROPBOX_PATH="/TeslaCam", DROPBOX_WIFI_SSIDS="Home|Home 5G")
        self.store_credentials()
        self.assertEqual(dba.cmd_status(self.args()), 0)
        output = "\n".join(self.logs)
        self.assertNotIn(FakeDropbox.REFRESH_TOKEN, output)
        self.assertNotIn("Home", output)
        self.assertIn("2 specific wifi network(s)", output)

    def test_only_one_upload_runs_at_a_time(self):
        self.env(DROPBOX_PATH="/TeslaCam")
        self.store_credentials()
        lock = dba._lock(self.state_dir)
        self.addCleanup(os.close, lock)
        args = self.args(pairs=[self.source, self.write_list([])], reachability_script=None)
        self.assertEqual(dba.cmd_upload(args), dba.EXIT_FAILED)
        self.assertIn("Another Dropbox upload is already running", self.logs)


class ShellScriptTest(FakeServerTestCase):
    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.tmp, "bin")
        self.net = os.path.join(self.tmp, "net")
        os.mkdir(self.bin)
        os.mkdir(self.net)
        # make the scripts use the Python that runs the tests
        os.symlink(sys.executable, os.path.join(self.bin, "python3"))
        self.stub("iwgetid", 'var="SSID_$2"; [ -n "${!var:-}" ] && echo "${!var}"')
        self.stub("nc", 'exit "${NC_STATUS:-0}"')

    def stub(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, "w") as f:
            f.write("#!/bin/bash\n%s\n" % body)
        os.chmod(path, 0o755)

    def environment(self, **values):
        env = {"PATH": self.bin + os.pathsep + os.environ["PATH"], "DROPBOX_NET_DIR": self.net, "HOME": self.tmp}
        env.update(values)
        return env

    def reachable(self, interfaces=(), **values):
        for name in interfaces:
            open(os.path.join(self.net, name), "w").close()
        script = os.path.join(MODULE_DIR, "archive-is-reachable.sh")
        return subprocess.run(["bash", script, "api.dropboxapi.com"], env=self.environment(**values)).returncode == 0

    def test_reachable_without_wifi_restriction(self):
        self.assertTrue(self.reachable())
        self.assertFalse(self.reachable(NC_STATUS="1"))

    def test_reachable_only_on_listed_wifi(self):
        interfaces = ("wlan0", "ap0", "eth0")
        self.assertTrue(self.reachable(interfaces, DROPBOX_WIFI_SSIDS="Home", SSID_wlan0="Home"))
        self.assertTrue(self.reachable(interfaces, DROPBOX_WIFI_SSIDS="Home|Home 5G", SSID_wlan0="Home 5G"))
        self.assertFalse(self.reachable(interfaces, DROPBOX_WIFI_SSIDS="Home", SSID_wlan0="Phone"))
        self.assertFalse(self.reachable(interfaces, DROPBOX_WIFI_SSIDS="Home"))
        # teslausb's own access point doesn't count
        self.assertFalse(self.reachable(interfaces, DROPBOX_WIFI_SSIDS="Home", SSID_ap0="Home"))
        self.assertFalse(self.reachable(interfaces, DROPBOX_WIFI_SSIDS="Home", SSID_wlan0="Home", NC_STATUS="1"))

    def archive_clips(self, data, **values):
        snapshot = os.path.join(self.tmp, "snapshot")
        source = os.path.join(self.tmp, "merged")
        name = "SentryClips/2026-10-17_10-00-00/2026-10-17_09-59-00-front.mp4"
        os.makedirs(os.path.join(snapshot, os.path.dirname(name)), exist_ok=True)
        os.makedirs(os.path.join(source, os.path.dirname(name)), exist_ok=True)
        if not os.path.exists(os.path.join(snapshot, name)):
            with open(os.path.join(snapshot, name), "wb") as f:
                f.write(data)
        if not os.path.lexists(os.path.join(source, name)):
            os.symlink(os.path.join(snapshot, name), os.path.join(source, name))
        file_list = os.path.join(self.tmp, "list.txt")
        with open(file_list, "w") as f:
            f.write(name + "\n")
        env = self.environment(
            DROPBOX_API_URL=self.server.url, DROPBOX_CONTENT_URL=self.server.url,
            DROPBOX_STATE_DIR=os.path.join(self.tmp, "state"), DROPBOX_PATH="TeslaCam",
            DROPBOX_APP_KEY=FakeDropbox.APP_KEY, DROPBOX_REFRESH_TOKEN=FakeDropbox.REFRESH_TOKEN,
            DROPBOX_CHUNK_SIZE_MB="4", **values)
        # like archiveloop's archive_clips
        subprocess.run(["bash", os.path.join(MODULE_DIR, "connect-archive.sh")], env=env, check=True)
        result = subprocess.run(["bash", os.path.join(MODULE_DIR, "archive-clips.sh"), source, file_list],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        return result, os.path.lexists(os.path.join(source, name)), self.fake.remote("/TeslaCam/" + name)

    def test_archive_clips(self):
        flag = "/tmp/archive_is_unreachable"
        had_flag = os.path.exists(flag)
        self.addCleanup(lambda: had_flag or not os.path.exists(flag) or os.unlink(flag))
        data = pattern(9 * MIB + 3)
        # the connection is lost, and the car isn't on the home network anymore
        self.fake.add_fault("/2/files/upload_session/append_v2", "go_offline")
        result, pending, remote = self.archive_clips(
            data, DROPBOX_WIFI_SSIDS="Home", DROPBOX_OFFLINE_TIMEOUT="1")
        self.assertEqual(result.returncode, 75, result.stdout)
        self.assertTrue(pending)
        self.assertIsNone(remote)
        self.assertTrue(os.path.exists(flag), "archiveloop should be asked to try again")
        self.assertIn("archiving will resume when it is reachable again", result.stdout)
        # back home
        self.fake.online = True
        received = len(self.fake.requests)
        result, pending, remote = self.archive_clips(data)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(pending)
        self.assertEqual(remote, data)
        self.assertEqual(self.fake.bytes_received(received), len(data) - 4 * MIB)
        self.assertFalse(os.path.exists(flag))
        self.assertRegex(result.stdout, r"\d\d:\d\d:\d\d.*: Resuming the upload of SentryClips/")


if __name__ == "__main__":
    unittest.main()
