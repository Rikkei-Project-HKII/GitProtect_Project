"""Read one connected GitHub repository using its stored PAT."""
import base64
import re
from urllib.parse import quote

import httpx
from fastapi import HTTPException

from app.core.security import crypto_service


class RepositoryAPI:
    def __init__(self, client, name):
        self.client = client
        self.root = "/repos/" + "/".join(quote(part, safe="") for part in name.split("/"))

    @classmethod
    def connect(cls, repo):
        return cls(httpx.Client(base_url="https://api.github.com", timeout=20,
                                headers={"Authorization": "Bearer " + crypto_service.decrypt(repo.access_token_encrypted),
                                         "Accept": "application/vnd.github+json"}), repo.repo_name)

    def response(self, path, params=None):
        try:
            response = self.client.get(path, params=params)
        except httpx.RequestError:
            raise HTTPException(502, "GitHub unavailable") from None
        if response.status_code != 200:
            raise HTTPException(502, f"GitHub returned HTTP {response.status_code}")
        return response

    def pages(self, resource):
        path = self.root + "/" + resource
        params = {"per_page": 100}
        seen = set()
        while path:
            response = self.response(path, params)
            yield from response.json()
            link = response.links.get("next", {}).get("url")
            if link:
                target = httpx.URL(link)
                canonical_path = re.fullmatch(r"/repositories/\d+/" + re.escape(resource), target.path)
                if (target.scheme != "https" or target.host != "api.github.com" or target.port not in (None, 443)
                        or target.userinfo or link in seen
                        or (target.path != self.root + "/" + resource and not canonical_path)):
                    raise HTTPException(502, "Invalid GitHub pagination link")
                seen.add(link)
            path, params = link, None

    def snapshot(self, branch, heartbeat=None):
        commit = self.response(self.root + "/commits/" + quote(branch, safe="")).json()
        sha = commit["commit"]["tree"]["sha"]
        pending = [("", sha)]
        files = []
        while pending:
            if heartbeat:
                heartbeat()
            prefix, tree_sha = pending.pop()
            tree = self.response(self.root + "/git/trees/" + tree_sha).json()
            if tree.get("truncated"):
                raise ValueError("Incomplete Git tree")
            for entry in tree["tree"]:
                path = prefix + entry["path"]
                if entry["type"] == "tree":
                    pending.append((path + "/", entry["sha"]))
                elif entry["type"] == "blob" and entry["mode"] != "120000":
                    files.append((path, entry["sha"]))
        return commit["sha"], files

    def read_text(self, sha):
        blob = self.response(self.root + "/git/blobs/" + sha).json()
        if blob.get("encoding") != "base64":
            raise ValueError("Unsupported Git blob encoding")
        raw = base64.b64decode(blob["content"])
        if b"\0" in raw:
            return None
        try:
            return raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            return None
