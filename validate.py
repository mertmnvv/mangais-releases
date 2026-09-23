"""Run in the public binary-only GitHub release repository."""
import hashlib
import hmac
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request

API = f"https://api.github.com/repos/{os.environ['REPO']}"
CALLBACK_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
}
HEADERS = {
    "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "mangais-apk-validator",
}

def checked_open(request, timeout, label):
    try:
        return urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"{label} HTTP {error.code}: {detail}") from error

def api(path):
    with checked_open(urllib.request.Request(API + path, headers=HEADERS), 30, f"GitHub API {path}") as response:
        return json.load(response)

def report(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    signature = hmac.new(os.environ["CALLBACK_SECRET"].encode(), raw, hashlib.sha256).hexdigest()
    request = urllib.request.Request(os.environ["CALLBACK_URL"], raw, {
        "Content-Type": "application/json", "X-Mangais-Signature": signature, **CALLBACK_HEADERS}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            print(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"Validation callback HTTP {error.code}: {detail}") from error

def run():
    release = api(f"/releases/{os.environ['RELEASE_ID']}")
    asset = api(f"/releases/assets/{os.environ['ASSET_ID']}")
    for _ in range(12):
        if asset.get("digest"):
            break
        time.sleep(5)
        asset = api(f"/releases/assets/{os.environ['ASSET_ID']}")
    if asset["id"] not in [item["id"] for item in release["assets"]]:
        raise ValueError("Asset is not in the expected draft release")
    with checked_open(urllib.request.Request(asset["url"], headers={**HEADERS, "Accept": "application/octet-stream"}), 120, "GitHub APK download") as response, open("app.apk", "wb") as output:
        while block := response.read(1024 * 1024):
            output.write(block)
    data = open("app.apk", "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != asset["size"] or asset.get("digest") != "sha256:" + digest:
        raise ValueError("APK size or GitHub SHA-256 digest mismatch")
    build_tools = os.path.join(os.environ["ANDROID_HOME"], "build-tools", "35.0.0")
    signer = subprocess.check_output([os.path.join(build_tools, "apksigner"), "verify", "--print-certs", "app.apk"], text=True)
    fingerprints = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]+)", signer)
    expected = os.environ["CERT_SHA256"].replace(":", "").lower()
    if len(fingerprints) != 1 or fingerprints[0].lower() != expected:
        raise ValueError("APK signing certificate mismatch")
    badging = subprocess.check_output([os.path.join(build_tools, "aapt"), "dump", "badging", "app.apk"], text=True)
    package = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", badging, re.M)
    minimum = re.search(r"^sdkVersion:'(\d+)'", badging, re.M)
    if not package or not minimum or package.group(1) != "com.mangais.app":
        raise ValueError("APK package or minSdk missing")
    # The release notes are stored by the Worker; fetch declared values from a signed, read-only endpoint.
    info_url = os.environ["CALLBACK_URL"].replace("/validation", "/validation-info") + "?id=" + os.environ["PENDING_ID"]
    request = urllib.request.Request(info_url, headers={"X-Mangais-Secret": os.environ["CALLBACK_SECRET"], **CALLBACK_HEADERS})
    with checked_open(request, 30, "Worker validation-info") as response:
        declared = json.load(response)
    if int(package.group(2)) != declared["versionCode"] or package.group(3) != declared["versionName"]:
        raise ValueError("Embedded APK version differs from the form")
    if declared.get("minAndroid") and int(minimum.group(1)) != int(declared["minAndroid"]):
        raise ValueError("Embedded Android minimum differs from the form")
    return {"success": True, "sha256": digest, "size": len(data), "minAndroid": minimum.group(1)}

if __name__ == "__main__":
    result = {"pendingId": os.environ["PENDING_ID"]}
    try:
        result.update(run())
    except Exception as error:
        result.update({"success": False, "reason": str(error)[:400]})
    print(json.dumps(result, ensure_ascii=False))
    report(result)
    if not result["success"]:
        raise SystemExit(result["reason"])
