"""Run in the public binary-only GitHub release repository."""
import hashlib
import hmac
import json
import os
import re
import subprocess
import urllib.error
import urllib.request

CALLBACK_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
}


def checked_open(request, timeout, label):
    try:
        return urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"{label} HTTP {error.code}: {detail}") from error


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
    base_url = os.environ["CALLBACK_URL"].removesuffix("/validation")
    headers = {"X-Mangais-Secret": os.environ["CALLBACK_SECRET"], **CALLBACK_HEADERS}
    pending_id = os.environ["PENDING_ID"]
    info_request = urllib.request.Request(f"{base_url}/validation-info?id={pending_id}", headers=headers)
    with checked_open(info_request, 30, "Worker validation-info") as response:
        declared = json.load(response)
    apk_request = urllib.request.Request(f"{base_url}/validation-apk?id={pending_id}", headers=headers)
    with checked_open(apk_request, 180, "Worker validation APK") as response, open("app.apk", "wb") as output:
        while block := response.read(1024 * 1024):
            output.write(block)
    with open("app.apk", "rb") as apk:
        data = apk.read()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) == 0 or len(data) > 95_000_000:
        raise ValueError("APK size is invalid")
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