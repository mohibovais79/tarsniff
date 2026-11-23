"""Download the NPMStudy benign packages (exact name/version from zip_benign_list.txt)
straight from the npm registry into /bench/benign/. Never runs npm install.

Runs in a container with network; resumable (skips files already present).
Writes /bench/benign_fetch_log.tsv : list_entry, status (ok / http code / error)
"""

import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

OUT = Path("/bench/benign")


def url_for(entry):
    # entry: "@scope@pkg/1.2.3/@scope@pkg-1.2.3.tgz" or "pkg/1.2.3/pkg-1.2.3.tgz"
    enc_name, version, _ = entry.split("/", 2)
    if enc_name.startswith("@"):
        scope, pkg = enc_name[1:].split("@", 1)
        name, base = f"@{scope}/{pkg}", pkg
    else:
        name, base = enc_name, enc_name
    return f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}/-/{base}-{version}.tgz"


def fetch(entry):
    dest = OUT / entry.replace("/", "__")
    if dest.exists() and dest.stat().st_size > 0:
        return entry, "ok"
    for attempt in range(3):
        try:
            data = urllib.request.urlopen(url_for(entry), timeout=120).read()
            tmp = dest.with_suffix(".part")
            tmp.write_bytes(data)
            tmp.rename(dest)
            return entry, "ok"
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return entry, str(e.code)
            time.sleep(2 * (attempt + 1))
        except Exception as e:  # noqa: BLE001
            err = type(e).__name__
            time.sleep(2 * (attempt + 1))
    return entry, locals().get("err", "failed")


def main():
    OUT.mkdir(exist_ok=True)
    z = zipfile.ZipFile("/bench/NPMStudy.zip")
    entries = z.read("NPMStudy/Dataset/zip_benign/zip_benign_list.txt").decode().split()
    done = 0
    with ThreadPoolExecutor(16) as ex, open("/bench/benign_fetch_log.tsv", "w") as log:
        for entry, status in ex.map(fetch, entries):
            log.write(f"{entry}\t{status}\n")
            done += 1
            if done % 250 == 0:
                print(f"{done}/{len(entries)}", flush=True)
    print("DONE", done, flush=True)


if __name__ == "__main__":
    main()
