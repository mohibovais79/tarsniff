"""Pre-registered live set: every npm MAL- report OSV published since a cutoff, and whether
the malicious tarball can still be downloaded from the npm registry (metadata only; no tarballs).

Usage: python scripts/bench/live_osv.py <modified_id.csv> <since YYYY-MM-DD> <out.jsonl>
"""
import concurrent.futures as cf, json, sys, urllib.parse, urllib.request, urllib.error


def get(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "tarsniff-research"}), timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"_http": e.code}
    except Exception as e:  # noqa: BLE001
        return {"_err": str(e)}


def one(mid):
    v = get(f"https://api.osv.dev/v1/vulns/{mid}")
    out = []
    for a in v.get("affected", []):
        if a.get("package", {}).get("ecosystem") != "npm":
            continue
        name = a["package"]["name"]
        vers = a.get("versions") or []
        meta = get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}")
        reg = set(meta.get("versions", {}))
        avail = sorted((set(vers) & reg) if vers else reg)  # no version list = every version is malicious
        out.append({"id": mid, "published": v.get("published"), "name": name, "versions": vers,
                    "registry": meta.get("_http", "ok" if "versions" in meta else "err"),
                    "available": [x for x in avail if not x.endswith("-security")]})
    return out


def main(csv, since, out):
    ids = sorted({l.strip().split(",")[1] for l in open(csv) if ",MAL-" in l and l[:10] >= since})
    rows = []
    with cf.ThreadPoolExecutor(16) as ex:
        for res in ex.map(one, ids):
            rows += res
    rows = [r for r in rows if (r["published"] or "")[:10] >= since]
    with open(out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"reports {len(ids)} -> npm entries published since {since}: {len(rows)}; "
          f"still downloadable: {sum(bool(r['available']) for r in rows)}; "
          f"no version list (whole package): {sum(not r['versions'] for r in rows)}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
