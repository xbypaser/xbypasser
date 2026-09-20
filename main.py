#!/usr/bin/env python3
# [ context: xbypasser v2 — CFBundleIdentifier swap + safe ad-hoc re-sign
#   OS: macOS 15.2 "Sequoia" (Darwin 24.2.0), backward-compatible to 12.x
#   arch: arm64e / x86_64 universal Mach-O + framework bundles
#   toolchain: CPython 3.12, Xcode CLT 16.2 (codesign-1069), plutil, lsregister ]
"""
xbypasser v2 — change an .app's CFBundleIdentifier and ad-hoc resign it.

v1 failure modes fixed here:
  1. entitlements re-embedded blind -> application-identifier pinned the dead
     TEAMID/bundle-id -> AMFI SIGKILL at exec() on Apple Silicon
  2. `codesign -d --entitlements - --xml` doesn't exist on <=12.x, silently
     returned None; DER-vs-XML ambiguity could embed garbage
  3. quarantine/provenance xattrs survived -> Sequoia "damaged" dialog
  4. stale embedded CMS blobs left in Mach-Os --deep never reached
  5. LaunchServices never re-registered the new bundle id

Usage:
    xbypasser <app> -c <other.app>              # copy bundle id from another app
    xbypasser <app> -b com.example.newid        # explicit bundle id
    xbypasser <app> -b ... --keep-entitlements  # risky: keep non-restricted ents
    xbypasser <app> -b ... --hardened           # re-apply hardened runtime
    xbypasser <app> -b ... --no-deep            # outer bundle only
"""
import argparse
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile

LSREGISTER = ("/System/Library/Frameworks/CoreServices.framework/"
              "Frameworks/LaunchServices.framework/Support/lsregister")

# identity-bound / restricted entitlement keys. re-embedding any of these on an
# ad-hoc signature under a NEW bundle id is the classic arm64 AMFI kill.
ENT_DROP_EXACT = {
    "application-identifier",
    "com.apple.developer.team-identifier",
    "keychain-access-groups",
    "com.apple.security.application-groups",
    "com.apple.security.temporary-exception.mach-lookup.global-name",
    "com.apple.security.temporary-exception.shared-preference.read-only",
    "com.apple.security.temporary-exception.shared-preference.read-write",
    "com.apple.security.temporary-exception.files.home-relative-path.read-write",
    "com.apple.security.temporary-exception.files.absolute-path.read-only",
    "com.apple.security.temporary-exception.files.absolute-path.read-write",
    "beta-reports-active",
}
ENT_DROP_PREFIX = (
    "com.apple.private.",
    "com.apple.developer.",
)
# harmless + useful: keeps LLDB/debuggers attached to the re-signed build
ENT_KEEP = {"get-task-allow"}

XATTRS_TO_KILL = ("com.apple.quarantine", "com.apple.provenance")


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def run_quiet(cmd):
    """subprocess wrapper that never raises on nonzero rc, returns CompletedProcess"""
    return subprocess.run(cmd, capture_output=True)


def find_info_plist(app_path):
    """Info.plist at Contents/ (standard bundle) or bundle root (flat/iOS-style)"""
    candidates = (
        os.path.join(app_path, "Contents", "Info.plist"),
        os.path.join(app_path, "Info.plist"),
    )
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def read_bundle_id(app_path):
    plist_path = find_info_plist(app_path)
    if not plist_path:
        die(f"Info.plist not found in {app_path} (checked Contents/ and root)")
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
    except Exception as e:
        die(f"failed to parse {plist_path}: {e}")
    bid = data.get("CFBundleIdentifier")
    if not bid:
        die(f"CFBundleIdentifier missing from {plist_path}")
    return bid


def write_bundle_id(app_path, new_id):
    """plutil first (native, handles binary plists), visible errors this time"""
    plist_path = find_info_plist(app_path)
    if not plist_path:
        die(f"Info.plist not found in {app_path}, cannot set CFBundleIdentifier")

    run_quiet(["plutil", "-convert", "xml1", plist_path])

    r = subprocess.run(
        ["plutil", "-replace", "CFBundleIdentifier", "-string", new_id, plist_path],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        return
    # NOTE: v1 swallowed plutil stderr here — EPERM from missing App Management
    # TCC grant (Sequoia, /Applications targets) looked like "nothing happened"
    print(f"[!] plutil -replace failed (rc={r.returncode}): {r.stderr.strip()}",
          file=sys.stderr)
    print("[!] falling back to plistlib...", file=sys.stderr)
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
        data["CFBundleIdentifier"] = new_id
        with open(plist_path, "wb") as f:
            plistlib.dump(data, f, fmt=plistlib.FMT_XML)
    except Exception as e:
        die(f"failed to set CFBundleIdentifier: {e}")


def strip_problem_xattrs(app_path):
    """quarantine + provenance xattrs -> Sequoia reports ad-hoc bundles as
    'damaged' if either survives. native removexattr walk, xattr -cr fallback."""
    killed = 0
    native_ok = True
    targets = [app_path]
    for root, dirs, files in os.walk(app_path, followlinks=False):
        targets.extend(os.path.join(root, d) for d in dirs)
        targets.extend(os.path.join(root, f) for f in files)

    for t in targets:
        try:
            present = os.listxattr(t)
        except OSError:
            native_ok = False
            continue
        for attr in XATTRS_TO_KILL:
            if attr in present:
                try:
                    os.removexattr(t, attr)
                    killed += 1
                except OSError:
                    pass

    if not native_ok:
        # exotic attr namespace the native call choked on — nuke with the CLI
        run_quiet(["xattr", "-cr", app_path])
        killed = -1  # sentinel: fallback used
    return killed


def _try_parse_entitlements(blob):
    """slice the first well-formed <plist>...</plist> out of mixed output and
    validate it — handles stderr preamble lines and DER garbage rejection"""
    if not blob or b"<plist" not in blob:
        return None
    start = blob.index(b"<plist")
    end = blob.rindex(b"</plist>") + len(b"</plist>")
    try:
        return plistlib.loads(blob[start:end])
    except plistlib.InvalidFileException:
        return None


def dump_entitlements_raw(app_path):
    """version-proof entitlements extraction.
    13+ CLT: `--xml` gives clean XML plist on stdout
    <=12 CLT: `--xml` is unknown (rc!=0), XML ents ride on stderr w/ preamble,
              DER-signed ents are unrecoverable as XML -> None is honest"""
    r = run_quiet(["codesign", "-d", "--entitlements", "-", "--xml", app_path])
    if r.returncode == 0:
        for blob in (r.stdout, r.stderr):
            parsed = _try_parse_entitlements(blob)
            if parsed is not None:
                return parsed
    r = run_quiet(["codesign", "-d", "--entitlements", "-", app_path])
    for blob in (r.stderr, r.stdout):
        parsed = _try_parse_entitlements(blob)
        if parsed is not None:
            return parsed
    return None


def filter_entitlements(ent_dict):
    """drop identity-bound + restricted keys, keep the rest + get-task-allow.
    returns (kept_dict, dropped_key_list)"""
    kept, dropped = {}, []
    for key, val in ent_dict.items():
        restricted = (key in ENT_DROP_EXACT) or key.startswith(ENT_DROP_PREFIX)
        if restricted and key not in ENT_KEEP:
            dropped.append(key)
        else:
            kept[key] = val
    return kept, dropped


def remove_signatures(app_path):
    """codesign --remove-signature rewrites __LINKEDIT (drops the embedded CMS
    blob + LC_CODE_SIGNATURE properly) — rm -rf only killed CodeResources while
    stale blobs survived in Mach-Os --deep doesn't reach"""
    run_quiet(["codesign", "--remove-signature", "--deep", app_path])
    removed = 0
    for root, dirs, _ in os.walk(app_path, followlinks=False):
        for d in list(dirs):
            if d == "_CodeSignature":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                removed += 1
    return removed


def resign_bundle(app_path, ent_xml, deep=True, hardened=False):
    """ad-hoc re-sign. ent_xml is pre-filtered XML plist bytes or None"""
    cmd = ["codesign", "-f", "-s", "-", "--timestamp=none"]
    if deep:
        cmd.append("--deep")
    if hardened:
        # ad-hoc + hardened runtime is valid locally; needed by some apps whose
        # helpers assume CS_RUNTIME (library validation stays default-on)
        cmd += ["-o", "runtime"]

    ent_path = None
    if ent_xml:
        fd, ent_path = tempfile.mkstemp(suffix=".ent.plist")
        try:
            os.write(fd, ent_xml)
        finally:
            os.close(fd)
        cmd += ["--entitlements", ent_path]
    cmd.append(app_path)

    r = subprocess.run(cmd, capture_output=True, text=True)
    if ent_path:
        try:
            os.unlink(ent_path)
        except OSError:
            pass
    if r.returncode != 0:
        die(f"codesign failed (rc={r.returncode}):\n{r.stderr.strip()}")
    # --deep deprecation warning lands on stderr even on success — ignore it


def refresh_launchservices(app_path):
    """re-register the bundle so `open -b <newid>` and XPC lookups resolve"""
    run_quiet([LSREGISTER, "-f", app_path])


def main():
    p = argparse.ArgumentParser(
        prog="xbypasser",
        description="Swap an app's CFBundleIdentifier and ad-hoc resign it "
                    "without poisoning the new signature.",
    )
    p.add_argument("app", help="path to the target .app bundle")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-c", metavar="APP", help="copy CFBundleIdentifier from APP")
    g.add_argument("-b", metavar="BUNDLEID", help="explicit CFBundleIdentifier")
    p.add_argument("--keep-entitlements", action="store_true",
                   help="preserve non-restricted entitlements (default: strip "
                        "identity-bound keys that trigger AMFI kills)")
    p.add_argument("--hardened", action="store_true",
                   help="re-apply hardened runtime (-o runtime)")
    p.add_argument("--no-deep", action="store_true",
                   help="sign outer bundle only, skip nested code")
    args = p.parse_args()

    if not os.path.isdir(args.app):
        die(f"{args.app} is not a directory")

    if args.c:
        if not os.path.isdir(args.c):
            die(f"source app {args.c} is not a directory")
        new_id = read_bundle_id(args.c)
        print(f"[*] copied CFBundleIdentifier from {args.c}: {new_id}")
    else:
        new_id = args.b
        print(f"[*] using CFBundleIdentifier: {new_id}")

    old_id = read_bundle_id(args.app)
    print(f"[*] original CFBundleIdentifier: {old_id}")

    # entitlements MUST be read before remove-signature — they live in the CMS
    # blob we're about to destroy
    ent_xml = None
    raw_ents = dump_entitlements_raw(args.app)
    if raw_ents is None:
        print("[*] no parsable entitlements (or legacy DER signature) — none re-applied")
    elif args.keep_entitlements:
        kept, dropped = filter_entitlements(raw_ents)
        if dropped:
            print(f"[*] dropping identity-bound keys even with --keep-entitlements:")
            for k in dropped:
                print(f"      - {k}")
        if kept:
            ent_xml = plistlib.dumps(kept, fmt=plistlib.FMT_XML)
            print(f"[*] re-applying {len(kept)} filtered entitlement(s)")
        else:
            print("[*] nothing survived filtering — signing without entitlements")
    else:
        kept_count = len(raw_ents)
        ent_xml = None
        print(f"[*] stripping all {kept_count} entitlement(s) (default: safest for ad-hoc)")

    print("[*] removing existing signatures (--remove-signature --deep)...")
    n = remove_signatures(args.app)
    print(f"[*] swept {n} residual _CodeSignature dir(s)")

    if not args.no_deep or True:  # xattr sweep always runs, deep flag only affects signing
        xk = strip_problem_xattrs(args.app)
        if xk < 0:
            print("[*] xattr: native pass incomplete, used xattr -cr fallback")
        else:
            print(f"[*] stripped {xk} quarantine/provenance xattr(s)")

    print(f"[*] setting CFBundleIdentifier -> {new_id}")
    write_bundle_id(args.app, new_id)

    print(f"[*] ad-hoc resigning (deep={not args.no_deep}, "
          f"hardened={args.hardened})...")
    resign_bundle(args.app, ent_xml=ent_xml,
                  deep=not args.no_deep, hardened=args.hardened)

    print("[*] refreshing LaunchServices registration...")
    refresh_launchservices(args.app)

    print(f"[+] done. {args.app} reports bundle id: {new_id}")
    print("[+] verify with: codesign -dv --entitlements - "
          f"{args.app} 2>&1 | head -20")
    return 0


if __name__ == "__main__":
    sys.exit(main())
