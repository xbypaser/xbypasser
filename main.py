#!/usr/bin/env python3
# [ context: xbypasser v2.1 — CFBundleIdentifier swap + safe ad-hoc re-sign
#   OS: macOS 13 Ventura → 15.2 "Sequoia" (Darwin 24.2.0)
#   arch: arm64e / x86_64 universal Mach-O + nested framework/helper bundles
#   toolchain: CPython 3.9+ (stdlib-only), Xcode CLT (codesign, plutil),
#              lsregister, ctypes -> /usr/lib/libc.dylib for xattr syscalls ]
"""
xbypasser — change an .app's CFBundleIdentifier and ad-hoc resign it.

why v1 broke bundles (and what changed):
  1. entitlements were re-embedded blind. keys like application-identifier
     encode TEAMID + old bundle id, so the new ad-hoc signature carried a
     dead identity -> AMFI SIGKILL at exec() on Apple Silicon ("Killed: 9").
     now: identity-bound/restricted keys are stripped before re-embedding.
  2. `codesign -d --entitlements - --xml` doesn't exist on <= macOS 12 CLT
     and DER blobs can masquerade as output. now: output is slice-validated
     as a real <plist> before use, legacy paths probed as fallback.
  3. com.apple.quarantine / com.apple.provenance xattrs survived the whole
     pipeline -> Sequoia reports the bundle as "damaged". now: swept via
     raw libc syscalls (os.listxattr doesn't exist on Darwin CPython).
  4. `rm -rf _CodeSignature` leaves the embedded CMS blob + LC_CODE_SIGNATURE
     load command inside every Mach-O. now: `codesign --remove-signature
     --deep` rewrites __LINKEDIT properly, dir sweep is just residue patrol.
  5. LaunchServices kept the old bundle id cached. now: lsregister -f.

usage:
    xbypasser <app> -c <other.app>              copy bundle id from another app
    xbypasser <app> -b com.example.newid        explicit CFBundleIdentifier
    xbypasser <app> -b ... --keep-entitlements  keep non-restricted entitlements
    xbypasser <app> -b ... --hardened           re-apply hardened runtime
    xbypasser <app> -b ... --no-deep            outer bundle only (no nested)
"""

import argparse
import ctypes
import ctypes.util
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile

LSREGISTER = ("/System/Library/Frameworks/CoreServices.framework/"
              "Frameworks/LaunchServices.framework/Support/lsregister")

# identity-bound / restricted entitlement keys. re-embedding any of these on
# an ad-hoc signature under a NEW bundle id is the classic arm64 AMFI kill.
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
# harmless + useful: keeps debuggers attached to the re-signed build
ENT_KEEP = {"get-task-allow"}

XATTRS_TO_KILL = ("com.apple.quarantine", "com.apple.provenance")


# ── helpers ──────────────────────────────────────────────────────────────────

def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def run_quiet(cmd):
    """subprocess wrapper that never raises on nonzero rc"""
    return subprocess.run(cmd, capture_output=True)


def find_info_plist(app_path):
    """Info.plist at Contents/ (standard bundle) or bundle root (flat layout)"""
    for cand in (os.path.join(app_path, "Contents", "Info.plist"),
                 os.path.join(app_path, "Info.plist")):
        if os.path.isfile(cand):
            return cand
    return None


# ── bundle id read / write ───────────────────────────────────────────────────

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
    """plutil first (native, handles binary plists), visible errors + plistlib
    fallback. v1 swallowed plutil stderr here — an EPERM from a missing App
    Management TCC grant (Sequoia, /Applications targets) looked like a no-op."""
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


# ── xattr sweep (Darwin libc via ctypes) ────────────────────────────────────

_libc = None

def _load_libc():
    """bind libc listxattr/removexattr once. Darwin prototypes:
      ssize_t listxattr(const char *path, char *namebuf, size_t size, int options)
      int     removexattr(const char *path, const char *name, int options)
    the trailing `options` arg is why CPython never exposed these on os."""
    global _libc
    if _libc is not None:
        return _libc
    lib = ctypes.CDLL(ctypes.util.find_library("c") or "/usr/lib/libc.dylib",
                      use_errno=True)
    lib.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_size_t, ctypes.c_int]
    lib.listxattr.restype = ctypes.c_ssize_t
    lib.removexattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.removexattr.restype = ctypes.c_int
    _libc = lib
    return _libc


def _listxattr_raw(path):
    """raw libc probe. -> list of attr names, [] if clean, None on per-file error.
    size=0 probe returns the required buffer length, then refill with the
    NUL-separated name table — one syscall each until something has attrs."""
    lib = _load_libc()
    pb = os.fsencode(path)
    need = lib.listxattr(pb, None, 0, 0)
    if need <= 0:
        return None if need < 0 else []
    buf = ctypes.create_string_buffer(need)
    got = lib.listxattr(pb, buf, need, 0)
    if got < 0:
        return None
    return [n.decode("utf-8", "replace")
            for n in buf.raw[:got].split(b"\x00") if n]


def strip_problem_xattrs(app_path):
    """quarantine + provenance sweep via raw libc syscalls, zero process spawns
    (a Firefox-fork bundle is ~4k inodes — spawning `xattr` per file would be
    minutes of pure overhead). returns count killed, or -1 if the libc bind
    failed and we fell back to the blunt `xattr -cr` nuke."""
    try:
        _load_libc()
    except OSError:
        run_quiet(["xattr", "-cr", app_path])
        return -1

    killed = 0
    for root, dirs, files in os.walk(app_path, followlinks=False):
        for entry in dirs + files:
            t = os.path.join(root, entry)
            if os.path.islink(t):
                continue
            names = _listxattr_raw(t)
            if not names:
                continue
            for attr in XATTRS_TO_KILL:
                if attr in names:
                    lib = _load_libc()
                    if lib.removexattr(os.fsencode(t),
                                       attr.encode("utf-8"), 0) == 0:
                        killed += 1
    return killed


# ── entitlements ─────────────────────────────────────────────────────────────

def _parse_ent_blob(blob):
    """slice the first well-formed <plist>...</plist> out of mixed output and
    validate it — rejects stderr preamble lines and DER garbage"""
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
    13+ CLT: `--xml` gives a clean XML plist on stdout
    <=12 CLT: `--xml` is unknown (rc!=0); XML ents ride on stderr with a
              preamble; DER-signed ents are unrecoverable as XML -> None"""
    r = run_quiet(["codesign", "-d", "--entitlements", "-", "--xml", app_path])
    if r.returncode == 0:
        for blob in (r.stdout, r.stderr):
            parsed = _parse_ent_blob(blob)
            if parsed is not None:
                return parsed
    r = run_quiet(["codesign", "-d", "--entitlements", "-", app_path])
    for blob in (r.stderr, r.stdout):
        parsed = _parse_ent_blob(blob)
        if parsed is not None:
            return parsed
    return None


def filter_entitlements(ent_dict):
    """drop identity-bound + restricted keys, keep the rest.
    returns (kept_dict, dropped_key_list)"""
    kept, dropped = {}, []
    for key, val in ent_dict.items():
        restricted = (key in ENT_DROP_EXACT) or key.startswith(ENT_DROP_PREFIX)
        if restricted and key not in ENT_KEEP:
            dropped.append(key)
        else:
            kept[key] = val
    return kept, dropped


# ── signature strip / resign ─────────────────────────────────────────────────

def remove_signatures(app_path):
    """codesign --remove-signature rewrites __LINKEDIT (drops the embedded CMS
    blob + LC_CODE_SIGNATURE properly) — rm -rf only killed CodeResources while
    stale blobs survived in Mach-Os --deep never reaches"""
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
        # ad-hoc + hardened runtime is valid locally; needed by apps whose
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
    # --deep deprecation warning lands on stderr even on success — ignored


def refresh_launchservices(app_path):
    """re-register the bundle so `open -b <newid>` and XPC lookups resolve"""
    run_quiet([LSREGISTER, "-f", app_path])


# ── main ─────────────────────────────────────────────────────────────────────

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
                   help="preserve non-restricted entitlements (default strips "
                        "identity-bound keys that trigger AMFI kills)")
    p.add_argument("--hardened", action="store_true",
                   help="re-apply hardened runtime (-o runtime)")
    p.add_argument("--no-deep", action="store_true",
                   help="sign outer bundle only, skip nested code")
    args = p.parse_args()

    if not os.path.isdir(args.app):
        die(f"{args.app} is not a directory")

    # resolve the new bundle id
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

    # entitlements MUST be read before remove-signature — they live in the
    # CMS blob we're about to destroy
    ent_xml = None
    raw_ents = dump_entitlements_raw(args.app)
    if raw_ents is None:
        print("[*] no parsable entitlements (or legacy DER signature) — none re-applied")
    elif args.keep_entitlements:
        kept, dropped = filter_entitlements(raw_ents)
        if dropped:
            print("[*] dropping identity-bound keys even with --keep-entitlements:")
            for k in dropped:
                print(f"      - {k}")
        if kept:
            ent_xml = plistlib.dumps(kept, fmt=plistlib.FMT_XML)
            print(f"[*] re-applying {len(kept)} filtered entitlement(s)")
        else:
            print("[*] nothing survived filtering — signing without entitlements")
    else:
        print(f"[*] stripping all {len(raw_ents)} entitlement(s) "
              "(default: safest for ad-hoc)")

    print("[*] removing existing signatures (--remove-signature --deep)...")
    n = remove_signatures(args.app)
    print(f"[*] swept {n} residual _CodeSignature dir(s)")

    xk = strip_problem_xattrs(args.app)
    if xk < 0:
        print("[*] xattr: libc bind failed, used `xattr -cr` fallback "
              "(all attrs cleared)")
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
    print(f"[+] verify with: codesign -dv --entitlements - {args.app} 2>&1 | head -20")
    return 0


if __name__ == "__main__":
    sys.exit(main())
