#!/usr/bin/env python3
"""
xbypasser — change an .app's CFBundleIdentifier and ad-hoc resign it.

Usage:
    xbypasser <app> -c <app>          # copy CFBundleIdentifier from another .app
    xbypasser <app> -b <bundleid>    # use a custom CFBundleIdentifier string
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import plistlib


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def get_info_plist_path(app_path):
    """Find Info.plist whether it's in Contents/ or the root of the .app."""
    # Standard macOS bundle structure
    standard_path = os.path.join(app_path, "Contents", "Info.plist")
    if os.path.isfile(standard_path):
        return standard_path
    
    # Flat bundle structure (some basic apps)
    flat_path = os.path.join(app_path, "Info.plist")
    if os.path.isfile(flat_path):
        return flat_path
        
    return None


def get_bundle_id(app_path):
    """Read CFBundleIdentifier from the app's Info.plist."""
    plist_path = get_info_plist_path(app_path)
    if not plist_path:
        die(f"Info.plist not found in {app_path} (checked / and /Contents/)")
    
    try:
        with open(plist_path, "rb") as f:
            data = plistlib.load(f)
    except Exception as e:
        die(f"failed to read {plist_path}: {e}")
        
    bid = data.get("CFBundleIdentifier")
    if not bid:
        die(f"CFBundleIdentifier not found in {plist_path}")
    return bid


def set_bundle_id(app_path, new_id):
    """Replace CFBundleIdentifier in the app's Info.plist."""
    plist_path = get_info_plist_path(app_path)
    if not plist_path:
        die(f"Info.plist not found in {app_path}, cannot modify.")
        
    # Convert the plist to clean XML text first so it doesn't look like gibberish
    subprocess.run(
        ["plutil", "-convert", "xml1", plist_path],
        capture_output=True
    )
        
    # Now replace the value using plutil
    r = subprocess.run(
        ["plutil", "-replace", "CFBundleIdentifier", "string", new_id, plist_path],
        capture_output=True, text=True,
    )
    
    # If plutil fails for some reason, fallback to Python's plistlib
    if r.returncode != 0:
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)
            data["CFBundleIdentifier"] = new_id
            # Save as XML (FMT_XML) so it remains readable text
            with open(plist_path, "wb") as f:
                plistlib.dump(data, f, fmt=plistlib.FMT_XML)
        except Exception as e:
            die(f"failed to set CFBundleIdentifier: {e}")


def strip_signatures(app_path):
    """Remove _CodeSignature dirs in the app bundle (top-level + embedded)."""
    sig = os.path.join(app_path, "_CodeSignature")
    if os.path.isdir(sig):
        shutil.rmtree(sig, ignore_errors=True)
        
    # Also check the Contents directory just to be thorough
    sig_contents = os.path.join(app_path, "Contents", "_CodeSignature")
    if os.path.isdir(sig_contents):
        shutil.rmtree(sig_contents, ignore_errors=True)
        
    for root, dirs, _ in os.walk(app_path):
        for d in list(dirs):
            if d == "_CodeSignature":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)


def extract_entitlements(app_path):
    """Try to read the app's existing entitlements so we can re-apply them."""
    r = subprocess.run(
        ["codesign", "-d", "--entitlements", "-", "--xml", app_path],
        capture_output=True,
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout
    return None


def resign(app_path, entitlements=None):
    """Ad-hoc sign the app. Optionally re-apply captured entitlements."""
    cmd = ["codesign", "-f", "-s", "-", "--timestamp=none", "--deep"]
    ent_path = None
    if entitlements:
        with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as tf:
            tf.write(entitlements)
            ent_path = tf.name
        cmd += ["--entitlements", ent_path]
    cmd.append(app_path)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die(f"codesign failed:\n{r.stderr}")
    if ent_path:
        try:
            os.unlink(ent_path)
        except OSError:
            pass


def main():
    p = argparse.ArgumentParser(
        prog="xbypasser",
        description="Replace an app's CFBundleIdentifier (from another app or a "
                    "custom value), strip the existing signature, and ad-hoc resign.",
    )
    p.add_argument("app", help="Path to the target .app bundle to modify")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-c", metavar="APP",
                   help="Copy CFBundleIdentifier from APP")
    g.add_argument("-b", metavar="BUNDLEID",
                   help="Use BUNDLEID as the new CFBundleIdentifier")
    args = p.parse_args()

    if not os.path.isdir(args.app):
        die(f"{args.app} is not a directory")

    # Resolve the new bundle id
    if args.c:
        if not os.path.isdir(args.c):
            die(f"source app {args.c} is not a directory")
        new_id = get_bundle_id(args.c)
        print(f"[*] copied CFBundleIdentifier from {args.c}: {new_id}")
    else:
        new_id = args.b
        print(f"[*] using CFBundleIdentifier: {new_id}")

    old_id = get_bundle_id(args.app)
    print(f"[*] original CFBundleIdentifier: {old_id}")

    # Grab entitlements BEFORE stripping the signature
    ents = extract_entitlements(args.app)
    if ents:
        print("[*] preserving existing entitlements")

    print("[*] stripping existing code signature(s)...")
    strip_signatures(args.app)

    print(f"[*] setting CFBundleIdentifier -> {new_id} ...")
    set_bundle_id(args.app, new_id)

    print("[*] ad-hoc resigning...")
    resign(args.app, entitlements=ents)

    print(f"[+] done. {args.app} now reports bundle id: {new_id}")


if __name__ == "__main__":
    main()
