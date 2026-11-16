# GTV Sideload Checker (Android app) — 🚧 scaffold / WIP

An on-device port of the **plain sideload-vetting** tier of
[`gtv-triage`](../README.md). Runs directly on an Android TV / Google TV / Fire TV
device as a sideloaded app — **no PC, no ADB, no root** — and vets the apps you
installed outside the official store.

> **Status:** compiling scaffold with the core logic ported and a first working
> app-list screen. Not yet a finished app — see *Roadmap* below.

## What it does today

- Enumerates every installed package (`QUERY_ALL_PACKAGES`)
- Classifies each app's installer — **Fire OS aware** (Amazon Appstore trusted on
  Fire OS, Google Play everywhere) — to flag genuinely **sideloaded** apps
- Computes the **SHA-256** of each third-party APK
- Substring-matches every app against the bundled **`gtv-iocs.txt`** feed
- Best-effort **firmware integrity** (build tags, test-keys, verified boot, SELinux)
- Produces the same **severity-gated 0–100 score / grade / verdict**
- Shows a TV screen: score header + per-app cards (sideloaded / IOC / store), each
  with its hash and a **VirusTotal link**

## What it deliberately does NOT do (this tier)

A sandboxed app can't see system-wide processes, listening sockets, or run
`dumpsys` (needs root or the `shell` uid). Those live in the ADB tool and would
require a **Shizuku** or root bridge — planned as a separate optional mode.

## Build & run

Requires Android Studio (Koala+) or a local Gradle 8.9 + Android SDK 34.

```bash
# The Gradle wrapper jar isn't checked in. Either open android/ in Android Studio
# (it generates the wrapper automatically), or generate it once with a local Gradle:
cd android
gradle wrapper        # creates ./gradlew and the wrapper jar

# Then build the debug APK:
./gradlew :app:assembleDebug
# -> app/build/outputs/apk/debug/app-debug.apk
```

Install on a device:

```bash
# Over ADB (dev/testing):
adb install -r app/build/outputs/apk/debug/app-debug.apk

# Or sideload the APK on the device itself via Downloader / a USB drive, then launch
# "GTV Sideload Checker" from the Android TV / Google TV home row.
```

> `QUERY_ALL_PACKAGES` is restricted on Google Play, so this app is meant for
> **sideload distribution**, not the Play Store.

## Project layout

```
android/
  app/src/main/
    AndroidManifest.xml            QUERY_ALL_PACKAGES, LEANBACK launcher
    assets/gtv-iocs.txt            copy of the IOC feed (bundled)
    java/com/crash101g/gtvtriage/
      MainActivity.kt              Compose entry point
      core/
        Models.kt                  Severity, AppEntry, TriageReport
        InstallerClassifier.kt     Fire OS detection + trusted-store logic
        PackageInventory.kt        PackageManager enumeration
        ApkHasher.kt               SHA-256 of APKs
        IocMatcher.kt              substring IOC matcher (bundled feed)
        FirmwareIntegrity.kt       Build / SystemProperties / SELinux checks
        Scoring.kt                 severity-gated 0–100 score
        TriageEngine.kt            orchestrates the above
      ui/
        TriageViewModel.kt         runs the scan off the main thread
        TriageScreen.kt            score header + app-list cards
```

## Roadmap

- [ ] Tappable VirusTotal links (open in browser / show QR for TV)
- [ ] On-device YARA (bundle `libyara` via NDK, or port the rules to a matcher)
- [ ] Persistence-lite: boot receivers + `Settings.Secure` a11y/notif/IME readouts
- [ ] Optional **VirusTotal API** mode (enter key, show detection counts)
- [ ] Export / share the report
- [ ] Optional **Shizuku** mode for process/socket/dumpsys depth (ADB-tool parity)
- [ ] Proper TV banner artwork + Compose-for-TV focus polish
- [ ] Real-device validation (onn. 4K Pro + Fire TV Stick)
