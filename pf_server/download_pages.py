"""Product downloads and setup guides backed only by the local website catalog."""

from flask import Blueprint, abort, current_app, render_template, request

from .website_releases import ReleaseError, catalog, latest_artifacts

downloads_bp = Blueprint("downloads", __name__)
PLATFORMS = {
    "windows": {
        "name": "Windows",
        "summary": "Desktop app for x64 and ARM64 PCs.",
        "requirements": "Windows 10 or later",
        "kinds": {"gui", "installer"},
        "steps": [
            "Choose x64 for an Intel or AMD PC, or ARM64 for a Windows on ARM device. Check System → About → System type if you are unsure.",
            "Download and run the Qt installer. Choose the components you need; QMaintenanceTool handles component changes and automatic app updates.",
            "Alternatively, extract the complete portable archive and launch the application. Keep its bundled files together. Portable packages require manual updates.",
        ],
    },
    "linux": {
        "name": "Linux",
        "summary": "Desktop app for x64 and ARM64 systems.",
        "requirements": "64-bit Linux · X11 or Wayland",
        "kinds": {"gui", "installer"},
        "steps": [
            "Choose x64 for an Intel or AMD system, or ARM64 for an AArch64 system. Run uname -m in a terminal to check.",
            "Download the Qt installer, allow the .run file to execute, and run it. Choose your components during setup; QMaintenanceTool manages components and automatic app updates.",
            "For a portable installation, extract the complete archive and allow the application file to execute. Keep its bundled libraries and helper executables together. Portable packages require manual updates.",
        ],
    },
    "macos": {
        "name": "macOS",
        "summary": "Desktop app for Intel and Apple Silicon Macs.",
        "requirements": "macOS 14.4 Sonoma or later",
        "kinds": {"gui", "installer"},
        "steps": [
            "Choose ARM64 for Apple Silicon or x64 for Intel. A Universal package, when listed, contains both architectures. Check Apple menu → About This Mac.",
            "Open the Qt installer and choose your components. QMaintenanceTool manages components and automatic app updates. Portable archives are also available, but require manual updates.",
            "Builds may be ad-hoc signed. If macOS blocks a verified download, review the developer information and use the system’s Open or Privacy & Security controls. Follow the included installation instructions.",
        ],
    },
    "android": {
        "name": "Android",
        "summary": "Installable APKs, with CLI setup through Termux.",
        "requirements": "Android 9.0 or later · compatible APK ABI",
        "kinds": {"apk"},
        "steps": [
            "Choose the APK for your device: ARM64 (arm64-v8a), ARMv7 (armeabi-v7a), x86, or x86_64. Availability depends on the published release.",
            "Download the APK and open it with Android’s package installer. Android may ask you to allow installation from the browser or file manager you used.",
            "For the command line, use Termux and the CLI source package. Desktop CLI executables do not run as Android apps. Android download tracking and statistics are unavailable.",
        ],
    },
    "ios": {
        "name": "iOS",
        "summary": "CLI only on a compatible, jailbroken iPhone.",
        "requirements": "palera1n · xz-kitty Python build · NewTerm",
        "kinds": set(),
        "steps": [
            "Use a compatible iPhone already jailbroken with palera1n. Device and iOS-version compatibility are determined by palera1n; this is not support for every iPhone.",
            "Install the xz-kitty Python build and NewTerm in your jailbreak environment. A standard App Store Python app is not the supported setup.",
            "Download the CLI source archive below and extract it in a writable folder. Run the CLI in NewTerm with the dependencies required by that release. There is no native IPA or graphical iOS app.",
            "The current v3.9 CLI works in this setup. For installation help, contact me with your iPhone model, iOS version, Python version, and the exact error.",
        ],
    },
    "cli": {
        "name": "CLI",
        "summary": "Terminal packages and source for supported systems.",
        "requirements": "No Qt or graphical desktop required",
        "kinds": {"cli", "source"},
        "steps": [
            "Choose a package matching both your operating system and architecture. Extract all files together and run the included CLI executable from a terminal.",
            "Keep bundled support files alongside the executable. On Linux and macOS, allow the executable to run before launching it.",
            "Android uses Termux. iOS requires a palera1n-jailbroken iPhone, the xz-kitty Python build, and NewTerm. Both use source-based setup rather than desktop binaries.",
            "For source packages, read the included README and dependency declarations. Porn_Fetch_CLI.py is the command-line entry point; the desktop launcher requires Qt.",
        ],
    },
}
ARCH_LABELS = {
    "x64": "x64 / Intel / AMD",
    "arm64": "ARM64 / AArch64",
    "x86": "x86 / 32-bit Intel",
    "armv7": "ARMv7 / 32-bit ARM",
    "x32": "x32 / 32-bit Linux",
    "riscv64": "RISC-V 64-bit",
    "universal": "Universal · Intel + Apple Silicon",
    "any": "Source · platform-specific setup",
}
PLATFORM_ARCH_LABELS = {
    "windows": {"arm64": "ARM64 · Windows on ARM"},
    "macos": {"x64": "Intel (x64)", "arm64": "Apple Silicon (ARM64)"},
    "android": {
        "x64": "x86_64",
        "arm64": "arm64-v8a",
        "armv7": "armeabi-v7a",
        "x86": "x86",
    },
}


def load_catalog():
    try:
        return {"releases": catalog(), "unavailable": False}
    except OSError, ValueError, ReleaseError:
        current_app.logger.warning("Website release catalog is unavailable")
        return {"releases": [], "unavailable": True}


def download_context(selected_platform=None):
    data = load_catalog()
    channel = request.args.get("channel")
    channel = channel if channel in {"stable", "beta"} else None
    releases = data["releases"]
    cards = []
    for key, info in PLATFORMS.items():
        files = (
            latest_artifacts(
                releases, None if key == "cli" else key, info["kinds"], channel
            )
            if info["kinds"]
            else []
        )
        if key in {"ios", "android"}:
            files += latest_artifacts(releases, "any", {"source"}, channel)
        for file in files:
            file["arch_label"] = PLATFORM_ARCH_LABELS.get(file["platform"], {}).get(
                file["arch"], ARCH_LABELS[file["arch"]]
            )
        cli_files = latest_artifacts(
            releases, None if key == "cli" else key, {"cli", "source"}, channel
        )
        if key != "cli":
            cli_files += latest_artifacts(releases, "any", {"source"}, channel)
        for file in cli_files:
            file["arch_label"] = PLATFORM_ARCH_LABELS.get(file["platform"], {}).get(
                file["arch"], ARCH_LABELS[file["arch"]]
            )
        # Prefer stable packages, then the managed Qt installer for each CPU.
        # Older manifests retain their original experimental metadata; installers
        # are now supported and recommended regardless of that historical flag.
        recommended = {}
        for file in files:
            if file["kind"] not in {"gui", "apk", "installer"}:
                continue
            if file["experimental"] and file["kind"] != "installer":
                continue
            file["installation_note"] = (
                "Qt installer · Choose components and get automatic app updates with QMaintenanceTool."
                if file["kind"] == "installer"
                else "Portable app · Updates must be downloaded and installed manually."
                if file["kind"] == "gui"
                else "APK · Open the downloaded file to install."
            )
            rank = (file["channel"] != "stable", file["kind"] != "installer")
            previous = recommended.get(file["arch"])
            if previous is None or rank < (
                previous["channel"] != "stable",
                previous["kind"] != "installer",
            ):
                recommended[file["arch"]] = file
        primary = list(recommended.values())
        has_stable = any(file["channel"] == "stable" for file in primary)
        default = next(
            (
                file
                for file in primary
                if file["arch"] == "universal"
                and (file["channel"] == "stable" or not has_stable)
            ),
            None,
        )
        if (
            default
            and default["kind"] == "gui"
            and any(
                file["kind"] == "installer"
                and (file["channel"] == "stable" or default["channel"] != "stable")
                for file in primary
            )
        ):
            # Ask for the chip rather than defaulting to a portable universal app
            # when an equally suitable managed installer is available.
            default = None
        if key == "android":
            default = next(
                (file for file in primary if file["arch"] == "arm64"), default
            )
        cards.append(
            dict(
                info,
                key=key,
                files=files,
                cli_files=cli_files,
                primary=primary,
                default=default,
            )
        )
    return dict(data, cards=cards, channel=channel, selected_platform=selected_platform)


def render_download_page():
    return render_template("download.html", **download_context())


@downloads_bp.get("/download/<platform>")
def platform_download(platform):
    if platform not in PLATFORMS:
        abort(404)
    context = download_context(platform)
    card = next(card for card in context["cards"] if card["key"] == platform)
    return render_template("download_platform.html", card=card, **context)


@downloads_bp.get("/releases")
def release_history():
    return render_template("release_history.html", **load_catalog())


@downloads_bp.get("/releases/<version>")
def release_notes(version):
    data = load_catalog()
    release = next(
        (item for item in data["releases"] if item["version"] == version), None
    )
    if not release:
        abort(404)
    return render_template("release_notes.html", release=release)


@downloads_bp.get("/help")
def help_page():
    return render_template("help.html")
