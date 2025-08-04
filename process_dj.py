# Original idea and most of the logic (minus Spotify API stuff)
# from Laurie Wired's Infinite Radio, copied on original_process_dj.py

# top_process_dj_refined.py

import time
import sys
import psutil
import requests
import argparse
import platform
from collections import defaultdict

import socket
import os
from dotenv import load_dotenv
import threading
from base64 import urlsafe_b64encode
import webbrowser
import configparser
import re

load_dotenv()

# --- Configuration: Process Filtering ---

# Processes to always ignore. This is our primary filter.
PROCESS_BLACKLIST = {
    # macOS
    "kernel_task",
    "launchd",
    "cfprefsd",
    "logd",
    "UserEventAgent",
    "runningboardd",
    "CommCenter",
    "SpringBoard",
    "backboardd",
    "ReportCrash",
    "spindump",
    "WindowServer",
    "loginwindow",
    "SystemUIServer",
    "Dock",
    "Finder",
    "mds",
    "mds_stores",
    "mdworker",
    "mDNSResponder",
    "coreaudiod",
    "coreduetd",
    "cloudd",
    "bird",
    "nsurlsessiond",
    "cfnetworkd",
    "rapportd",
    "sharingd",
    "bluetoothd",
    "timed",
    "secd",
    "trustd",
    "askpermissiond",
    "dasd",
    "AirPlayXPCHelper",
    "universalaccessd",
    "syspolicyd",
    "tccd",
    "ScreenTime",
    "distnoted",
    "lsd",
    # Linux
    "systemd",
    "kthreadd",
    "kworker",
    "ksoftirqd",
    "dbus-daemon",
    "udevd",
    "rsyslogd",
    "cron",
    "irqbalance",
    "polkitd",
    "udisksd",
    "gdm",
    "sddm",
    "pipewire",
    "wireplumber",
    "pulseaudio",
    "Xorg",
    "Xwayland",
    "gnome-shell",
    "kwin_x11",
    # Windows
    "system",
    "System Idle Process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "sihost.exe",
    "ctfmon.exe",
    "fontdrvhost.exe",
    "audiodg.exe",
    "RuntimeBroker.exe",
}


def is_script_process(cmdline):
    """Check if a process is running this script"""
    if not cmdline:
        return False
    cmdline_str = " ".join(cmdline)
    script_names = ["process_dj.py", "top_process_dj.py", "process_dj_refined.py"]
    return any(script_name in cmdline_str for script_name in script_names)


def map_process_to_genre(process_name, cmdline_str="", verbose=False):
    """Maps a process name to a music genre. Now includes cmdline for better context."""
    p_name = process_name.lower().replace(".exe", "")
    cmdline_lower = cmdline_str.lower()

    # Debug output to see what we're working with
    if verbose:
        print(f"   DEBUG: Processing '{process_name}' -> '{p_name}'")

    config = configparser.ConfigParser()
    config.read("config.ini")

    # More reliable mapping for Mac apps running under generic names like 'Electron'
    if "electron" in p_name:
        if "visual studio code.app" in cmdline_lower:
            p_name = "vscode"
        elif "obsidian.app" in cmdline_lower:
            p_name = "obsidian"
        elif "slack.app" in cmdline_lower:
            p_name = "slack"
        elif "discord.app" in cmdline_lower:
            p_name = "discord"
        elif "whatsapp.app" in cmdline_lower:
            p_name = "whatsapp"
        elif "figma.app" in cmdline_lower:
            p_name = "figma"
        elif "notion.app" in cmdline_lower:
            p_name = "notion"
        elif "spotify.app" in cmdline_lower:
            p_name = "spotify"

    # Gaming - check if any game keyword is in the process name
    gaming_keywords = [
        "steam",
        "lutris",
        "csgo",
        "dota2",
        "valorant",
        "league of legends",
        "fortnite",
        "minecraft",
        "overwatch",
        "apex legends",
        "rocket league",
        "cyberpunk2077",
        "elden ring",
        "witcher3",
        "gta",
        "fifa",
        "nba2k",
        "call of duty",
        "battlefield",
        "destiny2",
        "warframe",
        "world of warcraft",
        "final fantasy",
        "assassins creed",
        "far cry",
        "tomb raider",
        "skyrim",
        "fallout",
        "diablo",
        "starcraft",
        "hearthstone",
        "wow",
        "lol",
        "dota",
        "pubg",
        "among us",
        "fall guys",
        "rust",
        "ark",
        "terraria",
        "stardew valley",
        "cities skylines",
        "civilization",
        "total war",
        "age of empires",
        "counter-strike",
        "rainbow six",
        "sea of thieves",
        "no mans sky",
        "subnautica",
        "epic games",
        "origin",
        "uplay",
        "battle.net",
        "gog galaxy",
        "gamepass",
    ]
    if any(keyword in p_name for keyword in gaming_keywords):
        print(f"\x1b[36mMatched 'gaming'\x1b[39m")
        return config.get("Playlists", "gaming")

    # Development & Programming
    dev_keywords = [
        "code",
        "vscode",
        "cursor",
        "pycharm",
        "intellij",
        "webstorm",
        "phpstorm",
        "clion",
        "datagrip",
        "vim",
        "nvim",
        "neovim",
        "emacs",
        "sublime text",
        "atom",
        "brackets",
        "notepad++",
        "xcode",
        "android studio",
        "unity",
        "unreal engine",
        "godot",
        "blender",
        "docker",
        "kubernetes",
        "kubectl",
        "helm",
        "terraform",
        "ansible",
        "vagrant",
        "git",
        "github desktop",
        "sourcetree",
        "gitkraken",
        "fork",
        "tower",
        "postman",
        "insomnia",
        "curl",
        "wget",
        "httpie",
        "ngrok",
        "localtunnel",
        "mysql workbench",
        "pgadmin",
        "dbeaver",
        "tableplus",
        "sequel pro",
        "robo 3t",
        "redis-cli",
        "mongodb compass",
        "elasticsearch",
        "kibana",
        "grafana",
        "jupyter",
        "anaconda",
        "spyder",
        "rstudio",
        "matlab",
        "octave",
        "node",
        "npm",
        "yarn",
        "python",
        "ruby",
        "php",
        "java",
        "golang",
        "rustc",
        "wireshark",
        "burp suite",
        "metasploit",
        "nmap",
        "sqlmap",
    ]
    if any(keyword in p_name for keyword in dev_keywords):
        print(f"\x1b[36mMatched 'development'\x1b[39m")
        return config.get("Playlists", "development")

    # Web Browsing
    browser_keywords = [
        "chrome",
        "firefox",
        "safari",
        "edge",
        "brave",
        "opera",
        "vivaldi",
        "chromium",
        "tor browser",
        "librewolf",
        "waterfox",
        "seamonkey",
        "internet explorer",
        "ie",
        "msedge",
    ]
    if any(keyword in p_name for keyword in browser_keywords):
        print(f"\x1b[36mMatched 'browser'\x1b[39m")
        return config.get("Playlists", "browser")

    # Media & Entertainment
    media_keywords = [
        "spotify",
        "apple music",
        "youtube music",
        "pandora",
        "soundcloud",
        "vlc",
        "mpv",
        "quicktime",
        "windows media player",
        "media player classic",
        "kodi",
        "plex",
        "jellyfin",
        "emby",
        "netflix",
        "hulu",
        "disney+",
        "youtube",
        "twitch",
        "obs",
        "streamlabs",
        "xsplit",
        "restream",
        "audacity",
        "garage band",
        "logic pro",
        "ableton live",
        "fl studio",
        "cubase",
        "pro tools",
        "reaper",
        "reason",
        "bitwig",
        "studio one",
    ]
    if any(keyword in p_name for keyword in media_keywords):
        print(f"\x1b[36mMatched 'media'\x1b[39m")
        return config.get("Playlists", "media")

    # Communication & Social
    comm_keywords = [
        "discord",
        "slack",
        "teams",
        "zoom",
        "skype",
        "webex",
        "gotomeeting",
        "telegram",
        "whatsapp",
        "signal",
        "messenger",
        "imessage",
        "facetime",
        "thunderbird",
        "outlook",
        "mail",
        "gmail",
        "yahoo mail",
        "protonmail",
        "tweetdeck",
        "twitter",
        "facebook",
        "instagram",
        "linkedin",
        "reddit",
        "mastodon",
        "matrix",
        "element",
        "riot",
        "irc",
        "hexchat",
        "weechat",
    ]
    if any(keyword in p_name for keyword in comm_keywords):
        print(f"\x1b[36mMatched 'communication'\x1b[39m")
        return config.get("Playlists", "communication")

    # Terminals & Command Line
    terminal_keywords = [
        "terminal",
        "iterm",
        "alacritty",
        "kitty",
        "konsole",
        "gnome-terminal",
        "xterm",
        "urxvt",
        "terminator",
        "tilix",
        "hyper",
        "warp",
        "tabby",
        "powershell",
        "cmd",
        "bash",
        "zsh",
        "fish",
        "tmux",
        "screen",
        "windows terminal",
        "wt",
        "pwsh",
    ]
    if any(keyword in p_name for keyword in terminal_keywords):
        print(f"\x1b[36mMatched 'terminal'\x1b[39m")
        return config.get("Playlists", "terminal")

    # Office & Productivity
    office_keywords = [
        "word",
        "excel",
        "powerpoint",
        "outlook",
        "onenote",
        "access",
        "publisher",
        "libreoffice",
        "openoffice",
        "writer",
        "calc",
        "impress",
        "draw",
        "base",
        "google docs",
        "google sheets",
        "google slides",
        "google drive",
        "notion",
        "obsidian",
        "logseq",
        "roam research",
        "remnote",
        "anki",
        "evernote",
        "onenote",
        "bear",
        "drafts",
        "ulysses",
        "scrivener",
        "trello",
        "asana",
        "monday",
        "clickup",
        "todoist",
        "things",
        "omnifocus",
        "calendly",
        "fantastical",
        "calendar",
        "reminders",
        "notes",
    ]
    if any(keyword in p_name for keyword in office_keywords):
        print(f"\x1b[36mMatched 'office'\x1b[39m")
        return config.get("Playlists", "office")

    # Design & Creative
    design_keywords = [
        "photoshop",
        "illustrator",
        "indesign",
        "after effects",
        "premiere pro",
        "lightroom",
        "bridge",
        "acrobat",
        "xd",
        "dimension",
        "animate",
        "figma",
        "sketch",
        "canva",
        "affinity photo",
        "affinity designer",
        "affinity publisher",
        "pixelmator",
        "gimp",
        "inkscape",
        "krita",
        "procreate",
        "clip studio paint",
        "paint tool sai",
        "artrage",
        "zbrush",
        "maya",
        "3ds max",
        "cinema 4d",
        "houdini",
        "substance painter",
        "substance designer",
        "marmoset toolbag",
        "keyshot",
        "vray",
        "octane",
    ]
    if any(keyword in p_name for keyword in design_keywords):
        print(f"\x1b[36mMatched 'design'\x1b[39m")
        return config.get("Playlists", "design")

    # Video & Audio Editing
    video_keywords = [
        "final cut pro",
        "davinci resolve",
        "premiere pro",
        "after effects",
        "avid media composer",
        "filmora",
        "camtasia",
        "screenflow",
        "handbrake",
        "ffmpeg",
        "vlc",
        "audacity",
        "logic pro",
        "pro tools",
        "reaper",
        "hindenburg",
        "izotope",
        "waves",
        "slate digital",
        "universal audio",
    ]
    if any(keyword in p_name for keyword in video_keywords):
        print(f"\x1b[36mMatched 'video editing'\x1b[39m")
        return config.get("Playlists", "vid_editing")

    # File Management & System
    file_mgr_keywords = [
        "finder",
        "explorer",
        "nautilus",
        "dolphin",
        "thunar",
        "pcmanfm",
        "ranger",
        "nemo",
        "caja",
        "spacefm",
        "double commander",
        "total commander",
        "far manager",
        "midnight commander",
        "mc",
        "ftp",
        "sftp",
        "rsync",
        "filezilla",
        "cyberduck",
        "transmit",
        "winscp",
        "putty",
        "mobaxterm",
        "activity monitor",
        "task manager",
        "process explorer",
        "htop",
        "btop",
        "system monitor",
        "resource monitor",
        "performance monitor",
    ]
    if any(keyword in p_name for keyword in file_mgr_keywords):
        print(f"\x1b[36mMatched 'file management'\x1b[39m")
        return config.get("Playlists", "file_mgmt")

    # Security & VPN
    security_keywords = [
        "nordvpn",
        "expressvpn",
        "surfshark",
        "protonvpn",
        "mullvad",
        "windscribe",
        "tunnelbear",
        "cyberghost",
        "pia",
        "hotspot shield",
        "openvpn",
        "wireguard",
        "lastpass",
        "bitwarden",
        "1password",
        "keeper",
        "dashlane",
        "keychain",
        "malwarebytes",
        "norton",
        "mcafee",
        "kaspersky",
        "bitdefender",
        "avast",
        "avg",
        "windows defender",
        "clamav",
        "sophos",
        "eset",
    ]
    if any(keyword in p_name for keyword in security_keywords):
        print(f"\x1b[36mMatched security -> dark electronic\x1b[39m")
        return config.get("Playlists", "security")

    # Virtual Machines & Containers
    vm_keywords = [
        "vmware",
        "virtualbox",
        "parallels",
        "qemu",
        "kvm",
        "hyperv",
        "docker",
        "podman",
        "containerd",
        "kubernetes",
        "k8s",
        "minikube",
        "vagrant",
        "lxc",
        "lxd",
        "wine",
        "crossover",
        "playonlinux",
    ]
    if any(keyword in p_name for keyword in vm_keywords):
        print(f"\x1b[36mMatched 'virtualization'\x1b[39m")
        return config.get("Playlists", "virtualization")

    # Database & Data Tools
    db_keywords = [
        "mysql",
        "postgresql",
        "sqlite",
        "mongodb",
        "redis",
        "elasticsearch",
        "cassandra",
        "couchdb",
        "influxdb",
        "neo4j",
        "dynamodb",
        "firebase",
        "tableau",
        "power bi",
        "looker",
        "qlik",
        "superset",
        "metabase",
        "jupyter",
        "rstudio",
        "spss",
        "sas",
        "stata",
        "r-studio",
        "r.exe",
        "spark",
        "hadoop",
        "kafka",
        "airflow",
        "prefect",
        "dagster",
    ]
    if any(keyword in p_name for keyword in db_keywords):
        print(f"\x1b[36mMatched 'database'\x1b[39m")
        return config.get("Playlists", "database")

    # E-commerce & Business
    ecom_keywords = [
        "shopify",
        "magento",
        "woocommerce",
        "prestashop",
        "opencart",
        "salesforce",
        "hubspot",
        "pipedrive",
        "zoho",
        "freshworks",
        "quickbooks",
        "xero",
        "wave",
        "sage",
        "tally",
        "peachtree",
        "stripe",
        "paypal",
        "square",
        "adyen",
        "klarna",
        "razorpay",
    ]
    if any(keyword in p_name for keyword in ecom_keywords):
        print(f"\x1b[36mMatched 'ecommerce'\x1b[39m")
        return config.get("Playlists", "ecommerce")

    # Reading & Documentation
    reading_keywords = [
        "kindle",
        "books",
        "apple books",
        "calibre",
        "adobe reader",
        "foxit",
        "sumatra pdf",
        "evince",
        "okular",
        "preview",
        "zathura",
        "mupdf",
        "notion",
        "obsidian",
        "logseq",
        "roam",
        "dendron",
        "foam",
        "gitbook",
        "confluence",
        "wiki",
        "dokuwiki",
        "mediawiki",
        "markdown",
        "typora",
        "mark text",
        "ghostwriter",
        "zettlr",
    ]
    if any(keyword in p_name for keyword in reading_keywords):
        print(f"\x1b[36mMatched 'reading'\x1b[39m")
        return config.get("Playlists", "reading")

    print(f"\x1b[36mNo match found, using default\x1b[39m")
    return config.get("Playlists", "default")  # A good, neutral default


def get_process_name_map():
    """
    On some OSes (macOS), helpers have generic names. This function tries to map them
    to their parent application for more stable tracking.
    e.g., "Google Chrome Helper" -> "Google Chrome"
    """
    process_map = {}
    for p in psutil.process_iter(["pid", "name", "ppid"]):
        try:
            # Simple heuristic: if a helper process is found, map its PID to its parent's name
            if "Helper" in p.info["name"] or "helper" in p.info["name"]:
                parent = psutil.Process(p.info["ppid"])
                process_map[p.info["pid"]] = parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return process_map


def get_top_apps(process_map, verbose=False):
    """
    Gets a dictionary of application CPU usage, coalescing helper processes.
    This is the key to stable CPU measurement.
    """
    app_cpu_usage = defaultdict(float)
    app_cmdlines = {}  # Store a sample cmdline for each app for better mapping

    for p in psutil.process_iter(["pid", "name", "cpu_percent", "cmdline"]):
        try:
            p_info = p.info
            p_name = p_info["name"]

            # 1. Initial Filtering
            if not p_name or p_name in PROCESS_BLACKLIST:
                continue

            # Skip Python processes running this script
            if p_name.lower() in ["python", "python3", "python.exe", "python3.exe"]:
                if is_script_process(p_info["cmdline"]):
                    continue

            # 2. Coalesce helper processes
            # If this PID is in our map (e.g., it's a helper), use the parent's name
            app_name = process_map.get(p_info["pid"], p_name)

            # 3. Aggregate CPU usage - handle None values
            cpu = p_info["cpu_percent"]
            if cpu is not None and cpu > 0:
                app_cpu_usage[app_name] += cpu
                # Store the command line for context, prefer parent process's cmdline
                if app_name not in app_cmdlines:
                    app_cmdlines[app_name] = (
                        " ".join(p_info["cmdline"]) if p_info["cmdline"] else ""
                    )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not app_cpu_usage:
        return None, None

    # Find the top application by summed CPU usage
    top_app_name = max(app_cpu_usage, key=app_cpu_usage.get)
    top_app_cmdline = app_cmdlines.get(top_app_name, "")

    if verbose:
        # Debug print the top 5
        sorted_apps = sorted(
            app_cpu_usage.items(), key=lambda item: item[1], reverse=True
        )
        print("   --- Top 5 Active Applications ---")
        for name, cpu_total in sorted_apps[:5]:
            print(f"     - {name}: {cpu_total:.1f}%")
        print("   ---------------------------------")

    return top_app_name, top_app_cmdline


# def change_server_genre(server_ip, server_port, genre):
#     """Sends a POST request to the music server to change the playlist."""
#     url = f"http://{server_ip}:{server_port}/genre"
#     payload = {"genre": genre}
#     print(f"-> Attempting to change genre to '{genre}'...")
#     try:
#         response = requests.post(url, json=payload, timeout=5)
#         response.raise_for_status()
#         print(f"   SUCCESS: Genre changed to '{response.json().get('genre', genre)}'.")
#     except requests.exceptions.RequestException as e:
#         print(f"   ERROR: Could not connect to the music server at {url}. Details: {e}")

# Spotify API stuff
# region Spotify API stuff
access_token = None
refresh_token = None
expires_in = None
client_id = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
stop = threading.Event()
refresh = None


def refresh_access_token():
    """Refreshes the access token using the refresh token."""
    global access_token, expires_in, refresh_token
    if not refresh_token:
        print(
            "\x1b[31mERROR: No refresh token available. Cannot refresh access token.\x1b[36m"
        )
        return

    try:
        auth_header = urlsafe_b64encode(f"{client_id}:{CLIENT_SECRET}".encode("ascii"))
        headers = {"Authorization": f'Basic {auth_header.decode("ascii")}'}
        form = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        response = requests.post(
            url="https://accounts.spotify.com/api/token",
            headers=headers,
            timeout=5,
            data=form,
        )
        response.raise_for_status()
        response_data = response.json()
        access_token = response_data["access_token"]
        expires_in = response_data["expires_in"]
        # print(
        #     f"\x1b[32mGot access token:'{access_token}' (expires in: {expires_in}s)\x1b[39m"
        # )
        global refresh
        refresh = threading.Timer(
            expires_in - 60, refresh_access_token
        )  # Refresh 1 minute before expiry
        refresh.start()
        if "refresh_token" in response_data:
            refresh_token = response_data["refresh_token"]
            # print(f"\x1b[32mrefresh token:'{refresh_token}'.\x1b[39m")

    except requests.exceptions.RequestException as e:
        print(f"\x1b[31mERROR: Could not connect to Spotify token API. Details: {e}")
    except requests.exceptions.JSONDecodeError as e:
        print(f"\x1b[31mERROR: Could not decode JSON response. Details: {e}")


def socket_thread(server_socket, verbose=False):
    if verbose:
        print(
            "DEBUG: Socket thread started with server_socket:",
            server_socket.getsockname(),
        )
    while not stop.is_set():
        try:
            client_socket, client_address = server_socket.accept()
        except Exception as e:
            if verbose:
                print(f"Socket accept interrupted: {e}")
            return  # Exit if the socket is closed
        if verbose:
            print(f"Connection from {client_address}")

        # Receive request
        req = client_socket.recv(1024).decode()

        ## Step 4: Find beginning of HTTP response body, and write
        ## bytes to a chosen file
        if "?error=access_denied" in req:
            print("\x1b[31mERROR: Access denied when loggin into Spotify\x1b[39m")
            # Prepare HTTP response
            http_response = """
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
    <body style="background-color:#1a1a1a;color:#f0f0f0">
        <h1 style="display:block;margin-inline:auto;color:red">Access was denied while logging into Spotify!</h1>
        <p>This window will close in <span id="seconds">5</span> seconds.</p>
    </body>
    <script>setTimeout(() => {window.close();}, 5000);
    setInterval(() => {let secs=document.getElementById("seconds");let s=parseInt(secs.innerHTML);secs.innerHTML=s-1}, 1000);</script>
</html>
"""
            client_socket.sendall(http_response.encode())
            client_socket.close()
        elif req.startswith("GET /favicon.ico"):
            if verbose:
                print("Received request for favicon.ico, ignoring.")
        elif "?code=" in req:
            if verbose:
                print("Received authorization code from Spotify")
            # Extract the code from the request
            code = req.split("?code=")[1].split("&")[0].split(" ")[0]
            if verbose:
                print(f"Authorization code: {code}")
                # try to get the access token
                print(f"-> Attempting to get access token for code '{code}'...")
            try:
                auth_header = urlsafe_b64encode(
                    f"{client_id}:{CLIENT_SECRET}".encode("ascii")
                )
                headers = {"Authorization": f'Basic {auth_header.decode("ascii")}'}
                form = {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": f"http://{server_socket.getsockname()[0]}:{server_socket.getsockname()[1]}",
                }
                response = requests.post(
                    url="https://accounts.spotify.com/api/token",
                    headers=headers,
                    timeout=5,
                    data=form,
                )
                # print("Response from Spotify token API:", response.content)
                response.raise_for_status()
                response_data = response.json()
                global access_token, expires_in, refresh_token
                access_token = response_data["access_token"]
                expires_in = response_data["expires_in"]
                refresh_token = response_data["refresh_token"]
                if verbose:
                    print(
                        f"\x1b[32mGot access token:'{access_token}' (expires in: {expires_in}s)\nrefresh token:'{refresh_token}'.\x1b[39m"
                    )
                global refresh
                refresh = threading.Timer(
                    expires_in - 60, refresh_access_token
                )  # Refresh 1 minute before expiry
                refresh.start()

                # Prepare HTTP response
                http_response = """
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
    <body style="background-color:#1a1a1a;color:#f0f0f0">
        <h1 style="display:block;margin-inline:auto;color:green">Successfully logged into Spotify!</h1>
        <p>This window will close in <span id="seconds">5</span> seconds.</p>
    </body>
    <script>setTimeout(() => {window.close();}, 5000);
    setInterval(() => {let secs=document.getElementById("seconds");let s=parseInt(secs.innerHTML);secs.innerHTML=s-1}, 1000);</script>
</html>
"""
                client_socket.sendall(http_response.encode())
                client_socket.close()
            except requests.exceptions.RequestException as e:
                print(
                    f"\x1b[31mERROR: Could not connect to Spotify token API.\x1b[39m Details: {e}"
                )
            except requests.exceptions.JSONDecodeError as e:
                print(
                    f"\x1b[31mERROR: Could not decode JSON response.\x1b[39m Details: {e}"
                )
    server_socket.close()


def get_playstate():
    """Sends a GET request to the Spotify API to change the playlist."""
    url = f"https://api.spotify.com/v1/me/player"
    headers = {"Authorization": f"Bearer  {access_token}"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        response_data = response.json()
        if (
            response.status_code == 204
            or response_data.get("is_playing") is None
            or not response_data["is_playing"]
        ):
            print("Spotify is currently not playing anything.")
        elif (
            response_data.get("is_playing") is not None and response_data["is_playing"]
        ):
            print(
                f"You are listening to: {response_data['item']['name']} by {response_data['item']['artists'][0]['name']}"
            )
        # print(f"   SUCCESS: Genre changed to '{response.json().get('genre', genre)}'.")
    except requests.exceptions.RequestException as e:
        print(
            f"\x1b[31mERROR: Could not connect to the music server at {url}.\x1b[39m Details: {e}"
        )
    except requests.exceptions.JSONDecodeError as e:
        print(f"\x1b[31mERROR: Could not decode JSON response.\x1b[39m Details: {e}")


def set_shuffle(shuffle=True):
    """Sends a GET request to the Spotify API to set the playback shuffle."""
    print(f"-> Attempting to set shuffle to {str(shuffle).lower()}...")
    url = f"https://api.spotify.com/v1/me/player/shuffle?state={str(shuffle).lower()}"
    headers = {"Authorization": f"Bearer  {access_token}"}
    try:
        response = requests.put(url, headers=headers, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(
            f"\x1b[31mERROR: Could not connect to the music server at {url}.\x1b[39m Details: {e}"
        )
        if response.status_code == 403:
            response_data = response.json()
            print(
                f"\x1b[31mError\x1b[39m thrown by \x1b[32mSpotify\x1b[39m: {response_data["error"]["message"]}."
            )


def set_repeat(mode="off"):
    """Sends a GET request to the Spotify API to set the repeat mode."""
    print(f"-> Attempting to set repeat mode to {mode}...")
    url = f"https://api.spotify.com/v1/me/player/repeat?state={mode}"
    headers = {"Authorization": f"Bearer  {access_token}"}
    try:
        response = requests.put(url, headers=headers, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(
            f"\x1b[31mERROR: Could not connect to the music server at {url}.\x1b[39m Details: {e}"
        )
        if response.status_code == 403:
            response_data = response.json()
            print(
                f"\x1b[31mError\x1b[39m thrown by \x1b[32mSpotify\x1b[39m: {response_data["error"]["message"]}."
            )


def spotify_play(genre):
    """Sends a GET request to the Spotify API to set the repeat mode."""
    type = "playlist"
    ID = None
    if "open" in genre:
        matches = re.match(
            r"https:\/\/open\.spotify\.com\/(?P<type>\w+)\/(?P<ID>\w+)(?:\?\S+)?", genre
        )
        if matches is None:
            print(f"\x1b[31mERROR: Invalid Spotify URL format:\x1b[39m {genre}")
            return
        type = matches.group("type")
        ID = matches.group("ID")
    elif "spotify" in genre:
        matches = re.match(r"spotify:(?P<type>\w+):(?P<ID>\w+)(?:\?\S+)?", genre)
        if matches is None:
            print(f"\x1b[31mERROR: Invalid Spotify URL format:\x1b[39m {genre}")
            return
        type = matches.group("type")
        ID = matches.group("ID")
    else:
        matches = re.match(r"(?P<ID>\w+)(?:\?\S+)?", genre)
        if matches is None:
            print(f"\x1b[31mERROR: Invalid Spotify URL format:\x1b[39m {genre}")
            return
        ID = matches.group("ID")

    print(
        f"-> Attempting to set playcontext to playlist {genre} -> spotify:{type}:{ID}..."
    )
    url = f"https://api.spotify.com/v1/me/player/play"
    headers = {
        "Authorization": f"Bearer  {access_token}",
        "Content-Type": "application/json",
    }
    data = {"context_uri": f"spotify:{type}:{ID}"}
    try:
        response = requests.get(url, json=data, headers=headers, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(
            f"\x1b[31mERROR: Could not connect to the music server at {url}.\x1b[39m Details: {e}"
        )
        if response.status_code == 403:
            response_data = response.json()
            print(
                f"\x1b[31mError\x1b[39m thrown by \x1b[32mSpotify\x1b[39m: {response_data["error"]["message"]}."
            )


# endregion Spotify API stuff


def main(args):
    """Main loop to monitor the top process and send genre changes."""
    print("--- Top Process DJ Starting ---")
    print(f"Checking for new top process every {args.interval} seconds.")
    # print(f"Targeting server: http://{args.ip}:{args.port}/genre")
    print("Press Ctrl+C to stop.")

    # Create a socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((args.ip, args.port))
    server_socket.listen(5)  # Allow up to 5 clients in queue
    if args.verbose:
        print(f"Server running on \x1b[4;34mhttp://{args.ip}:{args.port}\x1b[0m")
        print(
            "Computed redirect URI:",
            f"http://{server_socket.getsockname()[0]}:{server_socket.getsockname()[1]}",
        )
    t1 = threading.Thread(target=socket_thread, args=(server_socket,))
    t1.start()

    last_top_app = None

    # Initialize psutil.cpu_percent. The first call is always 0.
    for p in psutil.process_iter(["cpu_percent"]):
        pass
    redirect = f"https://accounts.spotify.com/authorize?response_type=code&client_id={client_id}&scope=user-read-playback-state&redirect_uri=http://{server_socket.getsockname()[0]}:{server_socket.getsockname()[1]}"
    print(
        f"Opening web browser to Spotify login...\nIf failed, visit: \x1b[4;34m{redirect}\x1b[0m"
    )
    webbrowser.open(redirect, new=2)  # Open in a new tab, if possible

    try:
        while not access_token:
            time.sleep(1)  # Wait for the socket to receive the access token
        if args.verbose:
            print("Access token received:", access_token)
        while True:
            # Build a map of helper processes to their parents. This is lightweight.
            process_map = get_process_name_map()

            # This is where the magic happens. We get the top app after the sleep.
            # The cpu_percent values now reflect usage over the sleep interval.
            top_app, top_app_cmdline = get_top_apps(process_map, args.verbose)

            if top_app and top_app != last_top_app:
                print(f"\nNew top application: '{top_app}'")

                new_genre = map_process_to_genre(top_app, top_app_cmdline, args.verbose)
                # get_playstate()
                set_repeat("off")  # Turn off repeat mode
                set_shuffle(True)  # Turn on shuffle mode
                spotify_play(new_genre)

                last_top_app = top_app
            elif not top_app and args.verbose:
                print("...no significant user process activity detected.")

            # Sleep after checking, not before
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n--- Top Process DJ Stopping ---")
        stop.set()
        server_socket.close()
        t1.join()  # Wait for the socket thread to finish
        global refresh
        refresh.cancel()  # Stop the refresh timer if it's running

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        stop.set()
        server_socket.close()
        t1.join()  # Wait for the socket thread to finish
        refresh.cancel()  # Stop the refresh timer if it's running


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Monitors the system's top CPU process and changes music genre accordingly."
    )
    parser.add_argument(
        "--ip",
        default="127.0.0.1",
        help="The IP address of the auth callback.",
        required=False,
    )
    parser.add_argument(
        "--port",
        type=int,
        default=3000,
        help="The port of the auth callback.",
        required=False,
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=10,
        help="Interval in seconds to check (default: 10).",
    )
    parser.add_argument("--verbose", action="store_true", help="Reduce output noise.")

    parsed_args = parser.parse_args()
    main(parsed_args)
