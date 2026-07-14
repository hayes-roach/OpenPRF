# OpenPRF

**A browser-based editor for decrypted PlayStation 4 and PlayStation 5 save game files.**

OpenPRF runs entirely in your browser. Save files are never uploaded to a server — all decryption, editing, and re-encryption happens locally on your machine.

![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-PS4%20%7C%20PS5-003791)
![Stack](https://img.shields.io/badge/stack-vanilla%20HTML%2FJS%2FCSS-3dff7c)

---

## Table of Contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [Workflow](#workflow)
- [Features](#features)
- [Supported files](#supported-files)
- [Editing PRF profiles](#editing-prf-profiles)
- [Important constraints](#important-constraints)
- [How it works](#how-it-works)
- [Project structure](#project-structure)
- [Local development](#local-development)
- [Deployment](#deployment)
- [Browser support](#browser-support)
- [Disclaimer](#disclaimer)
- [Credits](#credits)

---

## What it does

OpenPRF lets you inspect and edit decrypted PS4/PS5 save game folders after you have removed the outer console encryption layer. It is especially useful for editing **PRF profile files** — the encrypted config blobs that store in-game settings, stats, and progress data in many titles.

The app can:

- Decrypt and re-encrypt PRF files using the standard TripleDES scheme
- Parse and edit `set` / `seta` / `sets` / `bind` commands inside profiles
- Read game metadata from `sce_sys/param.sfo` and display `icon0.png`
- Preview images, view raw hex, and inspect file metadata
- Export individual files or zip the entire save folder for re-encryption

---

## Quick start

1. **Clone or download** this repository.
2. **Open** `index.html` in a modern browser, or serve the folder with any static file server (see [Local development](#local-development)).
3. **Decrypt** your save at [garlicsaves.com/decrypt](https://garlicsaves.com/decrypt) (outer PS4 container encryption).
4. **Drop** the decrypted save folder into OpenPRF.
5. **Edit** your files, then **download** and **re-encrypt** at [garlicsaves.com/encrypt](https://garlicsaves.com/encrypt) before copying back to your console.

No install step, no build step, no account required.

---

## Workflow

```
Console save export
        │
        ▼
garlicsaves.com/decrypt   ← outer PS4/PS5 container encryption
        │
        ▼
OpenPRF (this tool)       ← edit PRF profiles, inspect files
        │
        ▼
garlicsaves.com/encrypt   ← re-apply container encryption
        │
        ▼
Copy back to console
```

### Step-by-step

| Step | Action |
|------|--------|
| **1. Export** | Copy your save from PS4/PS5 to USB or transfer via the methods your setup supports. |
| **2. Decrypt container** | Use [garlicsaves.com/decrypt](https://garlicsaves.com/decrypt) to strip the outer encryption wrapper. OpenPRF does **not** handle this layer. |
| **3. Load into OpenPRF** | Drag the decrypted folder onto the drop zone, or use **Choose folder** / **Choose files**. |
| **4. Edit** | Select files from the sidebar. PRF files open in the Text tab with live byte-count tracking. |
| **5. Save** | Use **Save & Download** for one file, or **Download all (.zip)** for the full save folder. |
| **6. Re-encrypt** | Upload the zip (or individual files) to [garlicsaves.com/encrypt](https://garlicsaves.com/encrypt). |
| **7. Restore** | Copy the re-encrypted save back to your console. |

---

## Features

### File loading

- **Drag-and-drop** entire save folders (recursive directory traversal)
- **Folder picker** and **multi-file picker** as fallbacks
- Automatically skips OS junk files (`.DS_Store`, `Thumbs.db`, `__MACOSX`, etc.)
- Strips a common top-level wrapper folder so paths like `profile.prf` and `sce_sys/param.sfo` appear at the root

### PRF editing

- Automatic TripleDES decryption on load
- Raw text editor with Latin-1 byte fidelity (no UTF-8 corruption)
- **Format** button: splits crammed single-line configs into one command per line **without changing byte count**
- Live **text region meter** (see [Important constraints](#important-constraints))
- **Save & Download** re-encrypts PRF files before export
- **Decrypted copy** exports a plain `.decrypted.txt` for inspection
- **Undo all changes** reloads the original file from memory

### Inspection

| Tab | Purpose |
|-----|---------|
| **Text** | Edit decrypted PRF/plaintext config content |
| **Hex** | Hex dump with ASCII column (truncated at 64 KB for performance) |
| **Preview** | Image preview for PNG, JPEG, BMP, GIF, ICO, WebP |
| **Info** | File size, MD5, SFO fields, cipher details, command counts |
| **Help** | In-app workflow reminder |

### Save metadata

When `sce_sys/param.sfo` is present, OpenPRF reads:

- `MAINTITLE` / `TITLE` — game name
- `TITLE_ID` — e.g. `CUSA00419`
- `SUBTITLE` / `DETAIL` — additional labels

Game icons are loaded from `icon0.png` (or similar) when available. A small built-in title ID lookup fills in names when the SFO lacks a title string.

### Export

- **Save & Download** — single file, PRF files re-encrypted automatically
- **Download all (.zip)** — entire loaded save, with edits applied to all modified PRF/text files
- Zip filename is derived from the resolved game title (e.g. `grand-theft-auto-v-save.zip`)

---

## Supported files

| Kind | Extensions / names | Behavior |
|------|-------------------|----------|
| **PRF** | `*.prf`, any file matching PRF cipher | Auto-decrypted; editable in Text tab |
| **SFO** | `param.sfo`, `*.sfo` | Parsed for metadata; shown in Info tab |
| **Image** | `.png`, `.jpg`, `.jpeg`, `.bmp`, `.gif`, `.ico`, `.webp`, `.tif` | Preview tab; signature sniffing for honest error messages |
| **Text** | `.txt`, `.cfg`, `.ini`, `.log`, `.json`, `.xml`, `.md`, or >92% printable bytes | Editable if config commands detected |
| **Binary** | Everything else | Hex and Info tabs only |

PRF detection works by attempting TripleDES decryption and checking for `set ` command signatures in the decrypted payload.

---

## Editing PRF profiles

PRF files contain a **text region** of config commands followed by a **binary tail** (padding and game-specific data). OpenPRF preserves this structure:

```
┌─────────────────────────────────────┐
│  Text region (set/bind commands)    │  ← editable
├─────────────────────────────────────┤
│  Binary tail (padding, game data)   │  ← preserved byte-for-byte
└─────────────────────────────────────┘
```

### Recognized commands

The config parser handles these command types:

```
set, seta, sets, bind, unbindall, unbind, exec
```

Example decrypted content:

```
seta player_name "Arthur"
seta money 50000
bind DPAD_UP "+use"
```

### Value editing rules

- **Byte count must stay the same** for the file to remain valid in most games
- Replacing a value with a shorter one leaves the remaining bytes as padding
- Replacing with a longer value truncates to fit the original slot
- The **Format** tool converts whitespace to newlines in a byte-neutral way so crammed profiles become readable

---

## Important constraints

### Text region limit (~1000 bytes)

Most games reject PRF files whose editable text region exceeds roughly **1000 bytes**. OpenPRF tracks this with a meter in the status bar and warns you before saving if you are over the limit.

Keep edits concise. If you need to add many settings, you may hit this ceiling quickly.

### Two layers of encryption

OpenPRF only handles the **inner PRF TripleDES layer**. You must still:

1. Decrypt the **outer save container** before loading files here
2. Re-encrypt the **outer save container** after exporting from here

Use [garlicsaves.com](https://garlicsaves.com) for the outer layer.

### Back up your saves

Always keep a copy of your original save before editing. A bad edit can corrupt progress or make a save unreadable by the game.

---

## How it works

### PRF cryptography

OpenPRF ports the standard PRF crypto scheme (originally from community save tools such as `PrfCrypto.cs`):

| Parameter | Value |
|-----------|-------|
| Algorithm | TripleDES |
| Mode | CBC |
| Padding | None (manual 8-byte block alignment) |
| Key | `Md8ea20lPcftYwsl496q63x9` |
| IV | `0Peyx825` |

Decryption flow:

1. Pad ciphertext to 8-byte blocks
2. TripleDES-CBC decrypt
3. Validate by searching for `set ` in the first 512 bytes

### Config parsing

The parser (`CFG_RX` in `js/main.js`) uses a regex aligned with `PrfConfig.cs` to find commands and track **exact byte offsets** for each value. Rebuilds splice new values back into the original text without shifting the binary tail.

### param.sfo format

PlayStation SFO files use the `\0PSF` magic header with key and data tables. OpenPRF reads:

- `0x0404` — 32-bit integers
- `0x0204` — UTF-8 strings
- Other formats — hex preview

### Privacy model

| Data | Where it goes |
|------|---------------|
| Save files | Stays in browser memory only |
| Edits | Processed client-side |
| Downloads | Generated locally via `Blob` + anchor click |
| Network | Only Google Fonts load from CDN (optional; app works offline for save editing) |

---

## Project structure

```
openprf/
├── index.html          # App shell and layout
├── css/
│   └── styles.css      # Terminal-inspired UI theme
├── js/
│   ├── main.js         # Crypto, parsing, UI, and export logic
│   └── vendor/
│       ├── crypto-js.min.js   # TripleDES, MD5 (v4.1.1)
│       └── jszip.min.js       # Zip export (v3.10.1)
└── README.md
```

There is no bundler, package manager, or build step. The app is plain static files.

### Dependencies (vendored locally)

| Library | Version | Location | Purpose |
|---------|---------|----------|---------|
| [CryptoJS](https://github.com/brix/crypto-js) | 4.1.1 | `js/vendor/crypto-js.min.js` | TripleDES, MD5 |
| [JSZip](https://stuk.github.io/jszip/) | 3.10.1 | `js/vendor/jszip.min.js` | Zip export |
| [Google Fonts](https://fonts.google.com/) | — | CDN in `index.html` | IBM Plex Mono, Big Shoulders Display |

CryptoJS and JSZip are bundled in the repo so PRF editing and zip export work without an internet connection. Fonts still load from Google Fonts when online; the app remains usable offline with system monospace fallbacks.

---

## Local development

Because browsers restrict some file APIs on `file://` URLs, serving the folder locally is recommended:

### Python

```bash
cd openprf
python3 -m http.server 8080
# Open http://localhost:8080
```

### Node.js (npx)

```bash
cd openprf
npx serve .
# or: npx http-server -p 8080
```

### VS Code / Cursor

Use any "Live Server" extension and open `index.html`.

---

## Deployment

Deploy as a static site to any host:

- **GitHub Pages** — push to `gh-pages` or enable Pages on `main`
- **Netlify / Vercel / Cloudflare Pages** — set publish directory to the repo root
- **Any web server** — copy files to `public_html` or equivalent

No server-side code or environment variables are required. The app works fully offline for save editing; only the optional Google Fonts request needs network access.

---

## Browser support

| Feature | Requirement |
|---------|-------------|
| Folder drag-and-drop | Chrome, Edge, Opera (Chromium) |
| Folder picker (`webkitdirectory`) | Chromium browsers; Firefox has limited support |
| File picker fallback | All modern browsers |
| CryptoJS / JSZip | All modern browsers with ES6+ |

**Recommended:** Chrome or Edge for the best folder-loading experience.

---

## Disclaimer

- OpenPRF is an **unofficial community tool**. It is not affiliated with Sony or any game publisher.
- Editing save files may violate a game's terms of service or affect trophies and online features.
- **You are responsible** for your saves. Always back up before editing.
- The authors provide no warranty that edits will work with every game or firmware version.

---

## Credits

- PRF crypto and config parsing logic ported from community save-editing tools (`PrfCrypto.cs`, `PrfConfig.cs`)
- Outer save encryption/decryption via [garlicsaves.com](https://garlicsaves.com)
- Built as a fully client-side, open-source alternative to desktop save editors

---

## License

MIT — use, modify, and distribute freely. See repository license file if present.
