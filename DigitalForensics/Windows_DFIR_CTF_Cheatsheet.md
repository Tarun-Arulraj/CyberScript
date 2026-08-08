# Windows DFIR Cheat Sheet — CTF Edition

A field-reference for Windows forensic artifacts: where they live, what tool parses them, and what they tell you. Built for CTF triage (memory/disk images, KAPE collections, FTK/Autopsy cases).

---

## 0. General Workflow (do this first)

1. **Never work on the original image/E01.** Mount it read-only or work on a copy.
2. If you have a full disk image → mount in **FTK Imager** / **Arsenal Image Mounter** / `mount -o ro` (Linux).
3. If it's a **KAPE** output or raw file collection → go straight to parsing with EZ Tools.
4. If you have a **RAM dump** → that's a separate track, use **Volatility3** (see §11).
5. Build a timeline as you go — drop every parsed CSV into **Timeline Explorer** (Eric Zimmerman) or a spreadsheet sorted by timestamp. Most CTF DFIR challenges are "what happened and when," so a timeline solves half the challenge for free.
6. Always note **timezone**. Event logs, `$MFT`, and registry timestamps aren't always in the same timezone — check and normalize before trusting a sequence of events.

**Toolkit to grab beforehand:** [KAPE](https://ericzimmerman.github.io/) + **EZ Tools** (full suite by Eric Zimmerman — PECmd, EvtxECmd, MFTECmd, AmcacheParser, AppCompatCacheParser, RECmd, Registry Explorer, Timeline Explorer, JLECmd, LECmd), **Autopsy**, **FTK Imager**, **Sysinternals Autoruns**, **Volatility3**, **Hindsight**, **DB Browser for SQLite**, **RegRipper**.

---

## 1. Prefetch Files — proof of execution

| | |
|---|---|
| **Location** | `C:\Windows\Prefetch\*.pf` |
| **Tells you** | Program name, run count, first/last 8 run timestamps, files/DLLs it touched (great for spotting USB or network paths malware loaded from) |
| **Tool** | `PECmd.exe -d C:\Windows\Prefetch --csv out\` |
| **Gotcha** | Disabled by default on Windows **Server** editions. Only tracks the last 8 executions per binary (Win10+). File name hash can help confirm exact path even if binary was on a weird volume. |

---

## 2. Event Logs (.evtx)

| | |
|---|---|
| **Location** | `C:\Windows\System32\winevt\Logs\*.evtx` |
| **Key logs** | `Security.evtx`, `System.evtx`, `Application.evtx`, `Microsoft-Windows-PowerShell%4Operational.evtx`, `Microsoft-Windows-TaskScheduler%4Operational.evtx`, `Microsoft-Windows-Windows Defender%4Operational.evtx`, `Microsoft-Windows-Sysmon%4Operational.evtx` (if Sysmon was installed — goldmine) |
| **Tool** | `EvtxECmd.exe -d C:\...\Logs --csv out\` → load into Timeline Explorer |

### High-value Event IDs (memorize these for CTFs)
| Event ID | Log | Meaning |
|---|---|---|
| 4624 / 4625 | Security | Successful / failed logon |
| 4634 | Security | Logoff |
| 4672 | Security | Special privileges (admin) assigned to logon |
| 4688 | Security | Process creation (needs "Audit Process Creation" enabled) |
| 4720 | Security | New user account created |
| 4732 | Security | User added to a security group |
| 1102 | Security | **Audit log cleared** — huge red flag |
| 7045 | System | New **service** installed (classic persistence/lateral movement) |
| 7036 | System | Service started/stopped |
| 106 / 200 / 201 | TaskScheduler-Operational | Scheduled task registered / started / completed |
| 4103 / 4104 | PowerShell-Operational | Module logging / **ScriptBlock logging** (shows deobfuscated commands — check this FIRST for PS-based attacks) |
| 400 / 800 | Windows PowerShell.evtx | Engine state, pipeline execution details |
| 1116 / 1117 | Defender-Operational | Malware detected / action taken |

---

## 3. Browser Artifacts (Chrome / Edge — both Chromium, same schema)

| | |
|---|---|
| **Location** | `C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\` (Chrome)<br>`C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\` (Edge) |
| **Key files** | `History` (URLs, downloads, search terms — SQLite), `Cookies`, `Login Data` (saved creds — SQLite, encrypted), `Web Data` (autofill), `Bookmarks` (JSON) |
| **Tools** | `DB Browser for SQLite` for manual queries, or `Hindsight` / `NirSoft ChromeHistoryView` for a parsed timeline |
| **Gotcha** | These files are **locked while the browser is running** — copy with FTK Imager or `robocopy /b` on a live/mounted system, not a plain `cp`. |

**Useful SQL on `History`:**
```sql
SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') 
FROM urls ORDER BY last_visit_time DESC;
```
(Chrome timestamps are WebKit format — microseconds since 1601-01-01, hence the offset above.)

---

## 4. Recycle Bin — deleted files

| | |
|---|---|
| **Location** | `C:\$Recycle.Bin\<User-SID>\` |
| **Structure** | Each deleted file = pair of `$I######.ext` (metadata: original path, delete timestamp, original size) + `$R######.ext` (actual file content) |
| **Tool** | Autopsy/FTK parse automatically, or manually parse `$I` files (fixed binary header) with a hex editor / `RBCmd.exe` (Zimmerman) |

---

## 5. Scheduled Tasks — persistence

| | |
|---|---|
| **Location** | `C:\Windows\System32\Tasks\<TaskName>` (XML, no file extension) |
| **Registry** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` |
| **Live query** | `schtasks /query /fo LIST /v` |
| **Log** | `Microsoft-Windows-TaskScheduler%4Operational.evtx`, Event IDs 106 (registered), 140/141 (updated/removed), 200/201 (run/completed) |
| **What to look for** | Task `Actions` pointing to `powershell.exe -enc`, `mshta`, `rundll32`, or a binary in `Temp`/`AppData`/`Public` |

---

## 6. PowerShell History

| | |
|---|---|
| **Console history file** | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` — plain text, every command typed interactively |
| **Event logs** | `Microsoft-Windows-PowerShell%4Operational.evtx` (4104 = full script block, defeats basic obfuscation since it logs the deobfuscated content), `Windows PowerShell.evtx` (400/800) |
| **Tip** | If commands are Base64-encoded (`-enc` / `-EncodedCommand`), decode with: `[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("..."))` — this is a very common CTF step. |

---

## 7. Registry — USB history & persistence keys

Grab hives from `C:\Windows\System32\config\` (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT) — locked on a live system, so use `reg save` or pull from an image/KAPE collection. User hive is `C:\Users\<user>\NTUSER.DAT`.

| Artifact | Hive / Key |
|---|---|
| USB device history | `SYSTEM\CurrentControlSet\Enum\USBSTOR` and `...\Enum\USB` |
| USB first/last connect times | `SYSTEM\CurrentControlSet\Enum\USBSTOR\...` + cross-reference `setupapi.dev.log` |
| Drive letter mapping | `SOFTWARE\...\MountedDevices` |
| Autorun persistence | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` / `RunOnce`, same under `HKCU` |
| Services | `SYSTEM\CurrentControlSet\Services\<name>` — check `ImagePath` for odd binaries |
| Recently opened files/folders (per user) | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` |
| Typed paths in Explorer | `NTUSER.DAT\...\Explorer\TypedPaths` |
| **ShellBags** (folder access even after deletion) | `NTUSER.DAT` / `USRCLASS.DAT` — parse with `SBECmd.exe` |
| UserAssist (GUI program execution) | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` (ROT13-encoded key names!) |

**Tools:** `RegRipper` (fast plugin-based dump), `RECmd.exe` + `Registry Explorer` (GUI browsing — best for manual CTF digging).

---

## 8. Amcache.hve & Shimcache — evidence of execution

| | |
|---|---|
| **Amcache location** | `C:\Windows\AppCompat\Programs\Amcache.hve` |
| **Gives you** | SHA1 hash, full path, file size, compile/link timestamp of executed or installed binaries — survives even if the malware file itself was deleted |
| **Tool** | `AmcacheParser.exe -f Amcache.hve --csv out\` |
| **Shimcache (AppCompatCache)** | Lives inside the `SYSTEM` hive: `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`. Shows path + last-modified time, but **does not confirm execution** on its own (just that the file was seen by the OS) — always cross-reference with Prefetch/Amcache/EventID 4688. |
| **Tool** | `AppCompatCacheParser.exe -f SYSTEM --csv out\` |

Cross-referencing **Prefetch + Amcache + Shimcache + Event 4688** for the same binary/hash is the standard way to build airtight "this executed at this time" proof in a CTF write-up.

---

## 9. Startup Folders & Autoruns

| | |
|---|---|
| **User startup** | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` |
| **All-users startup** | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\` |
| **Winlogon hijacks** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` → check `Shell` (should be `explorer.exe` only) and `Userinit` |
| **Fastest single check** | **Sysinternals Autoruns** — enumerates Run keys, services, scheduled tasks, startup folders, WMI event subscriptions, browser extensions, and drivers all in one GUI. If you only have time for one persistence check in a CTF, run this (or its offline mode against a mounted image: `autorunsc.exe -a * -c -h -s -o output.csv`). |

---

## 10. $MFT and Root Filesystem Artifacts

| | |
|---|---|
| **Location** | Root of the volume (hidden), `$MFT` |
| **Gives you** | Full file record for every file **including deleted ones** (if the record hasn't been overwritten) — filename, size, and the 4 MACB timestamps (Modified / Accessed / Changed / Born) in both `$STANDARD_INFORMATION` and `$FILE_NAME` attributes |
| **In FTK Imager** | Mount image → `$MFT` appears at root → export it |
| **Tool** | `MFTECmd.exe -f $MFT --csv out\` → load into Timeline Explorer for a MACB super-timeline |
| **Anti-forensics tell** | If `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps don't match (timestomping), or `$SI` times are *earlier* than `$FN` creation time — that's a strong sign of manual timestamp tampering. Look for this in CTFs that hint at "hidden" or "renamed" files. |
| **Other $ files worth checking** | `$LogFile` and `$UsnJrnl:$J` (NTFS journal — records file operations even after deletion, parse with `MFTECmd` too or `LogFileParser`), `$Boot`, `$SDS`. |

---

## 11. Memory Forensics (if a RAM dump is provided) — Volatility3

Not in your original list but **very commonly paired** with disk artifacts in national-level CTFs. If you get a `.raw`, `.vmem`, `.dmp`, or `.mem` file:

```bash
# Identify the OS profile first
vol3 -f memdump.raw windows.info

# Process listing / tree
vol3 -f memdump.raw windows.pslist
vol3 -f memdump.raw windows.pstree

# Command lines used to launch each process
vol3 -f memdump.raw windows.cmdline

# Find injected/hidden code (classic malware-in-memory check)
vol3 -f memdump.raw windows.malfind

# Network connections at time of capture
vol3 -f memdump.raw windows.netscan

# Dump a suspicious process to disk for further analysis / hashing / VT lookup
vol3 -f memdump.raw -o out\ windows.dumpfiles --pid <PID>

# Registry hives loaded in memory (sometimes yields keys not flushed to disk yet)
vol3 -f memdump.raw windows.registry.hivelist
```

---

## 12. Quick Artifact-to-Question Cheat Map (CTF pattern recognition)

| Question in the challenge | Go straight to |
|---|---|
| "What time did the attacker log in?" | Security.evtx (4624), or if RDP: Event ID 21/25 in `TerminalServices-LocalSessionManager` |
| "What malware/binary was executed?" | Prefetch + Amcache + Shimcache, cross-check hash |
| "What command did the attacker run?" | PowerShell 4104, ConsoleHost_history.txt, or Event 4688 with command-line auditing |
| "How did the attacker persist?" | Autoruns output, Run keys, Services (7045), Scheduled Tasks (106) |
| "What USB device was plugged in and when?" | `USBSTOR` registry key + `setupapi.dev.log` |
| "What file was deleted / exfiltrated?" | Recycle Bin `$I` files, `$MFT`/`$UsnJrnl` for deletion timestamp, browser History for upload sites |
| "What did the user search/browse?" | Chrome/Edge `History` SQLite |
| "Was a log tampered with?" | Event ID 1102 (log cleared), or gaps in `EventRecordID` sequence in EvtxECmd output |
| "Prove file X ran even though it's gone now" | Amcache (survives deletion) + Prefetch |
| "Was a timestamp faked?" | Compare `$SI` vs `$FN` in `$MFT` via MFTECmd |

---

## 13. Handy One-Liners

```powershell
# Decode a Base64 PowerShell -enc command
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("BASE64HERE"))

# Convert Windows FILETIME (used in $MFT, registry) to human time — Python
python3 -c "import datetime; ft=133700000000000000; print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=ft/10))"

# Convert Chrome/WebKit timestamp (microseconds since 1601) — Python
python3 -c "import datetime; t=13350000000000000; print(datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=t))"

# Search all evtx CSVs (post-EvtxECmd) for a keyword across the case
grep -ri "powershell -enc" out\*.csv

# Hash a suspicious binary to check against VirusTotal / provided IOC list
Get-FileHash -Algorithm SHA1 C:\path\to\file.exe
```

---

## 14. Notes / Reminders

- Always **work off a copy**, hash it (`Get-FileHash` / `md5sum`) before touching it, and note the hash in your write-up — good practice even for a CTF and often literally scored.
- **Timezones will trip you up.** `$MFT` and registry timestamps are UTC internally; event log timestamps shown in Event Viewer are localized to the *viewer's* system unless you export raw XML — EvtxECmd gives you UTC in the CSV, which is usually what you want for a clean timeline.
- If multiple artifacts disagree (e.g., Prefetch says a program ran but Amcache doesn't have it) — that's usually not a bug, it's a *clue* (e.g., antiforensics, or the binary ran from a network share which Amcache handles differently).
- Don't skip **Sysmon logs** if present — they're far richer than default Windows auditing (process creation with full command line + parent process + hashes, by default, no extra config needed to read them).
- Keep an evidence/notes log as you go (artifact → finding → timestamp) — most CTF DFIR categories score partial credit for methodology, not just the final flag.

---

*Cheat sheet compiled for personal CTF use — verify tool versions/flags against current EZ Tools releases, syntax can change between versions.*
