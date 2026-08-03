	 # Digital Forensics CTF Cheatsheet — InCTF Edition

---


```bash
file <filename>                    # identify real file type via magic bytes
xxd <filename> | head -5            # eyeball the header
exiftool <filename>                 # metadata (author, GPS, software, comments)
strings <filename> | grep -i flag   # quick flag hunt
strings -n 8 <filename>             # only strings 8+ chars (less noise)
binwalk <filename>                  # scan for embedded/appended files
binwalk -e <filename>               # extract anything binwalk finds
md5sum / sha256sum <filename>       # verify integrity / compare to known hash
```

**Magic bytes table:**

|Type|Hex signature|
|---|---|
|JPEG|`FF D8 FF E0`|
|PNG|`89 50 4E 47`|
|PDF|`25 50 44 46`|
|ZIP|`50 4B 03 04`|
|GIF|`47 49 46 38`|
|ELF|`7F 45 4C 46`|
|E01 (EWF)|`45 56 46 09 0D 0A FF 00`|

---

## 1. Encoding / Hex / Data Transforms

```bash
base64 -d file.txt > out          # decode base64
base64 file.jpg > out.txt         # encode
xxd file.bin                      # hex dump
xxd -r file.hex > file.bin        # reverse hex → binary
xxd -r -p <<< 48656c6c6f          # hex string → ASCII
hexdump -C file | head -5         # canonical hex+ASCII view
echo "text" | rev                 # reverse a string
echo "text" | tr 'A-Za-z' 'N-ZA-Mn-za-m'   # ROT13
python3 -c "print(bytes.fromhex('48656c6c6f'))"   # hex → ascii, alt method
```

---

## 2. Steganography

```bash
steghide info image.jpg                    # check for embedded data
steghide extract -sf image.jpg             # extract (prompts for passphrase)
steghide extract -sf image.jpg -p ""       # try empty passphrase first
stegseek image.jpg rockyou.txt             # FAST steghide passphrase cracker
                                            # (steghide alone can't brute force — stegseek can)
zsteg -a image.png                         # detect LSB stego in PNG (all methods)
zsteg -E b1,r,lsb,xy image.png             # extract a specific bit-plane found by zsteg -a
stegsolve                                  # GUI: cycle through bit-planes / color channels
outguess -r stego.jpg out.txt              # alternate stego tool, sometimes shows up
exiftool image.jpg                         # comments/EXIF often hide flags directly
```

Audio steganography:

```bash
sonic-visualizer file.wav      # add a Spectrogram layer — flags are sometimes drawn as an image in the spectrum
ffmpeg -i file.wav -lavfi showspectrumpic=s=1024x512 spectrum.png   # CLI alternative, no GUI needed
```

QR codes hidden in images:

```bash
zbarimg image.png
```

---

## 3. Hashing & Password Cracking

```bash
md5sum file ; sha256sum file
echo -n "hello" | md5sum                       # hash a known string to compare

hashid hash.txt                                # identify hash type before cracking
john hash.txt --wordlist=rockyou.txt
john --show hash.txt                           # view cracked results
hashcat -m 0 hash.txt rockyou.txt              # -m 0 = MD5, -m 1000 = NTLM, -m 1800 = sha512crypt
hashcat -m <mode> hash.txt rockyou.txt --show  # show cracked results

zip2john file.zip > zip.hash && john zip.hash --wordlist=rockyou.txt
rar2john file.rar > rar.hash && john rar.hash --wordlist=rockyou.txt
bitlocker2john -i bitlocker.dd > bl.hash
hashcat -m 22100 -a 0 bl.hash rockyou.txt -w 3
hashcat -m 22100 bl.hash rockyou.txt --show     # get cracked password back
```

---

## 4. Archives

```bash
7z x archive.7z                                # handles zip/rar/tar/7z/etc
tar -xvf archive.tar.gz
unzip -P password file.zip
fcrackzip -u -D -p rockyou.txt file.zip        # brute-force zip password (fast, no john needed)
```

---

## 5. Network Forensics (Wireshark / tshark)

**GUI workflow (Wireshark):**

- Statistics → Protocol Hierarchy — what protocols exist in the capture
- Statistics → Conversations — who talked to who, data volume
- File → Export Objects → HTTP/SMB/etc — pull out transferred files directly
- Edit → Find Packet → search string "flag" inside packet bytes
- Right-click packet → Follow → TCP/UDP/HTTP Stream

**CLI (tshark) — use when GUI isn't available or for speed:**

```bash
tshark -r cap.pcap -q -z io,phs                       # protocol hierarchy
tshark -r cap.pcap -q -z conv,tcp                     # TCP conversation stats
tshark -r cap.pcap -q -z follow,tcp,ascii,0            # follow stream 0
tshark -r cap.pcap --export-objects http,extracted/    # dump HTTP files
tshark -r cap.pcap -Y "http.request.method==POST"      # find POST (creds/uploads)
tshark -r cap.pcap -Y "http" -T fields -e http.file_data
tshark -r cap.pcap -Y "dns" -T fields -e dns.qry.name  # DNS exfil check
tshark -r cap.pcap -Y "ftp-data" -T fields -e data     # FTP plaintext transfers
tshark -r cap.pcap -T fields -e usb.capdata | grep -v "^$"   # USB HID keystrokes
tshark -r cap.pcap -T fields -e data | xxd             # raw packet bytes as hex
tshark -r cap.pcap -o "tls.keylog_file:sslkeylog.txt"  # decrypt TLS if key given
strings cap.pcap | grep -i flag                        # dumb but fast first pass
```

**USB HID decode note:** raw `usb.capdata` bytes need a HID keycode → character map (search "USB HID usage table" or use a CyberChef recipe) — don't try to eyeball it.

**File carving straight from a pcap:**

```bash
binwalk -e cap.pcap
foremost -i cap.pcap -o out/
```


---

## 6. Disk Image Forensics (Sleuth Kit)

**Identify structure first:**

```bash
fdisk -l disk.img                    # partition table, start sectors, sizes
mmls disk.img                        # Sleuth Kit equivalent, gives byte offsets directly
fsstat -o <offset> disk.img          # filesystem type + details for one partition
```

**Mount a partition (need byte offset = start_sector × sector_size, usually 512):**

```bash
sudo mkdir -p /mnt/p1
sudo mount -o loop,offset=1048576 disk.img /mnt/p1
sudo losetup -a                      # see active loop devices
sudo mount /dev/loopN /mnt/p1        # if you need to attach manually
```

**Browse without mounting (Sleuth Kit, works read-only, no sudo needed):**

```bash
fls -o <offset> disk.img                     # list root of partition at offset
fls -o <offset> disk.img <inode>             # list contents of a directory inode
fls -r -o <offset> disk.img                  # recursive listing, whole partition
fls -r -o <offset> disk.img | grep "*"       # find DELETED entries (marked with *)
icat -o <offset> disk.img <inode> > out.file # dump file/inode contents to disk
tsk_recover -o <offset> disk.img ~/recovered/ # recover EVERYTHING (incl. deleted) to a folder
```

**Deleted file recovery:**

```bash
debugfs disk.img                     # ext-family only, interactive shell
  debugfs> lsdel                     # list deleted inodes
  debugfs> dump <inode> out.txt      # dump one back out

extundelete disk.img --restore-all   # ext-family, auto-restores to RECOVERED_FILES/
foremost -i disk.img -o ./recovered/ # signature-based carving, filesystem-agnostic
photorec disk.img                    # very thorough carving, works on any filesystem
```

**Timeline (MACB) analysis:**

```bash
fls -m / -r -o <offset> disk.img > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv     # human-readable CSV
mactime -b bodyfile.txt -d 2020-01-01         # filter one date
```

|Pattern|Meaning|
|---|---|
|MACB|File created (all 4 timestamps set together)|
|M.C.|Content edited (auto-updates metadata)|
|.A..|File read/opened, unchanged|
|..C.|Permissions/ownership/rename changed|
|M.CB|File copied in|
|MA..|Local move (some filesystems)|

**Git repo hidden inside a disk image:**

```bash
tsk_recover -o <offset> disk.img ~/extracted_git/
find ~/extracted_git -name ".git" -type d
cd <path> && git log --oneline
git log -p | grep "flag{"
```

**⚠ If the image is E01/EWF format (not raw .img/.dd) — Sleuth Kit alone can't read it directly:**

```bash
ewfmount evidence.E01 /mnt/ewf/          # from libewf-tools, exposes a raw .dd-equivalent
mmls /mnt/ewf/ewf1                       # then proceed as normal
```

## 7. Memory Forensics (Volatility 3)

```bash
python3 vol.py -f mem.dmp windows.info                  # confirm OS/profile first
python3 vol.py -f mem.dmp windows.pslist                # running processes
python3 vol.py -f mem.dmp windows.pstree                # parent/child process tree
python3 vol.py -f mem.dmp windows.cmdline                # command lines per process
python3 vol.py -f mem.dmp windows.filescan | grep -i <name>   # find files cached in memory
python3 vol.py -f mem.dmp windows.dumpfiles --pid <PID>  # dump a found file out
python3 vol.py -f mem.dmp windows.netscan                 # network connections at capture time
python3 vol.py -f mem.dmp windows.malfind                 # flags injected/suspicious memory regions
python3 vol.py -f mem.dmp windows.hashdump                 # local account password hashes
python3 vol.py -f mem.dmp windows.registry.printkey --key "<path>"   # read a live registry key from RAM
python3 vol.py -f mem.dmp windows.bitlocker.Bitlocker       # recover BitLocker keys from RAM if present
```

Linux memory images swap the `windows.` prefix for `linux.` (e.g. `linux.pslist`, `linux.bash`, `linux.pstree`).

**Workflow tip:** always run `windows.info` first — if you use the wrong symbol table/profile every other plugin can silently give bad results.

---

## 8. Windows Registry & Event Logs

Registry (once you have RegRipper or similar):

```bash
rip.pl -r SYSTEM -p usbstor          # USB device history
rip.pl -r NTUSER.DAT -p userassist   # GUI program execution history
rip.pl -r SAM -p samparse            # local user accounts
```

Without RegRipper, `regipy` (pure Python, pip-installable, no GUI needed) is a solid fallback:

```bash
pip install regipy
regipy-dump NTUSER.DAT -o dump.json
```

Windows Event Logs — priority Event IDs to filter for:

|Event ID|Meaning|
|---|---|
|4688|Process creation (catches command execution/malware)|
|1102|Audit log cleared (attacker covering tracks)|
|4698|Scheduled task created (persistence)|
|4720|New user account created|
|4625|Failed logon (brute force)|
|4648|Logon with explicit creds (lateral movement)|
|4672|Special/admin privileges assigned|
|4104|PowerShell script block logging (often has the payload in plaintext)|

If you only have raw `.evtx` files and no Event Viewer GUI:

```bash
pip install python-evtx
evtx_dump.py Security.evtx > security.xml       # or use Rust's evtx_dump (faster, single binary)
grep -i "4688\|4625" security.xml
```

EvtxECmd (Zimmerman tool) is much better for this — parses straight to CSV with clean fields.

---

## 9. Office Documents / PDFs / Phishing

```bash
pdfid file.pdf                       # quick scan for JS, embedded files, auto-open actions
pdf-parser file.pdf                  # detailed object-by-object inspection
pdf-parser -o <obj_num> -f file.pdf   # dump a specific object (e.g. decode a stream)

olevba file.docm                     # extract & deobfuscate VBA macros (phishing docs)
oleid file.doc                       # quick indicator scan for a suspicious Office file
oledump.py -s <n> file.doc           # dump a specific OLE stream
```


---

## 10. Regregistry

**Hive file locations on a mounted image:**

|Hive|Path|Holds|
|-|-|-|
|SYSTEM|`Windows/System32/config/SYSTEM`|USB history, services, computer name|
|SOFTWARE|`Windows/System32/config/SOFTWARE`|installed apps, OS version|
|SAM|`Windows/System32/config/SAM`|local users, password hashes|
|SECURITY|`Windows/System32/config/SECURITY`|LSA secrets, audit policy|
|NTUSER.DAT|`Users/<user>/NTUSER.DAT`|per-user: run history, typed paths, recent docs|
|UsrClass.dat|`Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat`|shellbags (folder access history)|

**Live system (reg.exe) — query without exporting a hive:**

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR                       
:: USB device history
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" 
:: Run box history
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run               
:: persistence (auto-start)
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run               
:: persistence, user-level
reg save HKLM\SYSTEM system.hive                                           
:: dump live hive to file
```

**Key artifact locations — flags/evidence live here:**

| Key                                                     | What it tells you                                       |
| ------------------------------------------------------- | ------------------------------------------------------- |
| `SYSTEM\CurrentControlSet\Enum\USBSTOR`                 | USB devices ever connected (serial, first/last plugged) |
| `SYSTEM\MountedDevices`                                 | drive letter → volume GUID mapping                      |
| `NTUSER.DAT\...\Explorer\RunMRU`                        | commands typed in Run dialog                            |
| `NTUSER.DAT\...\Explorer\UserAssist`                    | GUI programs launched (names are ROT13-encoded)         |
| `NTUSER.DAT\...\Explorer\RecentDocs`                    | recently opened files                                   |
| `NTUSER.DAT\...\Explorer\WordWheelQuery`                | Explorer search bar history                             |
| `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | autologon creds (sometimes plaintext password)          |
| `SOFTWARE\...\Run` / `RunOnce`                          | malware/persistence auto-start entries                  |
| `SYSTEM\CurrentControlSet\Services`                     | installed services — check for suspicious ones          |
| `SAM\SAM\Domains\Account\Users`                         | local user accounts (needs SAM+SYSTEM to decrypt)       |
| `SOFTWARE\...\ProfileList`                              | maps SID → user profile path                            |
| `UsrClass.dat\...\Shell\BagMRU`                         | shellbags — folders browsed, even if deleted            |

```bash
rip.pl -r SYSTEM -p shimcache          # program execution evidence, survives                                               reboot
rip.pl -r SYSTEM -p services           # installed services
rip.pl -r NTUSER.DAT -p runmru         # typed Run-box commands
rip.pl -r NTUSER.DAT -p recentdocs     # recently opened files
rip.pl -r SOFTWARE -p winlogon         # autologon creds, shell config
```

**Important RegRipper plugins (`rip.pl -r <hive> -p <plugin>`):**

|Plugin|Hive|Finds|
|-|-|-|
|`usbstor`|SYSTEM|USB device history|
|`shimcache`|SYSTEM|program execution evidence (survives reboot)|
|`services`|SYSTEM|installed services|
|`compname`|SYSTEM|computer name|
|`timezone`|SYSTEM|system timezone (for timeline correction)|
|`networklist`|SOFTWARE|wifi/network connection history|
|`winlogon`|SOFTWARE|autologon creds, shell config|
|`uninstall`|SOFTWARE|installed programs list|
|`profilelist`|SOFTWARE|SID → user profile mapping|
|`samparse`|SAM|local user accounts, last login, group membership|
|`runmru`|NTUSER.DAT|typed Run-box commands|
|`userassist`|NTUSER.DAT|GUI programs launched (ROT13-encoded)|
|`recentdocs`|NTUSER.DAT|recently opened files|
|`typedurls`|NTUSER.DAT|URLs typed in IE/Explorer address bar|
|`wordwheelquery`|NTUSER.DAT|Explorer search bar history|
|`shellbags`|UsrClass.dat|folders browsed, even if deleted|

```bash
rip.pl -l                              # list ALL available plugins for reference
rip.pl -r SYSTEM -p usbstor
rip.pl -r SYSTEM -p shimcache
rip.pl -r SYSTEM -p services
rip.pl -r SYSTEM -p compname
rip.pl -r SYSTEM -p timezone
rip.pl -r SOFTWARE -p networklist
rip.pl -r SOFTWARE -p winlogon
rip.pl -r SOFTWARE -p uninstall
rip.pl -r SOFTWARE -p profilelist
rip.pl -r SAM -p samparse
rip.pl -r NTUSER.DAT -p runmru
rip.pl -r NTUSER.DAT -p userassist
rip.pl -r NTUSER.DAT -p recentdocs
rip.pl -r NTUSER.DAT -p typedurls
rip.pl -r NTUSER.DAT -p wordwheelquery
rip.pl -r UsrClass.dat -p shellbags
```


## 10. Important greps

```bash
# IP addresses (IPv4)
strings file | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}"

# IPv6 addresses
strings file | grep -oE "([a-fA-F0-9]{0,4}:){2,7}[a-fA-F0-9]{0,4}"

# MAC addresses
strings file | grep -oE "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"

# Email addresses
strings file | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

# URLs
strings file | grep -oE "https?://[a-zA-Z0-9./?=_%:-]*"

# Domain names only
strings file | grep -oE "\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b"

# Base64-looking blobs (long unbroken runs)
strings file | grep -oE "[A-Za-z0-9+/]{20,}={0,2}"

# Hex-looking blobs
strings file | grep -oE "\b[0-9a-fA-F]{16,}\b"

# Windows file paths
strings file | grep -oE "[A-Za-z]:\\\\[^\"<>|]*"

# Linux file paths
strings file | grep -oE "/(usr|home|etc|var|tmp|root)[/a-zA-Z0-9._-]*"

# JWT tokens
strings file | grep -oE "eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"

# Private key headers (leaked keys)
strings file | grep -A1 "BEGIN.*PRIVATE KEY"

# Password-looking assignments in config/scripts
strings file | grep -iE "(pass(word)?|pwd|secret|api[_-]?key|token)\s*[:=]\s*['\"]?[^'\"\s]+"

# Base64 password fields specifically
strings file | grep -iE "(pass|pwd|secret)" | grep -oE "[A-Za-z0-9+/]{16,}={0,2}"

# Credit-card-like number patterns
strings file | grep -oE "\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b"

# GUID / UUID
strings file | grep -oE "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
```

**Combine with strings length + case-insensitive flag hunting:**

```bash
strings -n 8 file | grep -iE "flag|ctf|secret|password"
strings file | grep -oE "flag\{[^}]{1,100}\}"     # bound length, avoids garbage match
```

**On a pcap/memory dump — grep straight into tshark/vol output:**

```bash
tshark -r cap.pcap -T fields -e ip.src -e ip.dst | sort -u    # unique IP pairs, no regex needed
strings mem.dmp | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u
```

## 10. Quick Reference — CTF Triage Checklist

**Unknown file:**

```
file → exiftool → strings | grep flag → binwalk → binwalk -e
```

**PCAP:**

```
Protocol Hierarchy → Follow streams one by one → Export HTTP objects →
Check DNS queries → Check FTP data → foremost/binwalk on the pcap →
Check for base64 in payloads → Check USB HID data
```

**Disk image (.img/.dd/.E01):**

```
fdisk -l / mmls → mount or fls -o offset → find deleted (fls | grep "*") →
tsk_recover everything → foremost/photorec for carving → strings on raw image →
exiftool on anything suspicious → check file contents even if extension looks boring
```

**Memory dump:**

```
windows.info → windows.pslist/pstree → windows.cmdline → windows.malfind →
windows.netscan → windows.filescan (for named file) → windows.dumpfiles
```

-------------------------------------------------------------------------------------------------------------




