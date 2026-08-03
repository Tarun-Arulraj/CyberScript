# Hardware CTF Cheatsheet — Speed Edition

*Built around common defaults: binwalk, Logic analyzer + sigrok/PulseView, OpenOCD, a
USB-serial adapter for UART, Saleae/PulseView captures given as files, Ghidra (for the
firmware's actual binary logic once extracted). Swap in your actual installed set once
you send it.*

---

```bash
file firmware.bin                     # sometimes identifies filesystem/format directly
binwalk firmware.bin                  # signature scan, first move always
```

**Magic bytes / firmware format quick table:**

| Signature (hex) | Format |
|---|---|
| `68 73 71 73` (`hsqs`) | SquashFS |
| `31 7A 65 5F` variants | Various compressed FS headers, check binwalk output |
| `55 42 49 23` (`UBI#`) | UBI (raw flash filesystem) |
| `85 19` | JFFS2 |
| `27 05 19 56` | U-Boot uImage |
| `D0 0D FE ED` | Device Tree Blob (.dtb) |

---

## 1. Firmware Extraction

```bash
binwalk -e firmware.bin                       # extract everything binwalk recognizes
binwalk --dd='.*' firmware.bin                # more aggressive extraction, ignores file-type filters
binwalk -E firmware.bin                       # entropy graph -- spot encrypted/compressed regions visually

# Manual filesystem extraction if binwalk's auto-extract misses something
unsquashfs -d extracted_fs squashfs_partition.img         # SquashFS
jefferson jffs2_partition.img -d extracted_fs             # JFFS2
ubireader_extract_files ubi_partition.img -o extracted_fs # UBIFS
```

**Once extracted, grep for the usual suspects:**
```bash
grep -rIiE 'flag\{|ctf\{|password|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY' extracted_fs/
find extracted_fs -name "*.key" -o -name "*.pem"
cat extracted_fs/etc/passwd extracted_fs/etc/shadow 2>/dev/null    # default/hardcoded creds
```

---

## 2. UART (Serial Console Access)

```bash
# Identify pins on a physical board: TX/RX/GND (3-4 pins near a labeled header, or trial-and-error
# with a multimeter -- GND has continuity to chassis, TX idles high ~3.3V)

# Connect via USB-serial adapter, then:
screen /dev/ttyUSB0 115200                    # most common baud, try this first
minicom -D /dev/ttyUSB0 -b 115200
python3 -c "
import serial
s = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)
print(s.read(256))
"
```

**If baud rate is unknown, brute force common ones:** 9600, 19200, 38400, 57600,
115200, 230400 (see `serial_protocol_helper.py` in your Hardware toolkit repo for an
automated brute-forcer).

**Common UART wins:**
- Hitting any key during boot often drops into a U-Boot console (`Hit any key to stop autoboot`)
- U-Boot console gives you `printenv`, `setenv`, and often the ability to modify boot args
  to get a root shell (`setenv bootargs ... init=/bin/sh`)
- A live login prompt sometimes has default/blank creds

---

## 3. JTAG / SWD (Debug Access)

```bash
openocd -f interface/<your_adapter>.cfg -f target/<your_chip>.cfg
# example: openocd -f interface/stlink.cfg -f target/stm32f4x.cfg

# Once connected, from a separate terminal:
gdb-multiarch
(gdb) target remote localhost:3333
(gdb) monitor reset halt
(gdb) monitor dump_image firmware_dump.bin 0x08000000 0x100000    # dump flash contents via JTAG
```

Use `jtagenum`/pin-identification scripts if you're given an unlabeled header and need
to figure out which pins are TCK/TMS/TDI/TDO/GND on unfamiliar hardware.

---

## 4. I2C / SPI (Logic Analyzer Captures)

```bash
sigrok-cli -i capture.sr -P i2c:scl=SCL:sda=SDA -A i2c=address-read-write:data-read:data-write
sigrok-cli -i capture.sr -P spi:clk=CLK:mosi=MOSI:miso=MISO:cs=CS -A spi
```
PulseView (sigrok's GUI) is usually faster for these — load the capture, add the
protocol decoder (I2C/SPI/UART all built in), and read the decoded transaction log
directly rather than reconstructing bytes by hand from raw waveforms.

---

## 5. RFID / NFC (if the challenge involves tag dumps)

```bash
# Given a raw dump file (e.g. from a Proxmark3 or similar)
nfc-list                              # list detected tags if you have physical access
mfoc -O dump.mfd                      # Mifare Classic key recovery + dump
mfdread dump.mfd                      # read a dumped Mifare card's sectors
```

---

## 6. Common Firmware Artifact Checklist

| Location | What it usually holds |
|---|---|
| `/etc/passwd`, `/etc/shadow` | Default/hardcoded credentials |
| `/etc/dropbear` or `/etc/ssh` | Hardcoded SSH host keys (often **reused across every device of that model** — check if the key is publicly known) |
| `*.pem`, `*.key`, `*.crt` | Hardcoded certs/private keys |
| `/www` or `/html` | Web management interface source — check for command injection, auth bypass |
| `/bin/*`, `/sbin/*` | Custom binaries worth reversing with Ghidra + your RE cheatsheet |
| U-Boot environment (`uboot-env` partition) | Boot arguments, sometimes a debug/console-enable flag |
| `.dtb` (device tree blob) | Hardware layout — memory addresses, peripheral mappings |

---

## 7. Quick Reference — CTF Triage Checklist

**Given a firmware.bin file, no physical hardware:**
```
file + binwalk signature scan → binwalk -e to extract → grep extracted FS for
creds/keys/flags → if a binary looks custom, hand it to Ghidra (see RE cheatsheet)
```

**Given physical/emulated hardware with an unlabeled header:**
```
Multimeter/continuity check for GND → try UART first (most common, cheapest to try) →
screen/minicom at 115200 → if garbage, brute-force baud rate →
if UART yields nothing, consider JTAG/SWD via OpenOCD
```

**Given a logic analyzer capture file (.sr) instead of live access:**
```
Open in PulseView → add UART/I2C/SPI decoder as appropriate → read decoded output
directly rather than manual waveform reconstruction
```

**Bootloader console reached (U-Boot prompt):**
```
printenv to see current boot args → setenv bootargs to add init=/bin/sh or console access →
boot / reset to apply → should drop to a root shell on next boot
```

---
