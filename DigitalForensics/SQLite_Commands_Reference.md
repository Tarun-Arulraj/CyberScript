# SQLite Command Reference — CTF / DFIR Edition

Covers the `sqlite3` CLI plus the SQL queries you'll actually use when digging through Chrome/Edge `History`, `Cookies`, `Login Data`, `Web Data`, or any other SQLite DB found in an investigation.

---

## 1. Getting In

```bash
# Open a database (creates it if it doesn't exist — careful on evidence copies!)
sqlite3 History

# Open READ-ONLY (safer for evidence — won't modify the file or create -wal/-shm files)
sqlite3 -readonly History

# Open and immediately run a query, then exit
sqlite3 History "SELECT * FROM urls LIMIT 5;"

# Export query output straight to CSV from the shell
sqlite3 -header -csv History "SELECT * FROM urls;" > urls.csv
```

If a DB is **locked** (browser was running / copied mid-write), copy the `-wal` and `-shm` files alongside it (same folder, same base name) — SQLite needs them to recover uncommitted data. If they're missing you can often still open the DB read-only and get most of the data.

---

## 2. CLI Dot-Commands (once inside the `sqlite3` shell)

| Command | What it does |
|---|---|
| `.tables` | List all tables in the DB |
| `.schema <table>` | Show CREATE TABLE statement (columns + types) for a table |
| `.schema` | Show schema for the entire DB |
| `.headers on` | Show column names in output |
| `.mode column` | Pretty-print in aligned columns |
| `.mode csv` | Output as CSV |
| `.mode json` | Output as JSON |
| `.mode line` | One column per line (good for wide rows) |
| `.width 20 40 10` | Set column widths for `.mode column` |
| `.output result.csv` | Redirect all query output to a file |
| `.output stdout` | Reset output back to terminal |
| `.import data.csv table_name` | Import a CSV into a table |
| `.dump` | Dump entire DB as SQL statements (schema + data) — great for archiving evidence as text |
| `.dump table_name` | Dump just one table |
| `.databases` | Show attached DB files |
| `.indexes <table>` | List indexes on a table |
| `.quit` / `.exit` | Leave the shell |
| `.open <file>` | Open a different DB file without restarting shell |
| `.read script.sql` | Run a `.sql` file of queries |
| `.timeout 5000` | Wait up to 5000ms for a lock before failing (useful on semi-locked evidence files) |

**Typical first moves on an unknown evidence DB:**
```bash
sqlite3 -readonly Cookies
.tables
.schema cookies
.headers on
.mode column
SELECT * FROM cookies LIMIT 5;
```

---

## 3. Core SQL Syntax

```sql
-- Basic select
SELECT column1, column2 FROM table_name;

-- All columns
SELECT * FROM table_name;

-- Filter
SELECT * FROM table_name WHERE column = 'value';

-- Sort
SELECT * FROM table_name ORDER BY column DESC;

-- Limit rows
SELECT * FROM table_name LIMIT 10;

-- Pattern match (wildcard search — % = any chars, _ = single char)
SELECT * FROM table_name WHERE url LIKE '%.onion%';

-- Count rows
SELECT COUNT(*) FROM table_name;

-- Distinct values
SELECT DISTINCT column FROM table_name;

-- Group + count (e.g. most visited domains)
SELECT url, COUNT(*) as visits FROM table_name GROUP BY url ORDER BY visits DESC;

-- Join two tables
SELECT a.col1, b.col2 
FROM table_a a 
JOIN table_b b ON a.id = b.foreign_id;

-- Combine conditions
SELECT * FROM table_name WHERE col1 = 'x' AND col2 > 100;

-- Range on timestamps
SELECT * FROM table_name WHERE timestamp BETWEEN 1000000 AND 2000000;
```

---

## 4. Forensic-Specific Queries (Chrome/Edge `History` DB)

Chrome/Edge timestamps are **WebKit format**: microseconds since **1601-01-01 UTC**. Convert to human-readable in the query itself:

```sql
-- Browsing history, newest first, human-readable time
SELECT 
  url, 
  title, 
  visit_count,
  datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS last_visit_readable
FROM urls
ORDER BY last_visit_time DESC;

-- Search history for a keyword
SELECT url, title, datetime(last_visit_time/1000000-11644473600,'unixepoch') 
FROM urls 
WHERE url LIKE '%wikileaks%' OR title LIKE '%wikileaks%';

-- Download history (from the 'downloads' table)
SELECT 
  target_path, 
  tab_url, 
  datetime(start_time/1000000-11644473600,'unixepoch') AS download_time,
  total_bytes
FROM downloads;

-- Full visit log (individual visit events, not just aggregate per-URL)
SELECT 
  urls.url, 
  datetime(visits.visit_time/1000000-11644473600,'unixepoch') AS visit_time
FROM visits
JOIN urls ON visits.url = urls.id
ORDER BY visits.visit_time DESC;

-- Search terms typed into the address/search bar
SELECT term, datetime(last_visit_time/1000000-11644473600,'unixepoch')
FROM keyword_search_terms
JOIN urls ON keyword_search_terms.url_id = urls.id;
```

**Cookies DB:**
```sql
SELECT 
  host_key, 
  name, 
  value,
  datetime(expires_utc/1000000-11644473600,'unixepoch') AS expires
FROM cookies;
```

**Login Data DB** (passwords are encrypted with DPAPI — you'll get ciphertext, not plaintext, unless you also have the user's DPAPI master key):
```sql
SELECT origin_url, username_value, password_value FROM logins;
```

---

## 5. SQLite Timestamp Conversions (cheat block)

| Browser / Source | Epoch | Conversion in SQL |
|---|---|---|
| Chrome/Edge (WebKit) | microseconds since 1601-01-01 | `datetime(ts/1000000-11644473600,'unixepoch')` |
| Firefox (PRTime) | microseconds since 1970-01-01 | `datetime(ts/1000000,'unixepoch')` |
| Unix epoch (seconds) | seconds since 1970-01-01 | `datetime(ts,'unixepoch')` |
| Windows FILETIME | 100ns intervals since 1601-01-01 | `datetime(ts/10000000-11644473600,'unixepoch')` |

---

## 6. Recovering Deleted Rows

SQLite doesn't always fully erase deleted rows immediately — data can linger in unallocated pages within the file, or in the `-wal` (write-ahead log) file.

```bash
# Try to recover free/unallocated pages and deleted records
strings History | grep -i "http"          # quick and dirty — often finds deleted URLs as raw strings

# Proper tool: sqlite forensic recovery
pip install sqlite_dissect
sqlite_dissect -o output_dir/ History      # parses WAL, freelist pages, carves deleted records

# Alternative: sqlite3 recover extension (built into modern sqlite3 CLI)
sqlite3 History ".recover" > recovered.sql
```

---

## 7. Handy Combos for a CTF

```bash
# Dump every table's schema at once (quick recon on unfamiliar DB)
sqlite3 -readonly evidence.db ".tables" 
sqlite3 -readonly evidence.db ".schema"

# Export every table to its own CSV in one go (bash loop)
for t in $(sqlite3 evidence.db ".tables"); do
  sqlite3 -header -csv evidence.db "SELECT * FROM $t;" > "${t}.csv"
done

# Search every text column of every table for a keyword (rough, brute-force)
sqlite3 evidence.db ".dump" | grep -i "flag{"

# Query directly without opening the shell interactively
sqlite3 evidence.db "SELECT hex(data) FROM blobs WHERE id=1;"   # dump a BLOB as hex
```

---

## 8. GUI Alternative

If CLI queries get tedious mid-CTF: **DB Browser for SQLite** (`sqlitebrowser`) — open the file, click "Browse Data," or use its "Execute SQL" tab for the same queries above with instant visual output. Good for quickly eyeballing table structure before scripting the extraction.

---

*Pair this with the DFIR cheat sheet for the `History`/`Cookies`/`Login Data` file paths and what each table means in context.*
