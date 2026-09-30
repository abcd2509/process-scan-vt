# Scan-Processes — Suspicious Process Detector with VirusTotal Lookup

A PowerShell script that enumerates all running Windows processes, flags ones with suspicious characteristics using a set of heuristics, and optionally checks file hashes against the VirusTotal v3 API.

## What it checks

For every running process, the script inspects:

1. **Execution location** — flags processes running from `Temp`, `AppData`, `Downloads`, `Users\Public`, or `ProgramData`.
2. **System-name spoofing** — flags processes named like core Windows binaries (`svchost.exe`, `lsass.exe`, `explorer.exe`, etc.) but *not* running from `System32`/`SysWOW64`.
3. **Digital signature status** — flags anything unsigned or with an invalid Authenticode signature.
4. **Name mimicry** — flags names that closely resemble system process names without matching exactly (basic typosquat detection).

It also computes the SHA256 hash of every process's executable and, if you supply a VirusTotal API key, submits hashes (not files) for flagged/unsigned processes to VT for a detection count.

## Requirements

- Windows PowerShell (run **as Administrator** for full visibility into system process paths).
- A free [VirusTotal API key](https://www.virustotal.com/gui/join-us) if you want the VT lookups (optional).

## Usage

```powershell
# Full scan with VirusTotal lookups
.\Scan-Processes.ps1 -VTApiKey "your_api_key_here"

# Scan without VirusTotal (faster, no API key needed)
.\Scan-Processes.ps1 -SkipVT
```

Output:
- Color-coded console report of flagged processes.
- A timestamped CSV (`process_scan_<timestamp>.csv`) containing **all** scanned processes, saved next to the script.

A trimmed, scrubbed example of that output is in [`sample_output/process_scan_example.csv`](sample_output/process_scan_example.csv).

## Rate limiting

VirusTotal's free tier allows ~4 requests/minute. The script throttles itself (16-second delay between lookups) and only queries VT for processes that were already flagged by the local heuristics or lack a valid signature — not every process — to conserve your quota.

## Limitations

- Heuristic-based — flags are indicators to investigate, not proof of malware. A clean scan is **not** a guarantee of safety.
- Hash lookups only catch previously-seen malware; a "not found" VT result just means the file is unknown to VT, not that it's safe.
- Should be paired with a real antivirus/EDR product, not used as a replacement.

## License

MIT
