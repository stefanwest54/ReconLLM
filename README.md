ReconLLM
LLM-assisted automated reconnaissance and penetration testing framework
Authorized use only. Only scan systems you own or have written permission to test. Unauthorized scanning is illegal.
ReconLLM pairs automated network scanning (ping + nmap) with a Claude-powered analyst that guides you through the full penetration testing kill chain — from initial recon through foothold, privilege escalation, and intrusion. It runs suggested commands, extracts loot automatically, and persists notes and findings across sessions.
Features

LLM-driven analysis — A Claude analyst interprets scan results, tags findings by severity, suggests prioritized follow-up commands, and advances through engagement phases as evidence accumulates
Three engagement modes — pentest, bugbounty, and ctf, each with tailored analyst behavior
Automatic loot extraction — Credentials, hashes, tokens, shell access, and sensitive file paths are extracted from output and tracked automatically
Persistent sessions — Notes and loot are saved per-target and reloaded on subsequent runs, allowing you to resume mid-engagement
Interactive command execution — Run all suggested commands, select specific ones, skip long-running ones mid-flight (s key), or inject your own output
Streaming output — Analyst responses stream in real time
Report export — Save a full session transcript to a file

Requirements
Python: 3.10+
Python package:
pip install -r requirements.txt
System tools (required):

nmap
ping

System tools (recommended):
sudo apt install -y nmap gobuster ffuf feroxbuster nikto wpscan whatweb \
  wfuzz curl sqlmap hydra metasploit-framework exploitdb \
  enum4linux smbclient crackmapexec nuclei
pip install impacket
Anthropic API key:
export ANTHROPIC_API_KEY='sk-ant-...'
Installation
git clone https://github.com/yourname/reconllm.git
cd reconllm
pip install -r requirements.txt
export ANTHROPIC_API_KEY='sk-ant-...'
Usage
python recon.py <target> [options]
Examples
python recon.py 192.168.1.1
python recon.py scanme.nmap.org --nmap-args "-sV -T4 -p-"
python recon.py 10.10.10.0/24 --no-ping
python recon.py 10.10.10.5 --type bugbounty --output report.txt
python recon.py 10.10.10.5 --type ctf --auto
Options
FlagDefaultDescriptiontarget(required)Target IP, hostname, or CIDR range--nmap-args-sV -T4 --top-ports 1000nmap argument string--no-pingoffSkip the initial ping check--typepentestEngagement type: pentest, bugbounty, ctf--modelclaude-opus-4-6Claude model to use--autooffAutomatically run all suggested commands--max-rounds10Maximum follow-up rounds--output(none)Save session transcript to this file
How It Works

Host discovery — Pings the target to confirm it's up
Port/service scan — Runs nmap and captures raw output
Initial analysis — Scan results are sent to the Claude analyst, which maps the attack surface, tags findings by severity, and suggests follow-up commands
Interactive loop — You choose which commands to run (or let --auto handle it). Output is fed back to the analyst for the next round
Loot tracking — After every round, credentials, hashes, tokens, and shell access are extracted and saved to a per-target loot file
Session persistence — Notes are appended to a per-target file each run; you can resume from where you left off
Attack summary — The analyst produces a structured summary of confirmed vulnerabilities and quick wins for the next session

Engagement Phases
PhaseDescriptionRECONAttack surface mapping, CVE identification, vector prioritizationFOOTHOLDTurning confirmed vulnerabilities or credentials into initial accessESCALATIONPrivilege escalation to root, SYSTEM, or domain adminINTRUSIONLateral movement, data access, persistence, exfiltration paths
Phases advance automatically as evidence accumulates.
Session Files
FileContentssessions/<target>.txtCumulative session notes, appended each runsessions/<target>.loot.jsonStructured loot: credentials, hashes, tokens, shell access, files
Project Structure
reconllm/
├── recon.py         # Main entrypoint: CLI, scan orchestration, interactive loop
├── analyst.py       # Claude API integration: analysis, loot extraction, streaming
├── scanner.py       # ping and nmap wrappers, arbitrary command execution
├── loot.py          # Structured loot tracking and persistence
├── notes.py         # Per-target session note persistence
└── requirements.txt
Disclaimer
This tool is intended for authorized security testing only. You are responsible for ensuring you have explicit written permission before scanning any target. The authors accept no liability for misuse.
