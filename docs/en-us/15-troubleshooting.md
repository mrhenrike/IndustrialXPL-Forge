# Troubleshooting

Common issues and solutions for IndustrialXPL-Forge.

---

## Installation Issues

### `
        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
    ` fails

**Symptom:** pip reports build error or dependency conflict.

**Solution:**
```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install with verbose output to see exact error

        $extras = $args[0].Groups[1].Value
        "pip install industrialxpl-forge$extras"
     -v

# If scapy fails on Windows, install Npcap first
# https://npcap.com/

# Python version check
python --version  # must be 3.9+
```

---

### `ixf` command not found after install

**Symptom:** `ixf: command not found` or `'ixf' is not recognized`

**Diagnosis:**
```bash
# Check if entry point installed
pip show industrialxpl-forge | grep -i location

# Find the scripts directory
python -c "import sys; print(sys.prefix + '/Scripts')"   # Windows
python -c "import sys; print(sys.prefix + '/bin')"       # Linux/macOS
```

**Solution:**
```bash
# Linux/macOS: add to PATH
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Windows: add Scripts folder to PATH in System Environment Variables
# Or use the full path:
python -m industrialxpl

# Or from the repo:
python ixf.py
```

---

### Windows crash: `AttributeError: 'NoneType' object has no attribute 'write_history_file'`

**Cause:** readline is None on Windows (Unix-only module), and the shell tried to call it.

**Fix:** Upgrade to v1.0.12+ which guards all readline calls:
```bash
pip install --upgrade industrialxpl-forge
```

If still failing, manually install pyreadline3:
```bash
pip install pyreadline3>=3.4
```

---

### `ModuleNotFoundError: No module named 'scapy'`

**Cause:** scapy failed to install (common on Windows without Npcap).

**Fix:**
```bash
# Install Npcap first (Windows): https://npcap.com/
# Then:
pip install scapy

# On Linux if libpcap missing:
sudo apt install libpcap-dev  # Debian/Ubuntu
sudo dnf install libpcap-devel  # Fedora/RHEL
pip install scapy
```

---

### `ModuleNotFoundError: No module named 'pysnmp'`

**Cause:** pysnmp not installed or wrong version.

**Fix:**
```bash
pip install "pysnmp>=6.1"
# Note: pysnmp v4.x is incompatible with Python 3.12+
```

---

### urllib3/requests version warning on startup

**Symptom:**
```
RequestsDependencyWarning: urllib3 (2.6.3) or chardet doesn't match a supported version!
```

**Fix:**
```bash
pip install "requests>=2.31.0,<3.0" "urllib3>=1.26.0,<3.0"
```

---

## Module Issues

### 0 modules indexed

**Symptom:**
```
[*] Indexing modules…
[+] 0 modules indexed.
```

**Diagnosis:**
```bash
python -c "
from industrialxpl.core.exploit.utils import index_modules, MODULES_DIR
print('MODULES_DIR:', MODULES_DIR)
print('Exists:', MODULES_DIR.exists())
mods = index_modules()
print('Count:', len(mods))
"
```

**Fix:**
```bash
# Reinstall package
pip install --force-reinstall industrialxpl-forge

# Or install from source
git clone https://github.com/mrhenrike/IndustrialXPL-Forge.git
cd IndustrialXPL-Forge
pip install -e .
```

---

### Module import error

**Symptom:**
```
ixf > use cve/siemens/cve_2021_22681_s7_1200_hardcoded_key
[-] Error loading module: ...
```

**Diagnosis:**
```bash
python -c "
from industrialxpl.core.exploit.utils import import_exploit
obj = import_exploit('industrialxpl.modules.cve.siemens.cve_2021_22681_s7_1200_hardcoded_key')
print('OK:', obj)
"
```

**Common causes:**
1. Syntax error in module file — check the file for syntax issues
2. Missing dependency — the module may require an optional package
3. Wrong Python version — some modules use f-strings or walrus operator

---

### `check()` always returns False

**Symptom:** `check` shows NOT VULNERABLE even when target should respond.

**Diagnosis:**
```bash
# Test raw connectivity
python -c "
import socket
s = socket.socket()
s.settimeout(5)
try:
    s.connect(('192.168.1.100', 502))
    print('Port open')
    s.close()
except Exception as e:
    print('Failed:', e)
"
```

**Common causes:**
1. Firewall blocking the port
2. Wrong port number — use `show options` and verify
3. Module probe rejected by device — some devices only respond to specific unit IDs
4. Network routing issue — can you ping the target?

---

### `run` in simulate mode shows nothing

**Cause:** Module's `run()` doesn't call `DestructiveGate.print_simulation()`.

This may be a module bug. Check the module source:
```bash
cat industrialxpl/modules/cve/vendor/module_name.py | grep "print_simulation"
```

If missing, the module only implements live mode. File an issue on GitHub.

---

## Shell Issues

### Tab completion not working

**Windows:** Requires `pyreadline3`. Install if missing:
```bash
pip install pyreadline3
```

**Linux/macOS:** readline should be built-in. If not:
```bash
pip install readline  # macOS
sudo apt install python3-readline  # Debian/Ubuntu
```

---

### Command history not saved between sessions

**Symptom:** Up-arrow doesn't show previous session commands.

**Cause:** `~/.ixf_history` file not being written (permission issue or readline not available).

**Fix:**
```bash
# Check if file exists
ls -la ~/.ixf_history

# Check write permissions
touch ~/.ixf_history
```

---

### ANSI colors display as literal escape codes (Windows)

**Symptom:** Output shows `\x1b[32m[+]\x1b[0m` instead of colored text.

**Fix:** Use Windows Terminal or PowerShell 7:
```powershell
# Install Windows Terminal from Microsoft Store
# Or use PowerShell 7+: https://github.com/PowerShell/PowerShell

# Alternative: disable colors (workaround)
$env:NO_COLOR = "1"
ixf
```

---

## NSE Issues

### `nse install` fails with Permission Error (Linux)

**Fix:**
```bash
sudo python tools/nse_install.py --install
# or
sudo ixf
# then: nse install
```

### `nse install` fails on Windows

**Fix:** Run terminal as Administrator:
1. Right-click PowerShell → Run as Administrator
2. Then run `ixf` and `nse install`

### Nmap not found even though it's installed

**Symptom:** `nse status` shows "Nmap NOT installed" but nmap works in terminal.

**Cause:** nmap not in PATH for the Python process.

**Diagnosis:**
```python
import shutil
print(shutil.which("nmap"))  # Should show path or None
```

**Fix (Linux/macOS):**
```bash
which nmap  # Find nmap path
# Add to PATH if needed
export PATH="/usr/bin:$PATH"
```

**Fix (Windows):**
```powershell
where.exe nmap  # Find nmap path
# Add Nmap folder to PATH in System Environment Variables
```

### NSE script not found by Nmap after install

Run `nmap --script-updatedb` to refresh the script database:
```bash
nmap --script-updatedb

# Or use IXF (it runs this automatically after install)
ixf > nse install
```

---

## SAST / LLM Issues

### `LLM key not configured`

```
ixf > sast /path/to/plc/ --mode sast
[-] No LLM API key configured
```

**Fix:**
```bash
export OPENAI_API_KEY=sk-...
export GOOGLE_AI_STUDIO_API_KEY=AIzaSy...
ixf
```

Or inside IXF:
```
ixf > llm-key gemini AIzaSyBGaoio...
```

### `LLM request failed: HTTP 429`

Rate limit exceeded. Wait a few seconds and retry:
```
ixf > sast /path/to/plc/ --mode sast
```

Or switch to a different provider:
```
ixf > llm-key openai sk-...
```

### SAST response truncated

**Symptom:** Analysis cuts off mid-sentence.

**Cause:** Default max_tokens limit.

**Workaround:** Use a provider with higher token limits (GPT-4o: 128K context, Claude 3.5: 200K).

---

## Performance Issues

### IXF starts slowly (module indexing takes 10+ seconds)

**Cause:** Large number of modules (976+) being indexed.

**Workaround:** Indexing is cached in memory for the session. Subsequent operations are fast.

**Improvement:** Use non-interactive mode for single commands:
```bash
ixf stats  # faster than interactive start + stats
```

### Scan is very slow

**Causes:**
1. Large CIDR range — use `--rate-limit` to control pace
2. High timeout — reduce with `set timeout 3`
3. Many modules per technique — use `ttp-check` for faster check-only mode

```
ixf > ttp T0843 192.168.1.0/24 --rate-limit 100
ixf > set timeout 3
ixf > ttp-check T0843 192.168.1.0/24
```

---

## Getting Help

1. Check this troubleshooting guide
2. Run `python tools/env_doctor.py` for environment diagnostics
3. Search GitHub Issues: https://github.com/mrhenrike/IndustrialXPL-Forge/issues
4. Open a new issue with:
   - IXF version: `ixf stats`
   - Python version: `python --version`
   - OS: `uname -a` (Linux/macOS) or `winver` (Windows)
   - Full error output

---

*Back to [Index](_index.md)*
