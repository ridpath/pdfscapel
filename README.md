<!--
PDFScalpel, forensic PDF analysis toolkit, CTF PDF solver, PDF malware analysis,
PDF watermark removal, PDF password cracking (CTF authorized),
PDF steganography detection, PDF object graph visualization,
PDF form security analysis, PDF anti-forensics detection,
security research PDF tools, digital forensics PDF toolkit
-->

<!--
PDFScalpel is an advanced forensic PDF analysis framework for security research, digital forensics, CTF competitions, penetration testing, malware analysis, steganography detection, PDF structure analysis, encryption assessment, metadata forensics, anti-forensics detection, document authenticity verification, PDF repair, object graph visualization, revision timeline reconstruction, and authorized challenge-based testing.
-->


<p align="center">
  <img src="PDFScalpel.PNG" alt="PDFScalpel - Forensic PDF Analysis Toolkit" width="720">
</p>

# PDFScalpel

Forensic PDF analysis and CTF toolkit for security researchers, forensic analysts, and penetration testers.

## Installation

### Basic Installation

```bash
pip install pdfscalpel
```

### Full Installation (with all features)

```bash
pip install pdfscalpel[full]
```

### Development Installation

```bash
git clone https://github.com/ridpath/pdfscalpel
cd pdfscalpel
pip install -e .[full,dev]
```

### External Tools (Optional)

For enhanced functionality, install external tools:

**Windows:**
```powershell
# Install via package manager or manually download
# - Ghostscript: https://ghostscript.com/download/gsdnld.html
# - QPDF: http://qpdf.sourceforge.net/
# - John the Ripper: https://www.openwall.com/john/
```

**Linux/WSL:**
```bash
sudo apt install ghostscript qpdf john hashcat tesseract-ocr imagemagick
```

**Check dependencies:**
```bash
pdfscalpel check-deps
```

### Shell Completion (Tab Autocomplete)

Enable tab completion for faster command usage:

**Bash:**
```bash
pdfscalpel completion bash > ~/.pdfscalpel-complete.bash
echo "source ~/.pdfscalpel-complete.bash" >> ~/.bashrc
source ~/.bashrc
```

**Zsh:**
```bash
pdfscalpel completion zsh > ~/.pdfscalpel-complete.zsh
echo "source ~/.pdfscalpel-complete.zsh" >> ~/.zshrc
source ~/.zshrc
```

**Fish:**
```bash
pdfscalpel completion fish > ~/.config/fish/completions/pdfscalpel.fish
```

### Command Discovery

**Quick reference for common commands:**
```bash
pdfscalpel commands                    # Show all common commands by category
pdfscalpel commands --search malware   # Search for specific commands
```

**List all available commands:**
```bash
pdfscalpel list-commands               # List all commands
pdfscalpel list-commands --group analyze   # Show only analyze commands
pdfscalpel list-commands --format json     # JSON output for scripting
```

## Quick Start

### Analyze PDF Structure
```bash
pdfscalpel analyze structure document.pdf
pdfscalpel analyze metadata document.pdf
pdfscalpel analyze encryption encrypted.pdf --check-exploits
```

### Forensic Analysis (Malware, Signatures, Forms)
```bash
# Malware and exploit detection
pdfscalpel analyze malware suspicious.pdf
pdfscalpel analyze malware file.pdf --yara-rules ./rules --output report.json

# Digital signature validation
pdfscalpel analyze signatures signed.pdf
pdfscalpel analyze signatures file.pdf --output report.json --format json

# Form security analysis
pdfscalpel analyze form-security form.pdf
pdfscalpel analyze form-security file.pdf --output report.json

# Anti-forensics detection
pdfscalpel analyze anti-forensics document.pdf
pdfscalpel analyze anti-forensics sanitized.pdf --format json

# Advanced steganography detection
pdfscalpel analyze advanced-stego file.pdf
pdfscalpel analyze advanced-stego suspicious.pdf --deep

# PDF repair and damage assessment
pdfscalpel solve repair corrupted.pdf --assess-only
pdfscalpel solve repair broken.pdf --output fixed.pdf --report report.json
```

### Extract Data
```bash
pdfscalpel extract text document.pdf -o output.txt
pdfscalpel extract images document.pdf -o images/
pdfscalpel extract javascript malicious.pdf -o scripts/
pdfscalpel extract revisions modified.pdf -o revisions/
```

### Web Content Extraction
Download paginated content from web APIs and compile into PDFs. Perfect for documentation archives, writeup systems, and API-based content extraction.

```bash
# Simple extraction with URL and page range
pdfscalpel extract web --url "https://api.example.com/page" --pages "1-20" -o output.pdf

# Auto-discover available pages
pdfscalpel extract web --url "https://api.example.com/page" --auto-discover -o output.pdf

# Advanced configuration file
pdfscalpel extract web --config web-scrape-example.toml
```

**Configuration File Example (web-scrape-example.toml):**
```toml
[web_extraction]
base_url = "https://api.example.com/infoiwant"
pages = "1-50"
title = "Documentation Archive"
auto_discover = true
cookies_from_browser = "firefox"

[retry]
max_retries = 5
exponential_backoff = true

[rate_limit]
base_delay_ms = 2000
jitter_ms = 1000
```

**Features:**
- **Auto-discovery**: Automatically find available pages
- **Browser cookies**: Load authentication cookies from Firefox/Chrome/Edge
- **Retry logic**: Automatic retry with exponential backoff
- **Rate limiting**: Configurable delays with jitter to avoid rate limits
- **Progress tracking**: Real-time download progress and statistics
- **Resume support**: Resume from cached downloads (planned)

### Password Cracking (CTF/Authorized Testing)
```bash
# CTF mode (requires challenge ID for audit trail)
pdfscalpel solve password encrypted.pdf --ctf-mode --challenge-id ctf-2024-001

# Dictionary attack
pdfscalpel solve password encrypted.pdf --wordlist rockyou.txt --ctf-mode --challenge-id test

# Brute force
pdfscalpel solve password encrypted.pdf --brute --length 6 --ctf-mode --challenge-id test
```

### Watermark Detection & Removal
```bash
# Detect watermark
pdfscalpel analyze watermark watermarked.pdf

# Remove watermark (auto-detect method)
pdfscalpel mutate watermark watermarked.pdf clean.pdf --remove auto

# Try all removal methods
pdfscalpel mutate watermark watermarked.pdf clean.pdf --remove-all
```

### Flag Hunting (CTF)
```bash
# Hunt for flags with built-in patterns
pdfscalpel solve flag-hunt challenge.pdf --patterns ctf,flag,md5

# Custom pattern
pdfscalpel solve flag-hunt challenge.pdf --custom-pattern "FLAG\{[a-f0-9]+\}"

# Search all layers (text, metadata, streams, revisions)
pdfscalpel solve flag-hunt challenge.pdf --deep --report flag_report.txt
```

### Auto-Solve CTF Challenges
```bash
pdfscalpel solve auto challenge.pdf --ctf-mode --challenge-id ctf-2024-pdf --report solution.txt
```

### Generate CTF Challenges
```bash
# Password-protected challenge
pdfscalpel generate challenge output.pdf --flag "CTF{test_flag}" --difficulty medium --type password

# Steganography challenge
pdfscalpel generate challenge output.pdf --flag "CTF{hidden}" --type stego --difficulty hard

# Multi-stage challenge
pdfscalpel generate challenge output.pdf --flag "CTF{final}" --type multi --stages 3
```

### Object Graph Visualization
```bash
# Generate DOT graph
pdfscalpel analyze graph document.pdf -o graph.dot

# Generate PNG (requires graphviz installed)
pdfscalpel analyze graph document.pdf -o graph.png --format png

# With entropy analysis
pdfscalpel analyze entropy document.pdf --heatmap -o entropy.png
```

### Modify PDFs
```bash
# Merge PDFs
pdfscalpel mutate pages file1.pdf file2.pdf -o merged.pdf --merge

# Extract page range
pdfscalpel mutate pages document.pdf -o output.pdf --extract 1-5,10,15-20

# Add password
pdfscalpel mutate encrypt input.pdf output.pdf --password secret123 --algorithm aes256

# Remove password (requires current password)
pdfscalpel mutate decrypt encrypted.pdf output.pdf --password secret123

# Redact text patterns
pdfscalpel mutate redaction document.pdf output.pdf --pattern "\d{3}-\d{2}-\d{4}"
```

## Command Reference

### Analyze Commands

| Command | Description |
|---------|-------------|
| `structure` | Analyze PDF structure, detect anomalies |
| `metadata` | Extract metadata (Info dict, XMP) |
| `encryption` | Analyze encryption parameters, assess crackability |
| `malware` | Detect malware, exploits, and malicious JavaScript (20+ CVEs) |
| `signatures` | Validate digital signatures and detect forgery attacks |
| `form-security` | Analyze PDF forms for XXE, SSRF, and injection vulnerabilities |
| `anti-forensics` | Detect sanitization tools and anti-forensic manipulation |
| `advanced-stego` | Detect advanced steganography beyond LSB |
| `watermark` | Detect and classify watermarks |
| `graph` | Generate object graph visualization |
| `entropy` | Entropy analysis for malware/stego detection |
| `intelligence` | Generate intelligence report with recommendations |
| `compliance` | Check PDF/A, PDF/X, PDF/E, PDF/UA compliance |
| `render-diff` | Analyze reader-specific rendering differences |

### Extract Commands

| Command | Description |
|---------|-------------|
| `text` | Extract text with layout preservation |
| `images` | Extract all embedded images |
| `javascript` | Extract and deobfuscate JavaScript |
| `attachments` | Extract embedded files |
| `forms` | Extract AcroForm/XFA form data |
| `streams` | Extract and decompress object streams |
| `objects` | Dump specific PDF objects by ID |
| `hidden` | Find invisible/hidden content |
| `revisions` | Extract PDF revision history |
| `web` | Extract paginated web content to PDF |

### Mutate Commands

| Command | Description |
|---------|-------------|
| `pages` | Merge, extract, reorder, delete pages |
| `watermark` | Add or remove watermarks |
| `encryption` | Add or remove password protection |
| `bookmarks` | Add, remove, or auto-generate bookmarks |
| `redaction` | Redact sensitive content |
| `optimize` | Compress, remove unused objects, linearize |

### Solve Commands (CTF/Authorized Testing)

| Command | Description |
|---------|-------------|
| `password` | Crack PDF passwords (requires --ctf-mode) |
| `flag-hunt` | Hunt for flags across all PDF layers |
| `stego` | Detect and extract steganography |
| `auto` | Automatically analyze and solve challenges |
| `repair` | Assess PDF damage and attempt repair/recovery |

### Generate Commands

| Command | Description |
|---------|-------------|
| `challenge` | Generate CTF challenges |
| `corrupted` | Generate intentionally broken PDFs |
| `polyglot` | Create PDF polyglots (PDF+ZIP, PDF+HTML) |

### Utility Commands

| Command | Description |
|---------|-------------|
| `check-deps` | Check all dependencies and show installation instructions |
| `commands` | Quick reference for common commands (searchable) |
| `list-commands` | List all available commands (filterable by group) |
| `completion` | Generate shell completion scripts (bash/zsh/fish) |
| `plugin` | Plugin management (list, enable, disable) |
| `perf` | Performance profiling and benchmarking |

## CTF Mode

CTF mode enforces ethical use with audit trails:

```bash
pdfscalpel solve password encrypted.pdf \
  --ctf-mode \
  --challenge-id "defcon-2024-pdf-01" \
  --output-audit audit.json
```

**CTF Mode Requirements:**
- Challenge ID must be provided
- All operations are logged
- Generates signed provenance file
- Prevents destructive operations without audit

**Audit Log Format:**
```json
{
  "mode": "ctf",
  "challenge_id": "defcon-2024-pdf-01",
  "timestamp": "2024-01-27T12:00:00Z",
  "operations": ["password_crack", "flag_hunt"],
  "results": {...},
  "hash": "sha256:..."
}
```

## Configuration

Create `pdfscalpel.toml` in your project directory or `~/.pdfscalpel.toml`:

```toml
# PDFScalpel Configuration

[ocr]
enabled = true
language = "eng"
jobs = 4
deskew = true

[watermark]
font_size = 72
opacity = 0.3
rotation = 45

[password]
wordlists = ["rockyou.txt", "common-passwords.txt"]
max_brute_length = 6
timeout = 3600  # seconds

[plugins]
enabled = true
directories = ["plugins", "~/.pdfscalpel/plugins"]
```

Load configuration:
```bash
pdfscalpel --config pdfscalpel.toml analyze structure document.pdf
```

## Plugin Development

Create custom plugins by extending base classes:

```python
# plugins/my_analyzer.py
from pdfscalpel.plugins.base import AnalyzerPlugin

class MyAnalyzer(AnalyzerPlugin):
    name = "my-analyzer"
    description = "Custom PDF analysis"
    version = "1.0.0"
    
    def analyze(self, pdf_path, **kwargs):
        # Your analysis logic
        return {"status": "analyzed"}
```

Register plugin:
```bash
pdfscalpel plugin list
pdfscalpel plugin enable my-analyzer
```

## Examples

### Forensic Analysis Workflow
```bash
# 1. Initial triage
pdfscalpel analyze structure suspicious.pdf
pdfscalpel analyze metadata suspicious.pdf

# 2. Malware analysis
pdfscalpel analyze malware suspicious.pdf --output malware_report.json
pdfscalpel extract javascript suspicious.pdf -o js/

# 3. Signature validation (if signed)
pdfscalpel analyze signatures suspicious.pdf

# 4. Deep analysis
pdfscalpel analyze entropy suspicious.pdf --output entropy.png
pdfscalpel analyze anti-forensics suspicious.pdf
pdfscalpel analyze advanced-stego suspicious.pdf --deep

# 5. Intelligence report
pdfscalpel analyze intelligence suspicious.pdf --report report.txt

# 6. Extract timeline
pdfscalpel extract revisions suspicious.pdf -o revisions/
```

### CTF Challenge Solving
```bash
# 1. Auto-solve attempt
pdfscalpel solve auto challenge.pdf --ctf-mode --challenge-id ctf-001 --report solution.txt

# 2. Manual solving
pdfscalpel solve password challenge.pdf --ctf-mode --challenge-id ctf-001
pdfscalpel solve flag-hunt challenge.pdf --patterns ctf
pdfscalpel solve stego challenge.pdf -o extracted/
```

### Watermark Removal (Authorized)
```bash
# 1. Analyze watermark
pdfscalpel analyze watermark document.pdf --verbose

# 2. Remove using recommended method
pdfscalpel mutate watermark document.pdf clean.pdf --remove content-stream

# 3. Try all methods if first fails
pdfscalpel mutate watermark document.pdf clean.pdf --remove-all
```

## Use Cases

**Digital Forensics:**
- Malware detection (JavaScript exploits, CVE fingerprinting, 20+ exploit patterns)
- Digital signature validation and forgery detection
- Document authenticity verification
- Timeline reconstruction from revisions
- Metadata analysis and tool fingerprinting
- Anti-forensics detection (sanitization tool identification)

**CTF Competitions:**
- Password cracking (RC4/AES, all key lengths)
- Advanced steganography detection (stream operators, object ordering, whitespace)
- Flag hunting across all PDF layers
- Challenge creation and testing
- PDF damage assessment and repair

**Penetration Testing:**
- Form exploitation (XFA XXE, SSRF, JavaScript injection - CVE-2025-54988)
- Encryption weakness detection
- Reader-specific exploit analysis
- Polyglot file detection

**Security Research:**
- PDF standard compliance testing
- Rendering difference analysis
- Sanitization tool fingerprinting (ExifTool, MAT2, QPDF, Ghostscript)
- Attack indicator detection (USF, SWA, ISA signature attacks)

## Performance

**Benchmarks (Windows 11, i7-12700K):**
- Structure analysis: 1000-page PDF in <3 seconds
- Password cracking: RC4-40 at 50,000+ passwords/sec
- Object graph generation: 5000 objects in <2 seconds
- Image extraction: 100 images in <1 second

**WSL/Linux Performance:**
- GPU-accelerated cracking with Hashcat: 100x+ improvement
- Parallel processing: 4-8x speedup on multi-core CPUs
- External tool integration: QPDF, John, Ghostscript

## Troubleshooting

**Dependencies missing:**
```bash
pdfscalpel check-deps
```

**Encrypted PDF without password:**
```bash
pdfscalpel analyze encryption document.pdf --check-exploits
# Review crackability assessment before attempting
```

**Watermark won't remove:**
```bash
# Try all methods and compare results
pdfscalpel mutate watermark input.pdf output.pdf --remove-all --compare
```

**Large PDF performance:**
```bash
# Use streaming mode for large files
pdfscalpel analyze structure huge.pdf --streaming
```

## Contributing

1. Fork repository
2. Create feature branch
3. Add tests for new features
4. Run test suite: `pytest`
5. Run linter: `ruff check pdfscalpel/`
6. Run type checker: `mypy pdfscalpel/`
7. Submit pull request

## Ethical Use

**Authorized Use Cases:**
- CTF competitions with `--ctf-mode`
- Authorized penetration testing engagements
- Digital forensics investigations
- Security research and education
- Defensive security analysis

Always obtain proper authorization before using password cracking or exploitation features.

## License

MIT License - See LICENSE file for details

## Credits

Built on: pikepdf, pdfplumber, PyPDF, QPDF, Ghostscript, John the Ripper, Hashcat

PDFScalpel Contributors
