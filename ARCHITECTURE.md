# PDFScalpel Architecture

## Project Structure

```
pdfscalpel/
├── analyze/        # Non-destructive PDF analysis
├── extract/        # Data extraction from PDFs
├── mutate/         # PDF modification operations
├── solve/          # CTF and forensic solving tools
├── generate/       # PDF and challenge generation
├── core/           # Shared utilities and base classes
├── cli/            # Command-line interface
└── plugins/        # Plugin system
```

## Module Responsibilities

### Analyze Module

**Purpose:** Non-destructive analysis and intelligence gathering

**Components:**
- `structure.py` - PDF structure analysis, object tree parsing, anomaly detection
- `metadata.py` - Metadata extraction (Info dict, XMP), tool fingerprinting
- `encryption.py` - Encryption parameter analysis, crackability assessment
- `malware.py` - Malware and exploit detection (20+ CVEs, JavaScript analysis, YARA integration)
- `signatures.py` - Digital signature validation, certificate chain analysis, attack detection (USF, SWA, ISA)
- `form_security.py` - Form vulnerability analysis (XXE, SSRF, JavaScript injection)
- `anti_forensics.py` - Sanitization tool fingerprinting (ExifTool, MAT2, QPDF, Ghostscript)
- `advanced_stego.py` - Advanced steganography detection (stream operators, object ordering, whitespace)
- `watermark.py` - Watermark detection and classification
- `graph.py` - Object graph visualization, DOT generation
- `intelligence.py` - Intelligence synthesis, recommendations, rendering analysis

**Output:** Analysis reports, visualizations, recommendations

### Extract Module

**Purpose:** Extract data from PDFs without modification

**Components:**
- `text.py` - Text extraction with layout preservation
- `images.py` - Image extraction, format detection
- `javascript.py` - JavaScript extraction and deobfuscation
- `attachments.py` - Embedded file extraction
- `forms.py` - AcroForm/XFA form data extraction
- `streams.py` - Object stream extraction and decompression
- `objects.py` - Raw PDF object dumping
- `hidden.py` - Hidden content detection (invisible text, whitespace)
- `revisions.py` - Incremental update extraction, timeline reconstruction

**Output:** Extracted files, text, data structures

### Mutate Module

**Purpose:** Modify PDFs (destructive operations)

**Components:**
- `watermark.py` - Watermark addition and removal (15+ techniques)
- `encryption.py` - Add/remove passwords, set permissions
- `pages.py` - Merge, split, extract, reorder pages
- `bookmarks.py` - Add, remove, auto-generate bookmarks
- `redaction.py` - Redact sensitive content
- `optimize.py` - Compress, linearize, remove unused objects

**Output:** Modified PDF files

### Solve Module

**Purpose:** CTF challenge solving and forensic recovery (ethical use only)

**Components:**
- `password.py` - Password cracking (dictionary, brute force, mask attacks)
- `flag_hunter.py` - Flag detection across all PDF layers
- `stego_solver.py` - Steganography detection and extraction
- `auto_solver.py` - Automated challenge solving orchestration
- `repair.py` - PDF damage assessment and repair (header reconstruction, xref rebuilding, stream recovery)
- `ctf_mode.py` - CTF mode enforcement, audit trail generation

**Output:** Cracked passwords, extracted flags, repaired PDFs, audit logs

**Note:** Password cracking requires `--ctf-mode` and `--challenge-id` for ethical use enforcement

### Generate Module

**Purpose:** Create PDFs and CTF challenges

**Components:**
- `challenges.py` - CTF challenge generation (password, stego, multi-stage)
- `corrupted.py` - Intentional PDF corruption for recovery challenges
- `polyglot.py` - Polyglot file creation (PDF+ZIP, PDF+HTML)
- `steganography.py` - Steganography embedding (LSB, metadata, whitespace)
- `watermark.py` - Watermark template generation

**Output:** Challenge PDFs, solution metadata

### Core Module

**Purpose:** Shared utilities and infrastructure

**Components:**
- `pdf_base.py` - PDFDocument wrapper class (pikepdf abstraction)
- `config.py` - Configuration management (TOML support)
- `constants.py` - Shared constants, patterns, thresholds
- `dependencies.py` - External tool detection, installation guidance
- `exceptions.py` - Custom exception hierarchy
- `logging.py` - Logging and audit infrastructure
- `crypto.py` - Cryptographic utilities (hashing, encryption)
- `image_utils.py` - Image processing (inpainting, frequency analysis)
- `patterns.py` - Regex patterns (flags, hashes, encoding detection)

**Output:** Shared services for all modules

### CLI Module

**Purpose:** Command-line interface implementation

**Components:**
- `main.py` - Click-based CLI, command routing
- `ui.py` - Rich-based UI components (progress bars, tables)
- `validators.py` - Input validation, path checking

**Output:** User-facing command-line interface

### Plugins Module

**Purpose:** Extensible plugin system

**Components:**
- `base.py` - Plugin base classes (AnalyzerPlugin, ExtractorPlugin, GeneratorPlugin)
- `loader.py` - Plugin discovery, registration, lifecycle management
- `examples/` - Example plugins for reference

**Output:** Plugin framework for third-party extensions

## Data Flow

### Analysis Workflow

```
User Command
    ↓
CLI Parser (main.py)
    ↓
Validator (validators.py)
    ↓
PDFDocument (pdf_base.py)
    ↓
Analyzer Module (analyze/*)
    ↓
Intelligence Layer (intelligence.py)
    ↓
Results Formatter (ui.py)
    ↓
Output (JSON/Text/HTML)
```

### CTF Solving Workflow

```
User Command (--ctf-mode --challenge-id)
    ↓
CTF Mode Enforcement (ctf_mode.py)
    ↓
Auto Solver Orchestration (auto_solver.py)
    ↓
┌─────────────┬─────────────┬─────────────┐
│   Password  │ Flag Hunter │    Stego    │
│  Cracker    │             │   Solver    │
└─────────────┴─────────────┴─────────────┘
    ↓
Results Aggregation
    ↓
Audit Log Generation (ctf_mode.py)
    ↓
Output (Report + Provenance)
```

### Watermark Removal Workflow

```
User Command (mutate watermark --remove)
    ↓
Watermark Analysis (analyze/watermark.py)
    ↓
Type Classification
    ↓
Strategy Selection
    ↓
┌────────────┬─────────────┬──────────────┐
│  Content   │     OCG     │   XObject    │
│  Stream    │   Removal   │   Removal    │
│  Editing   │             │              │
└────────────┴─────────────┴──────────────┘
    ↓
Quality Assessment
    ↓
Output (Clean PDF)
```

## Dependencies

### Core Dependencies
- **pikepdf** - PDF parsing and manipulation
- **pdfplumber** - Text extraction with layout
- **click** - CLI framework
- **rich** - Terminal UI components
- **tomli** - TOML configuration (Python <3.11)

### Optional Dependencies
- **Pillow** - Image processing
- **numpy** - Numerical operations
- **pycryptodome** - Cryptographic operations
- **ocrmypdf** - OCR functionality
- **graphviz** - Graph visualization
- **python-magic** - File type detection
- **pypdf** - Additional PDF operations

### External Tools (Optional)
- **Ghostscript** - PDF rendering, watermark operations
- **QPDF** - PDF structure manipulation, repair
- **John the Ripper** - Password cracking
- **Hashcat** - GPU-accelerated password cracking
- **Tesseract** - OCR engine
- **ImageMagick** - Advanced image processing

## Design Principles

### Separation of Concerns

Each module has a single responsibility:
- **Analyze** - Read-only analysis
- **Extract** - Data extraction
- **Mutate** - Modification
- **Solve** - Problem solving
- **Generate** - Creation

### Graceful Degradation

Missing external tools don't break core functionality:
- Detect tool availability
- Provide installation instructions
- Fall back to Python implementations
- Continue with reduced functionality

### Ethical Use Enforcement

Sensitive operations require explicit authorization:
- CTF mode enforcement (`--ctf-mode`)
- Challenge ID requirement (`--challenge-id`)
- Audit trail generation
- Signed provenance files

### Extensibility

Plugin system allows third-party extensions:
- Well-defined base classes
- Auto-discovery from multiple directories
- Lifecycle hooks for integration
- Isolated execution environments

### Performance

Optimized for large PDFs:
- Streaming parsers for large files
- Parallel processing where applicable
- Caching for expensive operations
- Memory-mapped file I/O

### Professional Quality

Production-ready code:
- >90% test coverage
- Type hints (mypy compatible)
- Comprehensive error handling
- Detailed logging
- Clear error messages with guidance

## Configuration System

### Configuration Hierarchy

1. Command-line options (highest priority)
2. Project config file (`./pdfscalpel.toml`)
3. User config file (`~/.pdfscalpel.toml`)
4. System config file (`~/.config/pdfscalpel/config.toml`)
5. Default values (lowest priority)

### Configuration Sections

```toml
[ocr]           # OCR settings
[watermark]     # Watermark defaults
[password]      # Password cracking settings
[plugins]       # Plugin directories
```

## Testing Strategy

### Unit Tests
- Test individual functions and classes
- Mock external dependencies
- High coverage (>90%)

### Integration Tests
- Test complete workflows
- Test CLI commands
- Test plugin system

### Performance Tests
- Benchmark critical paths
- Test with large PDFs
- Memory profiling

### Fixture Generation
- Auto-generate test PDFs
- Various encryption types
- Different watermark types
- Corrupted PDFs

## Error Handling

### Exception Hierarchy

```
PDFScalpelError (base)
├── PDFOpenError (cannot open file)
├── PDFEncryptedError (password required)
├── PDFCorruptedError (malformed PDF)
├── PDFNotFoundError (file not found)
├── DependencyMissingError (external tool missing)
└── ConfigurationError (invalid config)
```

### Error Messages

Provide actionable guidance:
- What went wrong
- Why it likely failed
- What to try next
- Installation instructions for missing tools

Example:
```
Error: Encrypted PDF requires password
Encryption: AES-256
Crackability: High (estimated 6-8 char password)

Try:
  1. pdfscalpel solve password INPUT --ctf-mode --challenge-id ID
  2. pdfscalpel analyze encryption INPUT --check-exploits
```

## Performance Considerations

### Optimization Techniques

1. **Lazy Loading** - Defer object dereferencing until needed
2. **Streaming** - Process large files incrementally
3. **Caching** - Cache expensive operations (graph traversal, entropy)
4. **Parallel Processing** - Use multiprocessing for page-level operations
5. **External Tools** - Delegate to optimized C tools (QPDF, Ghostscript)

### Benchmarks

Target performance (Windows 11, i7-12700K):
- Structure analysis: <3s for 1000-page PDF
- Password cracking: >50,000 passwords/sec (RC4-40)
- Object graph: <2s for 5000 objects
- Image extraction: <1s for 100 images

## Future Enhancements

### Planned Features
- GUI interface (electron/web-based)
- REST API for integration
- Distributed cracking (cluster support)
- Machine learning for malware detection
- Advanced polyglot detection
- Certificate-based encryption handling

### Research Areas
- Machine learning watermark detection
- Automated exploit generation
- PDF parser fuzzing
- Reader behavior profiling
