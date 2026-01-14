# dnsviz-tui

A TUI (Text User Interface) application for visualizing DNSSEC chain of trust, inspired by [dnsviz.net](https://dnsviz.net).

## Features

- **Three Visualization Modes**:
  - **Tree View**: Hierarchical display of the trust chain with expandable zones
  - **Diagram View**: ASCII box diagram showing zone relationships and DS→DNSKEY flows
  - **Table View**: Detailed tables of all DNSSEC records

- **Full DNSSEC Validation**:
  - Validates chain from root trust anchor to target domain
  - Shows DNSKEY, DS, RRSIG, NSEC/NSEC3 records
  - Color-coded status: Green (SECURE), Yellow (INSECURE), Red (BOGUS)

- **Additional Features**:
  - Query additional records (SPF, DMARC, MX, A, AAAA)
  - Export results to JSON and plain text
  - Configure custom DNS resolvers
  - Session query history

## Installation

### Using Docker (Recommended)

```bash
# Build the image
docker build -t dnsviz-tui .

# Run interactively
docker run -it --rm -v ./exports:/app/exports dnsviz-tui
```

### Using Docker Compose

```bash
docker compose run --rm dnsviz-tui
```

### From Source

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package
pip install -e .

# Run
python -m dnsviz_tui
```

## Usage

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Enter` | Query the entered domain |
| `1` | Switch to Tree View |
| `2` | Switch to Diagram View |
| `3` | Switch to Table View |
| `e` | Export results |
| `r` | Configure DNS resolver |
| `h` | Toggle history panel |
| `/` | Focus domain input |
| `q` | Quit |

### Example Domains to Test

- `cloudflare.com` - DNSSEC enabled
- `google.com` - DNSSEC enabled
- `example.com` - Basic domain
- `dnssec-failed.org` - Intentionally broken DNSSEC (for testing BOGUS status)

## Validation Status Colors

- **Green (SECURE)**: Complete chain of trust validated from root
- **Yellow (INSECURE)**: No DNSSEC configured (unsigned delegation)
- **Red (BOGUS)**: DNSSEC validation failed (broken chain)
- **Orange (INDETERMINATE)**: Could not determine validation status

## Export Formats

### JSON Export
Structured data including all zones, records, and validation details.

### Text Export
Human-readable report with summary tables.

Exports are saved to the `exports/` directory with timestamp-based filenames.

## Architecture

```
src/dnsviz_tui/
├── app.py              # Main Textual application
├── dns/
│   ├── resolver.py     # DNS query handling
│   ├── dnssec.py       # DNSSEC chain validation
│   └── records.py      # Record type parsing
├── models/
│   └── chain.py        # Trust chain data models
├── views/
│   ├── tree_view.py    # Tree visualization
│   ├── diagram_view.py # ASCII diagram visualization
│   └── table_view.py   # Table visualization
├── widgets/
│   ├── domain_input.py # Domain entry widget
│   ├── history_panel.py# Query history
│   └── status_bar.py   # Status bar
└── export/
    ├── json_export.py  # JSON export
    └── text_export.py  # Text export
```

## Dependencies

- [Textual](https://textual.textualize.io/) - TUI framework
- [dnspython](https://www.dnspython.org/) - DNS queries and DNSSEC
- [Rich](https://rich.readthedocs.io/) - Terminal formatting

## License

MIT
