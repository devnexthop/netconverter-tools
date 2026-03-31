# NetConverter Tools

Open-source CLI tools for working with [NetConverter.AI](https://netconverter.ai) — the multi-vendor network configuration translation engine.

These scripts help you import, export, and manage converted configurations across firewall management platforms.

## Available Tools

| Tool | Description | Status |
|------|-------------|--------|
| [FMC Import](fmc-import/) | Push NetConverter FMC JSON output to a Cisco Secure Firewall Management Center via REST API | Stable |

## Quick Start

```bash
# Clone the repo
git clone https://github.com/netconverter-ai/netconverter-tools.git
cd netconverter-tools

# Install dependencies
pip install requests

# Run the FMC import tool
python3 fmc-import/fmc_import.py --host 10.1.1.100 --user admin --json converted_output.json
```

## How It Works

1. **Convert** your firewall config using [NetConverter.AI](https://netconverter.ai) (Quick Convert or API)
2. **Download** the converted output (FMC JSON, Panorama XML, etc.)
3. **Import** using the appropriate tool from this repo

## Requirements

- Python 3.8+
- `requests` library (`pip install requests`)
- Network access to your target management platform

## Contributing

Found a bug or have a feature request? Open an issue or submit a PR.

## License

MIT License - see [LICENSE](LICENSE) for details.
