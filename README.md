# SEO Bot IP Collector

Automated collection and normalization of IP/CIDR ranges for SEO bots, crawlers, and monitoring services.

## Features

- **Daily automated collection** via GitHub Actions
- **Multiple data sources**: Official APIs, SPF records, static ranges
- **IP normalization**: Merging overlapping networks, deduplication
- **Multiple output formats**: CIDR and individual IPs for both IPv4/IPv6
- **Comprehensive coverage**: Google, Bing, Ahrefs, Semrush, UptimeRobot, and more

## Supported Bots & Services

### Search Engine Crawlers
- **Googlebot** - From official SPF records
- **Bingbot** - From official JSON API
- **Yahoo Slurp** - Static IP ranges
- **DuckDuckBot** - Static IP ranges
- **YandexBot** - Static IP ranges
- **Baiduspider** - Static IP ranges
- **CocCocBot** (Vietnamese) - Static IP ranges
- **Sogou Spider** (Chinese) - Static IP ranges
- **Applebot** - Static IP ranges

### SEO Tools
- **SemrushBot** - Static IP ranges
- **AhrefsBot** - Static IP ranges
- **MJ12bot (Majestic)** - Static IP ranges

### Social Media Crawlers
- **Facebookexternalhit** - Static IP ranges
- **Twitterbot** - Static IP ranges
- **LinkedInBot** - Static IP ranges

### Monitoring Services
- **UptimeRobot** - Official text files
- **Check-Host** - Static IP ranges

## Output Files

All files are generated in the `output/` directory:

### 🔥 Combined Files (Most Useful)
- `all_ranges.txt` - **All networks combined** (IPv4 + IPv6 CIDR) - 294 networks
- `all_ips.txt` - **All individual IPs combined** (IPv4 + IPv6) - 7,923 IPs

### Individual Format Files
- `ipv4_cidr.txt` - IPv4 networks in CIDR notation (181 networks)
- `ipv6_cidr.txt` - IPv6 networks in CIDR notation (113 networks)
- `ipv4_individual.txt` - Individual IPv4 addresses (7,807 IPs, small networks only)
- `ipv6_individual.txt` - Individual IPv6 addresses (116 IPs, small networks only)
- `summary.json` - Collection statistics and metadata

## Usage

### Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Run collection
python seobot_collector.py
```

### GitHub Actions - Real-time Updates

The workflow runs automatically with **frequent updates**:
- **Every 4 hours** for real-time data collection
- **Daily at 2 AM UTC** for comprehensive updates
- **On code changes** (push to master)
- **Manual trigger** available via workflow dispatch

Each run automatically:
- Collects IP ranges from all 17 configured sources
- Normalizes and deduplicates the data
- Commits changes to the repository
- Creates releases with updated IP lists

### Configuration

Bot sources are configured in `bot_sources.yaml`. Each source supports different collection methods:

- `dns_spf` - DNS SPF record resolution
- `json_api` - JSON API endpoints
- `txt_list` - Plain text IP lists
- `static_ranges` - Hardcoded IP ranges

## License

MIT License
