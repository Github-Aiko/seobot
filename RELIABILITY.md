# Data Source Reliability Assessment

## High Reliability Sources (90-100%)

### ✅ Official APIs & DNS Records
- **Googlebot**: Official SPF records from `_spf.google.com` - Real-time DNS lookup
- **UptimeRobot**: Official IP list from `https://uptimerobot.com/inc/files/ips/` - Updated by provider

## Medium Reliability Sources (70-89%)

### ⚠️ Semi-Official Sources
- **Social Media Crawlers** (Facebook, Twitter, LinkedIn): Based on published ASN ranges and documentation
- **Major Search Engines** (Yahoo, Yandex): ASN-based ranges from network registries

## Lower Reliability Sources (50-69%) 

### 🟡 Static Community-Sourced Ranges
- **SEO Tools** (Ahrefs, Semrush, MJ12): Based on reverse DNS and community reports
- **Asian Search Engines** (Baidu, CocCoc, Sogou): Limited official documentation
- **DuckDuckBot**: Limited public information available

## Known Issues & Limitations

### 🔴 Current Problems
1. **Bingbot API**: `https://www.bing.com/toolbox/bingbot.json` not responding
2. **Applebot Range**: `17.0.0.0/8` too broad (entire Apple infrastructure)
3. **Static Ranges**: May become outdated without notification
4. **CocCoc**: Vietnamese search engine data needs official verification

## Recommended Improvements

### Priority 1: Add Official Sources
- [ ] Find official Bingbot IP source (Microsoft documentation)
- [ ] Verify CocCoc official crawler documentation
- [ ] Add official Yandex webmaster tools API
- [ ] Narrow Applebot range to actual crawler IPs

### Priority 2: Add Validation
- [ ] Cross-reference with multiple sources
- [ ] Add reverse DNS validation
- [ ] Monitor for range changes
- [ ] Flag suspicious or overly broad ranges

### Priority 3: Documentation
- [ ] Add source URLs and last verified dates
- [ ] Mark confidence levels in output
- [ ] Provide alternative sources for comparison

## Usage Recommendations

1. **High-stakes applications**: Use only high reliability sources
2. **Testing environments**: Full dataset acceptable
3. **Regular validation**: Monitor for false positives/negatives
4. **Backup verification**: Manual spot-checks recommended

## Community Contributions

Users should verify ranges in their specific use cases and report:
- False positives (legitimate traffic blocked)
- False negatives (bots not identified)  
- Updated official sources
- Regional variations

Last Updated: 2025-08-31