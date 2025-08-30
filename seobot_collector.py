#!/usr/bin/env python3
"""
SEO Bot IP Collector
Collects and normalizes IP ranges for various SEO bots and crawlers
"""

import os
import re
import json
import socket
import requests
import yaml
from netaddr import IPNetwork, IPAddress, cidr_merge
import subprocess
from typing import List, Dict, Set, Union
from datetime import datetime

class SEOBotCollector:
    def __init__(self, config_file: str = "bot_sources.yaml"):
        with open(config_file, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.ipv4_networks = set()
        self.ipv6_networks = set()
        
    def log(self, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")
    
    def resolve_spf_record(self, domain: str) -> List[str]:
        """Resolve SPF record and extract IP ranges"""
        try:
            result = subprocess.run(['dig', '+short', 'TXT', domain], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                self.log(f"Failed to resolve SPF for {domain}")
                return []
            
            ip_ranges = []
            for line in result.stdout.strip().split('\n'):
                if 'v=spf1' in line or 'ip4:' in line or 'ip6:' in line:
                    # Extract IP ranges from SPF record
                    ip4_matches = re.findall(r'ip4:([0-9./]+)', line)
                    ip6_matches = re.findall(r'ip6:([0-9a-f:./]+)', line)
                    ip_ranges.extend(ip4_matches + ip6_matches)
                    
                    # Handle include mechanisms
                    includes = re.findall(r'include:([^\s]+)', line)
                    for include in includes:
                        ip_ranges.extend(self.resolve_spf_record(include))
            
            return ip_ranges
        except Exception as e:
            self.log(f"Error resolving SPF for {domain}: {e}")
            return []
    
    def fetch_json_ranges(self, url: str) -> List[str]:
        """Fetch IP ranges from JSON API"""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            ranges = []
            if isinstance(data, dict):
                if 'prefixes' in data:
                    for prefix in data['prefixes']:
                        # Google format
                        if 'ipv4Prefix' in prefix:
                            ranges.append(prefix['ipv4Prefix'])
                        if 'ipv6Prefix' in prefix:
                            ranges.append(prefix['ipv6Prefix'])
                        # AWS/Other formats
                        if 'ip_prefix' in prefix:
                            ranges.append(prefix['ip_prefix'])
                        if 'ipv6_prefix' in prefix:
                            ranges.append(prefix['ipv6_prefix'])
                elif 'prefixes' in data and isinstance(data['prefixes'], list):
                    # Handle alternative formats
                    for prefix in data['prefixes']:
                        if isinstance(prefix, str):
                            ranges.append(prefix)
                        elif isinstance(prefix, dict):
                            for key, value in prefix.items():
                                if 'prefix' in key.lower() and isinstance(value, str):
                                    ranges.append(value)
                elif 'ips' in data:
                    ranges.extend(data['ips'])
                elif 'ranges' in data:
                    ranges.extend(data['ranges'])
            elif isinstance(data, list):
                ranges.extend(data)
            
            return ranges
        except Exception as e:
            self.log(f"Error fetching JSON from {url}: {e}")
            return []
    
    def fetch_txt_list(self, url: str) -> List[str]:
        """Fetch IP ranges from text file"""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            ranges = []
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    ranges.append(line)
            
            return ranges
        except Exception as e:
            self.log(f"Error fetching text list from {url}: {e}")
            return []
    
    def normalize_ip_range(self, ip_range: str) -> Union[IPNetwork, None]:
        """Normalize IP range to IPNetwork object"""
        try:
            # Remove quotes and whitespace
            ip_range = ip_range.strip().strip('"')
            
            # Handle single IPs
            if '/' not in ip_range:
                try:
                    ip = IPAddress(ip_range)
                    if ip.version == 4:
                        return IPNetwork(f"{ip}/32")
                    else:
                        return IPNetwork(f"{ip}/128")
                except:
                    return None
            
            # Handle CIDR notation
            return IPNetwork(ip_range)
        except Exception as e:
            self.log(f"Invalid IP range: {ip_range} - {e}")
            return None
    
    def collect_source(self, source_name: str, source_config: Dict):
        """Collect IP ranges from a single source"""
        self.log(f"Collecting from {source_config['name']}")
        
        ranges = []
        method = source_config['method']
        
        try:
            if method == 'multiple_json_api':
                # Handle multiple JSON APIs (like Google's 4 sources)
                if 'official_json_urls' in source_config:
                    for url in source_config['official_json_urls']:
                        try:
                            json_ranges = self.fetch_json_ranges(url)
                            ranges.extend(json_ranges)
                            self.log(f"  - Fetched {len(json_ranges)} ranges from {url.split('/')[-1]}")
                        except Exception as e:
                            self.log(f"  - Failed to fetch from {url}: {e}")
                
                # Fallback to SPF if needed
                if not ranges and 'backup_spf' in source_config:
                    self.log(f"  - Using backup SPF: {source_config['backup_spf']}")
                    ranges.extend(self.resolve_spf_record(source_config['backup_spf']))
            
            elif method == 'dns_spf':
                if 'official_spf' in source_config:
                    ranges.extend(self.resolve_spf_record(source_config['official_spf']))
                if 'official_txt' in source_config:
                    ranges.extend(self.resolve_spf_record(source_config['official_txt']))
            
            elif method == 'json_api':
                if 'official_json' in source_config:
                    ranges.extend(self.fetch_json_ranges(source_config['official_json']))
            
            elif method == 'txt_list':
                if 'official_txt' in source_config:
                    ranges.extend(self.fetch_txt_list(source_config['official_txt']))
                if 'official_txt_v6' in source_config:
                    ranges.extend(self.fetch_txt_list(source_config['official_txt_v6']))
            
            elif method == 'static_ranges':
                ranges.extend(source_config.get('ranges', []))
            
            # Normalize and categorize ranges
            for range_str in ranges:
                network = self.normalize_ip_range(range_str)
                if network:
                    if network.version == 4:
                        self.ipv4_networks.add(network)
                    else:
                        self.ipv6_networks.add(network)
            
            self.log(f"Collected {len(ranges)} ranges from {source_config['name']}")
        
        except Exception as e:
            self.log(f"Error collecting from {source_config['name']}: {e}")
    
    def collect_all(self):
        """Collect from all configured sources"""
        self.log("Starting IP collection for all sources")
        
        for source_name, source_config in self.config['sources'].items():
            self.collect_source(source_name, source_config)
        
        self.log(f"Total collected: {len(self.ipv4_networks)} IPv4, {len(self.ipv6_networks)} IPv6 networks")
    
    def merge_and_deduplicate(self):
        """Merge overlapping networks and deduplicate"""
        self.log("Merging and deduplicating networks")
        
        # Convert to list and merge
        ipv4_list = list(self.ipv4_networks)
        ipv6_list = list(self.ipv6_networks)
        
        merged_ipv4 = cidr_merge(ipv4_list)
        merged_ipv6 = cidr_merge(ipv6_list)
        
        self.ipv4_networks = set(merged_ipv4)
        self.ipv6_networks = set(merged_ipv6)
        
        self.log(f"After merging: {len(self.ipv4_networks)} IPv4, {len(self.ipv6_networks)} IPv6 networks")
    
    def generate_individual_ips(self, networks: Set[IPNetwork]) -> List[str]:
        """Generate individual IP addresses from networks (for small networks only)"""
        individual_ips = []
        
        for network in networks:
            # Only expand small networks to avoid huge files
            if network.version == 4 and network.prefixlen >= 24:  # /24 or smaller
                for ip in network:
                    individual_ips.append(str(ip))
            elif network.version == 6 and network.prefixlen >= 120:  # /120 or smaller
                for ip in network:
                    individual_ips.append(str(ip))
        
        return sorted(individual_ips)
    
    def write_output_files(self):
        """Write output files in different formats"""
        os.makedirs('output', exist_ok=True)
        
        # IPv4 CIDR format
        ipv4_cidrs = sorted([str(net) for net in self.ipv4_networks])
        with open('output/ipv4_cidr.txt', 'w') as f:
            f.write('\n'.join(ipv4_cidrs) + '\n')
        
        # IPv6 CIDR format  
        ipv6_cidrs = sorted([str(net) for net in self.ipv6_networks])
        with open('output/ipv6_cidr.txt', 'w') as f:
            f.write('\n'.join(ipv6_cidrs) + '\n')
        
        # All ranges combined (IPv4 + IPv6 CIDR)
        all_ranges = sorted(ipv4_cidrs + ipv6_cidrs)
        with open('output/all_ranges.txt', 'w') as f:
            f.write('\n'.join(all_ranges) + '\n')
        
        # IPv4 individual IPs (for small networks only)
        ipv4_ips = self.generate_individual_ips(self.ipv4_networks)
        with open('output/ipv4_individual.txt', 'w') as f:
            f.write('\n'.join(ipv4_ips) + '\n')
        
        # IPv6 individual IPs (for small networks only)
        ipv6_ips = self.generate_individual_ips(self.ipv6_networks)
        with open('output/ipv6_individual.txt', 'w') as f:
            f.write('\n'.join(ipv6_ips) + '\n')
        
        # All IPs combined (IPv4 + IPv6 individual)
        all_ips = sorted(ipv4_ips + ipv6_ips, key=lambda x: IPAddress(x))
        with open('output/all_ips.txt', 'w') as f:
            f.write('\n'.join(all_ips) + '\n')
        
        # Summary
        summary = {
            'updated': datetime.now().isoformat(),
            'total_ipv4_networks': len(self.ipv4_networks),
            'total_ipv6_networks': len(self.ipv6_networks),
            'total_networks': len(self.ipv4_networks) + len(self.ipv6_networks),
            'total_ipv4_individual': len(ipv4_ips),
            'total_ipv6_individual': len(ipv6_ips),
            'total_individual_ips': len(ipv4_ips) + len(ipv6_ips),
            'sources': list(self.config['sources'].keys())
        }
        
        with open('output/summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.log(f"Output written to files:")
        self.log(f"  - IPv4 CIDR: {len(ipv4_cidrs)} networks")
        self.log(f"  - IPv6 CIDR: {len(ipv6_cidrs)} networks")
        self.log(f"  - All Ranges: {len(all_ranges)} total networks")
        self.log(f"  - IPv4 Individual: {len(ipv4_ips)} IPs")
        self.log(f"  - IPv6 Individual: {len(ipv6_ips)} IPs")
        self.log(f"  - All IPs: {len(all_ips)} total IPs")

def main():
    collector = SEOBotCollector()
    collector.collect_all()
    collector.merge_and_deduplicate()
    collector.write_output_files()
    print("Collection completed successfully!")

if __name__ == "__main__":
    main()