#!/usr/bin/env python3
"""
Flag Finder - CTF Tool for finding flags in website source code
Searches for flags matching the pattern: USU{...}
"""

import re
import argparse
import os
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import sys

class FlagFinder:
    def __init__(self, verbose=False, crawl=False, max_depth=3):
        self.flag_pattern = re.compile(r'USU\{[^}]+\}')
        self.found_flags = set()
        self.verbose = verbose
        self.crawl = crawl
        self.max_depth = max_depth
        self.visited_urls = set()
        self.base_domain = None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def log(self, message):
        """Print message if verbose mode is enabled"""
        if self.verbose:
            print(f"[*] {message}")

    def find_flags_in_text(self, text, source):
        """Search for flags in text content"""
        matches = self.flag_pattern.findall(text)
        if matches:
            for flag in matches:
                if flag not in self.found_flags:
                    self.found_flags.add(flag)
                    print(f"\n[+] FLAG FOUND: {flag}")
                    print(f"    Source: {source}")

    def scan_file(self, filepath):
        """Scan a local file for flags"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                self.log(f"Scanning file: {filepath}")
                self.find_flags_in_text(content, filepath)
        except Exception as e:
            print(f"[-] Error reading {filepath}: {e}")

    def scan_directory(self, directory, extensions=None):
        """Recursively scan directory for files with specific extensions"""
        if extensions is None:
            extensions = ['.html', '.htm', '.js', '.css', '.php', '.txt', '.json', '.xml']
        
        self.log(f"Scanning directory: {directory}")
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    filepath = os.path.join(root, file)
                    self.scan_file(filepath)

    def fetch_url_content(self, url):
        """Fetch content from a URL"""
        try:
            self.log(f"Fetching: {url}")
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"[-] Error fetching {url}: {e}")
            return None

    def scan_url(self, url):
        """Scan a URL and its linked resources"""
        self.log(f"Scanning URL: {url}")
        
        # Fetch main page
        html_content = self.fetch_url_content(url)
        if not html_content:
            return
        
        # Check main HTML for flags
        self.find_flags_in_text(html_content, f"{url} (HTML)")
        
        # Parse HTML to find linked resources
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Find all script tags
        scripts = soup.find_all('script')
        for script in scripts:
            if script.get('src'):
                script_url = urljoin(url, script['src'])
                script_content = self.fetch_url_content(script_url)
                if script_content:
                    self.find_flags_in_text(script_content, f"{script_url} (JavaScript)")
            elif script.string:
                self.find_flags_in_text(script.string, f"{url} (Inline JavaScript)")
        
        # Find all CSS links
        links = soup.find_all('link', rel='stylesheet')
        for link in links:
            if link.get('href'):
                css_url = urljoin(url, link['href'])
                css_content = self.fetch_url_content(css_url)
                if css_content:
                    self.find_flags_in_text(css_content, f"{css_url} (CSS)")
        
        # Check inline styles
        styles = soup.find_all('style')
        for style in styles:
            if style.string:
                self.find_flags_in_text(style.string, f"{url} (Inline CSS)")
        
        # Check HTML comments
        comments = soup.find_all(string=lambda text: isinstance(text, str))
        for comment in comments:
            self.find_flags_in_text(str(comment), f"{url} (HTML Content)")

    def print_summary(self):
        """Print summary of found flags"""
        print("\n" + "="*60)
        if self.found_flags:
            print(f"[+] Total flags found: {len(self.found_flags)}")
            print("\nAll flags:")
            for flag in sorted(self.found_flags):
                print(f"  {flag}")
        else:
            print("[-] No flags found")
        print("="*60)


def main():
    parser = argparse.ArgumentParser(
        description='Find CTF flags (USU{...}) in website source code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a website
  python flag_finder.py -u https://example.com

  # Scan local files
  python flag_finder.py -f index.html
  python flag_finder.py -f script.js style.css

  # Scan directory
  python flag_finder.py -d ./website

  # Verbose mode
  python flag_finder.py -u https://example.com -v
        """
    )
    
    parser.add_argument('-u', '--url', help='URL to scan')
    parser.add_argument('-f', '--files', nargs='+', help='Files to scan')
    parser.add_argument('-d', '--directory', help='Directory to scan recursively')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not (args.url or args.files or args.directory):
        parser.print_help()
        sys.exit(1)
    
    finder = FlagFinder(verbose=args.verbose)
    
    print("[*] Starting flag search...")
    print(f"[*] Looking for pattern: USU{{...}}\n")
    
    if args.url:
        finder.scan_url(args.url)
    
    if args.files:
        for file in args.files:
            finder.scan_file(file)
    
    if args.directory:
        finder.scan_directory(args.directory)
    
    finder.print_summary()


if __name__ == '__main__':
    main()
