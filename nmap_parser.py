import xml.etree.ElementTree as ET
import pandas as pd
import sys
from pathlib import Path
import argparse
from datetime import datetime


def parse_single_nmap_file(xml_file: str) -> list:
    """
    Parse a single Nmap XML file and return parsed data.
    
    Args:
        xml_file: Path to the Nmap XML file
        
    Returns:
        List of dictionaries containing parsed port data
    """
    # Parse XML
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        raise ValueError(f"Invalid XML format in {xml_file}: {e}")
    
    # Collect data
    parsed_data = []
    
    for host in root.findall('host'):
        # Extract IP address
        address_elem = host.find('address')
        if address_elem is None:
            continue  # Skip hosts without address
        ip_address = address_elem.get('addr', 'Unknown')
        
        # Extract hostname (optional)
        hostname = 'N/A'
        hostnames_elem = host.find('hostnames')
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find('hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name', 'N/A')
        
        # Extract port information
        ports_elem = host.find('ports')
        if ports_elem is None:
            continue  # Skip hosts without ports
        
        for port in ports_elem.findall('port'):
            # Protocol and port number
            protocol = port.get('protocol', 'Unknown')
            port_number = port.get('portid', 'Unknown')
            
            # Port state
            state = 'Unknown'
            state_elem = port.find('state')
            if state_elem is not None:
                state = state_elem.get('state', 'Unknown')
            
            # Service information
            service = 'Unknown'
            details_parts = []
            
            service_elem = port.find('service')
            if service_elem is not None:
                service = service_elem.get('name', 'Unknown')
                
                # Build details from product, version, and extrainfo
                product = service_elem.get('product')
                version = service_elem.get('version')
                extrainfo = service_elem.get('extrainfo')
                
                if product:
                    details_parts.append(product)
                if version:
                    details_parts.append(f"({version})")
                if extrainfo:
                    details_parts.append(extrainfo)
            
            details = ' '.join(details_parts) if details_parts else 'Unknown'
            
            parsed_data.append({
                'IP': ip_address,
                'Hostname': hostname,
                'Port Number': port_number,
                'Protocol': protocol,
                'State': state,
                'Service': service,
                'Details': details,
                'Source File': Path(xml_file).name
            })
    
    return parsed_data


def generate_html_report(df, output_file='nmap_report.html', open_only=False):
    """
    Generate a professional HTML report for client presentations.
    
    Args:
        df: DataFrame containing parsed Nmap data
        output_file: Output HTML file path
        open_only: Whether the report includes only open ports
    """
    
    # Calculate statistics
    total_hosts = df['IP'].nunique()
    total_ports = len(df)
    open_ports = len(df[df['State'] == 'open'])
    closed_ports = len(df[df['State'] == 'closed'])
    filtered_ports = len(df[df['State'] == 'filtered'])
    unique_services = df['Service'].nunique()
    
    # Get unique IPs for dropdown
    unique_ips = sorted(df['IP'].unique())
    
    # Get top services
    top_services = df[df['State'] == 'open']['Service'].value_counts().head(5)
    
    # Get critical services (common attack vectors)
    critical_services = ['ssh', 'telnet', 'ftp', 'http', 'https', 'rdp', 'ms-wbt-server', 
                        'mysql', 'postgresql', 'mssql', 'smb', 'microsoft-ds']
    critical_ports = df[df['Service'].isin(critical_services) & (df['State'] == 'open')]
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Nmap Security Assessment Report</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                background: #f4f4f4;
            }}
            
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
            }}
            
            header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 20px;
                border-radius: 10px;
                margin-bottom: 30px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            }}
            
            header h1 {{
                font-size: 2.5em;
                margin-bottom: 10px;
            }}
            
            header p {{
                font-size: 1.1em;
                opacity: 0.9;
            }}
            
            .summary-cards {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            
            .card {{
                background: white;
                padding: 25px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
                transition: transform 0.3s ease;
            }}
            
            .card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 5px 20px rgba(0,0,0,0.15);
            }}
            
            .card h3 {{
                color: #666;
                font-size: 0.9em;
                text-transform: uppercase;
                margin-bottom: 10px;
            }}
            
            .card .number {{
                font-size: 2.5em;
                font-weight: bold;
                color: #667eea;
            }}
            
            .card.danger .number {{
                color: #e74c3c;
            }}
            
            .card.warning .number {{
                color: #f39c12;
            }}
            
            .card.success .number {{
                color: #27ae60;
            }}
            
            .section {{
                background: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            
            .section h2 {{
                color: #667eea;
                margin-bottom: 20px;
                padding-bottom: 10px;
                border-bottom: 3px solid #667eea;
            }}
            
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            
            th {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 15px;
                text-align: left;
                font-weight: 600;
                position: sticky;
                top: 0;
                z-index: 10;
            }}
            
            td {{
                padding: 12px 15px;
                border-bottom: 1px solid #e0e0e0;
            }}
            
            tbody tr:hover {{
                background-color: #f8f9fa;
            }}
            
            tbody tr:nth-child(even) {{
                background-color: #fafafa;
            }}
            
            .state {{
                padding: 5px 12px;
                border-radius: 20px;
                font-weight: 600;
                font-size: 0.85em;
                display: inline-block;
            }}
            
            .state.open {{
                background-color: #d4edda;
                color: #155724;
            }}
            
            .state.closed {{
                background-color: #f8d7da;
                color: #721c24;
            }}
            
            .state.filtered {{
                background-color: #fff3cd;
                color: #856404;
            }}
            
            .critical-badge {{
                background-color: #e74c3c;
                color: white;
                padding: 3px 8px;
                border-radius: 12px;
                font-size: 0.75em;
                margin-left: 5px;
                font-weight: bold;
            }}
            
            .service-list {{
                list-style: none;
                padding: 0;
            }}
            
            .service-list li {{
                padding: 10px;
                margin: 5px 0;
                background: #f8f9fa;
                border-left: 4px solid #667eea;
                border-radius: 4px;
            }}
            
            .service-list li strong {{
                color: #667eea;
                margin-right: 10px;
            }}
            
            footer {{
                text-align: center;
                padding: 20px;
                color: #666;
                font-size: 0.9em;
                margin-top: 30px;
            }}
            
            .filter-controls {{
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin-bottom: 20px;
                align-items: center;
            }}
            
            .filter-group {{
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            
            .filter-group label {{
                font-weight: 600;
                color: #667eea;
                min-width: 80px;
            }}
            
            .filter-btn {{
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 0.9em;
                transition: all 0.3s ease;
            }}
            
            .filter-btn.active {{
                background: #667eea;
                color: white;
            }}
            
            .filter-btn:not(.active) {{
                background: #e0e0e0;
                color: #666;
            }}
            
            .filter-btn:hover {{
                opacity: 0.8;
            }}
            
            select {{
                padding: 10px 15px;
                border: 2px solid #667eea;
                border-radius: 5px;
                font-size: 0.9em;
                cursor: pointer;
                background: white;
                color: #333;
                min-width: 200px;
            }}
            
            select:focus {{
                outline: none;
                border-color: #764ba2;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }}
            
            .search-box {{
                padding: 10px 15px;
                border: 2px solid #667eea;
                border-radius: 5px;
                font-size: 0.9em;
                min-width: 250px;
            }}
            
            .search-box:focus {{
                outline: none;
                border-color: #764ba2;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }}
            
            .clear-filters {{
                padding: 10px 20px;
                background: #e74c3c;
                color: white;
                border: none;
                border-radius: 5px;
                cursor: pointer;
                font-size: 0.9em;
                transition: all 0.3s ease;
            }}
            
            .clear-filters:hover {{
                background: #c0392b;
            }}
            
            .results-count {{
                padding: 10px 20px;
                background: #667eea;
                color: white;
                border-radius: 5px;
                font-weight: 600;
            }}
            
            @media print {{
                body {{
                    background: white;
                }}
                .filter-controls {{
                    display: none;
                }}
                .card:hover {{
                    transform: none;
                }}
            }}
            
            @media (max-width: 768px) {{
                .filter-controls {{
                    flex-direction: column;
                    align-items: stretch;
                }}
                
                .filter-group {{
                    flex-direction: column;
                    align-items: stretch;
                }}
                
                select, .search-box {{
                    min-width: 100%;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>🔒 Network Security Assessment Report</h1>
                <p>Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
                <p>{'Showing open ports only' if open_only else 'Showing all discovered ports'}</p>
            </header>
            
            <div class="summary-cards">
                <div class="card">
                    <h3>Total Hosts</h3>
                    <div class="number">{total_hosts}</div>
                </div>
                <div class="card success">
                    <h3>Open Ports</h3>
                    <div class="number">{open_ports}</div>
                </div>
                <div class="card danger">
                    <h3>Closed Ports</h3>
                    <div class="number">{closed_ports}</div>
                </div>
                <div class="card warning">
                    <h3>Filtered Ports</h3>
                    <div class="number">{filtered_ports}</div>
                </div>
                <div class="card">
                    <h3>Unique Services</h3>
                    <div class="number">{unique_services}</div>
                </div>
                <div class="card">
                    <h3>Total Ports</h3>
                    <div class="number">{total_ports}</div>
                </div>
            </div>
    """
    
    # Critical Services Section
    if len(critical_ports) > 0:
        html += """
            <div class="section">
                <h2>⚠️ Critical Services Detected</h2>
                <p>The following services are commonly targeted and should be carefully secured:</p>
                <ul class="service-list">
        """
        
        for _, row in critical_ports.iterrows():
            html += f"""
                    <li>
                        <strong>{row['IP']}</strong> - 
                        Port {row['Port Number']}/{row['Protocol']} - 
                        {row['Service']} - {row['Details']}
                    </li>
            """
        
        html += """
                </ul>
            </div>
        """
    
    # Top Services Section
    if len(top_services) > 0:
        html += """
            <div class="section">
                <h2>📊 Most Common Services</h2>
                <ul class="service-list">
        """
        
        for service, count in top_services.items():
            html += f"""
                    <li>
                        <strong>{service}</strong> - Found on {count} port(s)
                    </li>
            """
        
        html += """
                </ul>
            </div>
        """
    
    # Main Table Section with Enhanced Filters
    html += """
            <div class="section">
                <h2>📋 Detailed Port Scan Results</h2>
                
                <div class="filter-controls">
                    <div class="filter-group">
                        <label>State Filter:</label>
                        <div>
                            <button class="filter-btn active" data-state="all" onclick="filterByState(this, 'all')">All</button>
                            <button class="filter-btn" data-state="open" onclick="filterByState(this, 'open')">Open</button>
                            <button class="filter-btn" data-state="closed" onclick="filterByState(this, 'closed')">Closed</button>
                            <button class="filter-btn" data-state="filtered" onclick="filterByState(this, 'filtered')">Filtered</button>
                        </div>
                    </div>
                    
                    <div class="filter-group">
                        <label>IP Address:</label>
                        <select id="ipFilter" onchange="applyFilters()">
                            <option value="all">All IP Addresses</option>
    """
    
    # Add IP options
    for ip in unique_ips:
        ip_count = len(df[df['IP'] == ip])
        html += f'                    <option value="{ip}">{ip} ({ip_count} ports)</option>\n'
    
    html += """
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label>Search:</label>
                        <input type="text" id="searchBox" class="search-box" 
                               placeholder="Search service, port, or details..." 
                               onkeyup="applyFilters()">
                    </div>
                    
                    <button class="clear-filters" onclick="clearAllFilters()">Clear All Filters</button>
                    
                    <div class="results-count" id="resultsCount">
                        Showing {total_ports} results
                    </div>
                </div>
                
                <table id="mainTable">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Hostname</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Details</th>
    """
    
    # Add Source File column if multiple files were processed
    if 'Source File' in df.columns and df['Source File'].nunique() > 1:
        html += "<th>Source File</th>"
    
    html += """
                        </tr>
                    </thead>
                    <tbody>
    """
    
    # Add table rows
    for _, row in df.iterrows():
        state_class = row['State'].lower()
        critical_marker = ""
        if row['Service'] in critical_services and row['State'] == 'open':
            critical_marker = '<span class="critical-badge">CRITICAL</span>'
        
        html += f"""
                        <tr data-state="{state_class}" data-ip="{row['IP']}">
                            <td>{row['IP']}</td>
                            <td>{row['Hostname']}</td>
                            <td>{row['Port Number']}</td>
                            <td>{row['Protocol'].upper()}</td>
                            <td><span class="state {state_class}">{row['State'].upper()}</span></td>
                            <td>{row['Service']}{critical_marker}</td>
                            <td>{row['Details']}</td>
        """
        
        if 'Source File' in df.columns and df['Source File'].nunique() > 1:
            html += f"<td>{row['Source File']}</td>"
        
        html += """
                        </tr>
        """
    
    html += """
                    </tbody>
                </table>
            </div>
            
            <footer>
                <p>This report was automatically generated by Nmap Parser Tool</p>
                <p>For questions or concerns, please contact your security team</p>
            </footer>
        </div>
        
        <script>
            let currentStateFilter = 'all';
            
            function filterByState(button, state) {
                currentStateFilter = state;
                
                // Update button states
                const buttons = document.querySelectorAll('.filter-btn');
                buttons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                
                applyFilters();
            }
            
            function applyFilters() {
                const table = document.getElementById('mainTable');
                const tbody = table.querySelector('tbody');
                const rows = tbody.getElementsByTagName('tr');
                const ipFilter = document.getElementById('ipFilter').value;
                const searchTerm = document.getElementById('searchBox').value.toLowerCase();
                
                let visibleCount = 0;
                
                for (let i = 0; i < rows.length; i++) {
                    const row = rows[i];
                    const rowState = row.getAttribute('data-state');
                    const rowIP = row.getAttribute('data-ip');
                    const rowText = row.textContent.toLowerCase();
                    
                    let showRow = true;
                    
                    // Apply state filter
                    if (currentStateFilter !== 'all' && rowState !== currentStateFilter) {
                        showRow = false;
                    }
                    
                    // Apply IP filter
                    if (ipFilter !== 'all' && rowIP !== ipFilter) {
                        showRow = false;
                    }
                    
                    // Apply search filter
                    if (searchTerm && !rowText.includes(searchTerm)) {
                        showRow = false;
                    }
                    
                    if (showRow) {
                        row.style.display = '';
                        visibleCount++;
                    } else {
                        row.style.display = 'none';
                    }
                }
                
                // Update results count
                document.getElementById('resultsCount').textContent = 
                    'Showing ' + visibleCount + ' result' + (visibleCount !== 1 ? 's' : '');
            }
            
            function clearAllFilters() {
                // Reset state filter
                currentStateFilter = 'all';
                const buttons = document.querySelectorAll('.filter-btn');
                buttons.forEach(btn => btn.classList.remove('active'));
                buttons[0].classList.add('active');
                
                // Reset IP filter
                document.getElementById('ipFilter').value = 'all';
                
                // Reset search box
                document.getElementById('searchBox').value = '';
                
                // Reapply filters (which will show all)
                applyFilters();
            }
        </script>
    </body>
    </html>
    """
    
    # Write HTML file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)


def nmap_parser(xml_files: list, open_only: bool = False, excel_output: bool = False, 
                html_output: bool = False) -> str:
    """
    Parse Nmap XML output files and generate reports.
    
    Args:
        xml_files: List of paths to Nmap XML files
        open_only: If True, only include ports with 'open' state
        excel_output: If True, generate Excel file
        html_output: If True, generate HTML report
        
    Returns:
        Success message string
    """
    all_data = []
    
    # Process each XML file
    for xml_file in xml_files:
        # Validate file extension
        if not xml_file.lower().endswith('.xml'):
            print(f"Warning: Skipping non-XML file: {xml_file}")
            continue
        
        # Check file exists
        if not Path(xml_file).exists():
            print(f"Warning: File not found: {xml_file}")
            continue
        
        print(f"Processing: {xml_file}")
        
        try:
            file_data = parse_single_nmap_file(xml_file)
            all_data.extend(file_data)
        except Exception as e:
            print(f"Error parsing {xml_file}: {e}")
            continue
    
    # Check if we have any data
    if not all_data:
        raise ValueError("No valid data found in any of the provided XML files")
    
    # Create DataFrame
    df = pd.DataFrame(all_data)
    
    # Filter for open ports only if requested
    if open_only:
        df = df[df['State'] == 'open']
        if len(df) == 0:
            raise ValueError("No open ports found in the scan results")
    
    # Generate outputs
    outputs = []
    
    # CSV output (always generated)
    csv_file = 'nmap_parser_output.csv'
    df.to_csv(csv_file, index=False, encoding='utf-8')
    outputs.append(csv_file)
    
    # Excel output
    if excel_output:
        excel_file = 'nmap_parser_output.xlsx'
        df.to_excel(excel_file, index=False, engine='openpyxl')
        outputs.append(excel_file)
    
    # HTML output
    if html_output:
        html_file = 'nmap_report.html'
        generate_html_report(df, html_file, open_only)
        outputs.append(html_file)
    
    # Print summary statistics
    print(f"\n{'='*60}")
    print(f"NMAP SCAN SUMMARY")
    print(f"{'='*60}")
    print(f"  Files processed: {len(xml_files)}")
    print(f"  Total hosts scanned: {df['IP'].nunique()}")
    print(f"  Total ports found: {len(all_data)}")
    print(f"  Open ports: {len([d for d in all_data if d['State'] == 'open'])}")
    print(f"  Closed ports: {len([d for d in all_data if d['State'] == 'closed'])}")
    print(f"  Filtered ports: {len([d for d in all_data if d['State'] == 'filtered'])}")
    print(f"  Unique services: {df['Service'].nunique()}")
    print(f"{'='*60}\n")
    
    # Return success message
    filter_msg = " (open ports only)" if open_only else ""
    output_msg = ", ".join(outputs)
    return f"Reports created successfully: {output_msg}{filter_msg} ({len(df)} entries)"


def main():
    parser = argparse.ArgumentParser(
        description='Parse Nmap XML reports and generate CSV/Excel/HTML output',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single file
  python nmap_parser.py scan.xml
  
  # Multiple files
  python nmap_parser.py scan1.xml scan2.xml scan3.xml
  
  # With wildcard
  python nmap_parser.py scans/*.xml
  
  # Generate all report types
  python nmap_parser.py scan.xml --excel --html
  
  # Client-ready report (open ports only, HTML)
  python nmap_parser.py scan*.xml --open-only --html
        """
    )
    
    parser.add_argument('xml_files', nargs='+', help='Path(s) to Nmap XML file(s)')
    parser.add_argument('--open-only', '-o', action='store_true',
                       help='Only include open ports in the report')
    parser.add_argument('--excel', '-x', action='store_true',
                       help='Generate Excel (.xlsx) output')
    parser.add_argument('--html', '-w', action='store_true',
                       help='Generate HTML report (ideal for clients)')
    
    args = parser.parse_args()
    
    try:
        result = nmap_parser(args.xml_files, args.open_only, args.excel, args.html)
        print(result)
    except (ValueError, FileNotFoundError) as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
