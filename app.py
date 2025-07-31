from flask import Flask, render_template, request
import sys
import re
import os
import glob
import json

app = Flask(__name__)

def print_usage():
    """Print usage information"""
    print("\nUsage: python3 app.py <log_file_or_directory>")
    print("\nSupported file formats:")
    print("  - .txt files (structured text logs)")
    print("  - .json files (JSON structured logs)")
    print("  - .tsv files (Snaffler TSV output)")
    print("\nExamples:")
    print("  python3 app.py snaffler_output.tsv")
    print("  python3 app.py /path/to/logs/directory/")
    print("  python3 app.py security_findings.txt")
    print("\nThe web interface will be available at: http://localhost:5000")
    print()

def validate_arguments():
    """Validate command line arguments"""
    if len(sys.argv) != 2:
        print("❌ Error: Invalid number of arguments")
        if len(sys.argv) < 2:
            print("   No log file or directory specified")
        else:
            print(f"   Too many arguments provided: {len(sys.argv) - 1}")
        print_usage()
        sys.exit(1)
    
    log_input = sys.argv[1]
    
    # Check for help flags
    if log_input in ['-h', '--help', 'help']:
        print_usage()
        sys.exit(0)
    
    return log_input

def validate_path(log_input):
    """Validate that the provided path exists and is accessible"""
    if not os.path.exists(log_input):
        print(f"❌ Error: Path does not exist: '{log_input}'")
        print("   Please check the file or directory path and try again.")
        sys.exit(1)
    
    if not os.access(log_input, os.R_OK):
        print(f"❌ Error: Permission denied accessing: '{log_input}'")
        print("   Please check file permissions and try again.")
        sys.exit(1)
    
    return True

def find_supported_files(log_input):
    """Find and validate supported log files"""
    supported_extensions = ['.txt', '.json', '.tsv']
    log_files = []
    
    if os.path.isdir(log_input):
        print(f"📁 Scanning directory: {log_input}")
        
        # Collect all supported files
        for ext in supported_extensions:
            pattern = os.path.join(log_input, f'*{ext}')
            files = glob.glob(pattern)
            log_files.extend(files)
        
        if not log_files:
            print(f"❌ Error: No supported log files found in directory: '{log_input}'")
            print(f"   Supported file types: {', '.join(supported_extensions)}")
            sys.exit(1)
        
        print(f"✅ Found {len(log_files)} supported files:")
        for file in sorted(log_files):
            print(f"   - {os.path.basename(file)}")
            
    elif os.path.isfile(log_input):
        # Check if single file has supported extension
        _, ext = os.path.splitext(log_input.lower())
        if ext not in supported_extensions:
            print(f"❌ Error: Unsupported file type: '{ext}'")
            print(f"   Supported file types: {', '.join(supported_extensions)}")
            sys.exit(1)
        
        log_files = [log_input]
        print(f"📄 Processing single file: {os.path.basename(log_input)}")
    
    return log_files

def parse_line(line, filename):
    result = {}

    # Extract Severity inside {}
    severity_match = re.search(r'\{([^}]+)\}', line)
    result['Severity'] = severity_match.group(1) if severity_match else 'N/A'

    # Extract content inside <>
    angle_brackets_match = re.search(r'<([^>]+)>', line)
    if angle_brackets_match:
        angle_content = angle_brackets_match.group(1)
        angle_parts = angle_content.split('|')
        result['RuleName'] = angle_parts[0] if len(angle_parts) > 0 else 'N/A'
        result['DateModified'] = angle_parts[-1] if len(angle_parts) > 4 else 'N/A'
    else:
        result['RuleName'] = 'N/A'
        result['DateModified'] = 'N/A'

    # Extract Full Path inside ()
    fullpath_match = re.search(r'\(([^)]+)\)', line)
    result['FullPath'] = fullpath_match.group(1) if fullpath_match else 'N/A'

    # Extract additional data after the FullPath
    after_fullpath = line.split(')', 1)
    result['AdditionalData'] = after_fullpath[1].strip() if len(after_fullpath) > 1 else 'N/A'

    # Add Filename
    result['Filename'] = filename

    return result

def parse_json_entry(entry, filename):
    result = {}

    # Extract Severity from 'level' or 'eventProperties'
    level = entry.get('level', 'N/A')
    event_properties = entry.get('eventProperties', {})
    # Possible severity keys in eventProperties are 'Red', 'Green', 'Yellow', 'Black'
    severity_keys = ['Red', 'Green', 'Yellow', 'Black']
    severity = 'N/A'
    for key in severity_keys:
        if key in event_properties:
            severity = key
            break
    result['Severity'] = severity if severity != 'N/A' else level

    # Extract 'message'
    message = entry.get('message', '')

    # Use similar parsing as for text lines
    # Extract RuleName and DateModified inside <>
    angle_brackets_match = re.search(r'<([^>]+)>', message)
    if angle_brackets_match:
        angle_content = angle_brackets_match.group(1)
        angle_parts = angle_content.split('|')
        result['RuleName'] = angle_parts[0] if len(angle_parts) > 0 else 'N/A'
        result['DateModified'] = angle_parts[-1] if len(angle_parts) > 4 else 'N/A'
    else:
        result['RuleName'] = 'N/A'
        result['DateModified'] = 'N/A'

    # Extract Full Path inside ()
    fullpath_match = re.search(r'\(([^)]+)\)', message)
    result['FullPath'] = fullpath_match.group(1) if fullpath_match else 'N/A'

    # Extract AdditionalData
    after_fullpath = message.split(')', 1)
    result['AdditionalData'] = after_fullpath[1].strip() if len(after_fullpath) > 1 else 'N/A'

    # Add Filename
    result['Filename'] = filename

    return result

def parse_snaffler_tsv_line(line, filename):
    result = {}
    
    # Split the line by tabs
    fields = line.strip().split('\t')
    
    # Skip lines that don't have enough fields or aren't file findings
    if len(fields) < 10 or '[File]' not in line:
        return None
    
    # Extract fields based on Snaffler TSV format
    try:
        result['UserHost'] = fields[0] if len(fields) > 0 else 'N/A'
        result['Timestamp'] = fields[1] if len(fields) > 1 else 'N/A'
        result['LogType'] = fields[2] if len(fields) > 2 else 'N/A'
        result['Severity'] = fields[3] if len(fields) > 3 else 'N/A'
        result['RuleName'] = fields[4] if len(fields) > 4 else 'N/A'
        result['AccessLevel'] = fields[5] if len(fields) > 5 else 'N/A'
        result['MatchPattern'] = fields[8] if len(fields) > 8 else 'N/A'
        result['FileSize'] = fields[9] if len(fields) > 9 else 'N/A'
        result['DateModified'] = fields[10] if len(fields) > 10 else 'N/A'
        result['FullPath'] = fields[11] if len(fields) > 11 else 'N/A'
        result['AdditionalData'] = fields[12] if len(fields) > 12 else 'N/A'
        result['Filename'] = filename
        
        return result
    except IndexError:
        return None

def deduplicate_findings(data):
    """Remove duplicate findings based on FullPath, RuleName, and Severity"""
    seen = set()
    deduplicated = []
    duplicates_removed = 0
    
    for finding in data:
        # Create a unique key based on critical fields
        key = (
            finding.get('FullPath', ''),
            finding.get('RuleName', ''),
            finding.get('Severity', '')
        )
        
        if key not in seen:
            seen.add(key)
            deduplicated.append(finding)
        else:
            duplicates_removed += 1
    
    if duplicates_removed > 0:
        print(f"   🔄 Removed {duplicates_removed} duplicate findings")
    
    return deduplicated

def process_snaffler_data():
    """Process Snaffler data files and return processed data"""
    # Validate arguments and paths
    log_input = validate_arguments()
    validate_path(log_input)
    log_files = find_supported_files(log_input)
    
    data = []
    severity_options = set()
    rule_options = set()
    processing_errors = []

    print(f"🔄 Processing files...")
    
    for logfile in log_files:
        filename = os.path.basename(logfile)
        
        try:
            if logfile.endswith('.txt'):
                with open(logfile, 'r', encoding='latin-1') as f:
                    line_count = 0
                    parsed_count = 0
                    for line in f:
                        line_count += 1
                        if '[File]' in line:
                            parsed = parse_line(line, filename)
                            if parsed:
                                data.append(parsed)
                                severity_options.add(parsed['Severity'])
                                rule_options.add(parsed['RuleName'])
                                parsed_count += 1
                    print(f"   ✅ {filename}: {parsed_count} findings from {line_count} lines")
                    
            elif logfile.endswith('.json'):
                with open(logfile, 'r', encoding='utf-8') as f:
                    try:
                        json_data = json.load(f)
                        entries = json_data.get('entries', [])
                        parsed_count = 0
                        for entry in entries:
                            # Consider only entries with level 'Warn' and messages containing '[File]'
                            if entry.get('level') in ['Warn', 'Error'] and '[File]' in entry.get('message', ''):
                                parsed = parse_json_entry(entry, filename)
                                if parsed:
                                    data.append(parsed)
                                    severity_options.add(parsed['Severity'])
                                    rule_options.add(parsed['RuleName'])
                                    parsed_count += 1
                        print(f"   ✅ {filename}: {parsed_count} findings from {len(entries)} entries")
                    except json.JSONDecodeError as e:
                        error_msg = f"Invalid JSON format in {filename}: {str(e)}"
                        print(f"   ❌ {error_msg}")
                        processing_errors.append(error_msg)
                        continue
                        
            elif logfile.endswith('.tsv'):
                with open(logfile, 'r', encoding='utf-8') as f:
                    line_count = 0
                    parsed_count = 0
                    for line in f:
                        line_count += 1
                        parsed = parse_snaffler_tsv_line(line, filename)
                        if parsed:
                            data.append(parsed)
                            severity_options.add(parsed['Severity'])
                            rule_options.add(parsed['RuleName'])
                            parsed_count += 1
                    print(f"   ✅ {filename}: {parsed_count} findings from {line_count} lines")
            
        except FileNotFoundError:
            error_msg = f"File not found: {filename}"
            print(f"   ❌ {error_msg}")
            processing_errors.append(error_msg)
            continue
        except PermissionError:
            error_msg = f"Permission denied reading file: {filename}"
            print(f"   ❌ {error_msg}")
            processing_errors.append(error_msg)
            continue
        except UnicodeDecodeError as e:
            error_msg = f"Encoding error in {filename}: {str(e)}"
            print(f"   ❌ {error_msg}")
            processing_errors.append(error_msg)
            continue
        except Exception as e:
            error_msg = f"Unexpected error processing {filename}: {str(e)}"
            print(f"   ❌ {error_msg}")
            processing_errors.append(error_msg)
            continue

    # Deduplicate findings if processing multiple files
    original_count = len(data)
    if len(log_files) > 1:
        print(f"\n🔄 Deduplicating findings across {len(log_files)} files...")
        data = deduplicate_findings(data)
    
    # Print processing summary
    total_findings = len(data)
    print(f"\n📊 Processing Summary:")
    print(f"   Total files processed: {len(log_files)}")
    if len(log_files) > 1:
        print(f"   Raw findings extracted: {original_count}")
        print(f"   Unique findings after deduplication: {total_findings}")
    else:
        print(f"   Total findings extracted: {total_findings}")
    
    if processing_errors:
        print(f"   ⚠️  Files with errors: {len(processing_errors)}")
        for error in processing_errors:
            print(f"      - {error}")
    
    if total_findings == 0:
        print("   ⚠️  No findings were extracted from the processed files.")
        print("      This could mean:")
        print("      - Files don't contain [File] entries")
        print("      - Files are in an unexpected format")
        print("      - Files are empty or corrupted")
    
    print(f"\n🌐 Starting web server at http://localhost:5000")
    print("   Press Ctrl+C to stop the server")
    
    # Sort options for dropdowns
    severity_options = sorted(severity_options)
    rule_options = sorted(rule_options)
    
    return data, severity_options, rule_options, processing_errors, total_findings

# Global variables to store processed data
processed_data = []
severity_options = []
rule_options = []
processing_errors = []
total_findings = 0

@app.route('/', methods=['GET', 'POST'])
def index():
    # Apply filters if any
    selected_severity = request.args.get('severity', 'All')
    selected_rules = request.args.getlist('rule')  # Get list of selected rules

    filtered_data = processed_data

    if selected_severity and selected_severity != 'All':
        filtered_data = [d for d in filtered_data if d['Severity'] == selected_severity]

    if selected_rules and 'All' not in selected_rules:
        filtered_data = [d for d in filtered_data if d['RuleName'] in selected_rules]

    # Convert all data to JSON for JavaScript export
    import json
    all_data_json = json.dumps(processed_data)
    
    return render_template('index.html',
                           data=filtered_data,
                           all_data_json=all_data_json,
                           severity_options=severity_options,
                           rule_options=rule_options,
                           selected_severity=selected_severity,
                           selected_rules=selected_rules,
                           processing_errors=processing_errors,
                           total_findings=total_findings)

if __name__ == '__main__':
    try:
        # Process and validate Snaffler data BEFORE starting the server
        processed_data, severity_options, rule_options, processing_errors, total_findings = process_snaffler_data()
        
        # Start the Flask server only if validation passes
        app.run(debug=True, host='127.0.0.1', port=5000)
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
        sys.exit(0)
    except OSError as e:
        if "Address already in use" in str(e):
            print("❌ Error: Port 5000 is already in use")
            print("   Another application may be using this port.")
            print("   Try stopping other applications or modify the port in app.py")
        else:
            print(f"❌ Server error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        print("   Please check your input and try again.")
        sys.exit(1)

