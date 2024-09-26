from flask import Flask, render_template, request
import sys
import re
import os
import glob
import json

app = Flask(__name__)

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

@app.route('/', methods=['GET', 'POST'])
def index():
    if len(sys.argv) < 2:
        return "Please provide the log directory or log file as a command line argument."

    log_input = sys.argv[1]
    data = []
    severity_options = set()
    rule_options = set()

    log_files = []

    if os.path.isdir(log_input):
        # Collect all .txt and .json files in the specified directory
        txt_files = glob.glob(os.path.join(log_input, '*.txt'))
        json_files = glob.glob(os.path.join(log_input, '*.json'))
        log_files = txt_files + json_files
    elif os.path.isfile(log_input):
        # Single file provided
        log_files = [log_input]
    else:
        return f"The path '{log_input}' is neither a valid directory nor a file."

    for logfile in log_files:
        filename = os.path.basename(logfile)
        if logfile.endswith('.txt'):
            with open(logfile, 'r', encoding='latin-1') as f:
                for line in f:
                    if '[File]' in line:
                        parsed = parse_line(line, filename)
                        data.append(parsed)
                        severity_options.add(parsed['Severity'])
                        rule_options.add(parsed['RuleName'])
        elif logfile.endswith('.json'):
            with open(logfile, 'r', encoding='utf-8') as f:
                try:
                    json_data = json.load(f)
                    entries = json_data.get('entries', [])
                    for entry in entries:
                        # Consider only entries with level 'Warn' and messages containing '[File]'
                        if entry.get('level') in ['Warn', 'Error'] and '[File]' in entry.get('message', ''):
                            parsed = parse_json_entry(entry, filename)
                            data.append(parsed)
                            severity_options.add(parsed['Severity'])
                            rule_options.add(parsed['RuleName'])
                except json.JSONDecodeError:
                    print(f"Error decoding JSON in file: {filename}")
                    continue
        else:
            print(f"Unsupported file type: {filename}")
            continue

    # Sort options for dropdowns
    severity_options = sorted(severity_options)
    rule_options = sorted(rule_options)

    # Apply filters if any
    selected_severity = request.args.get('severity', 'All')
    selected_rules = request.args.getlist('rule')  # Get list of selected rules

    filtered_data = data

    if selected_severity and selected_severity != 'All':
        filtered_data = [d for d in filtered_data if d['Severity'] == selected_severity]

    if selected_rules and 'All' not in selected_rules:
        filtered_data = [d for d in filtered_data if d['RuleName'] in selected_rules]

    return render_template('index.html',
                           data=filtered_data,
                           severity_options=severity_options,
                           rule_options=rule_options,
                           selected_severity=selected_severity,
                           selected_rules=selected_rules)

if __name__ == '__main__':
    app.run(debug=True)
