from flask import Flask, render_template, request
import sys
import re
import os
import glob

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

@app.route('/', methods=['GET', 'POST'])
def index():
    if len(sys.argv) < 2:
        return "Please provide the log directory as a command line argument."

    logdir = sys.argv[1]
    data = []
    severity_options = set()
    rule_options = set()

    # Collect all .txt files in the specified directory
    log_files = glob.glob(os.path.join(logdir, '*.txt'))

    for logfile in log_files:
        with open(logfile, 'r', encoding='latin-1') as f:
            filename = os.path.basename(logfile)
            for line in f:
                if '[File]' in line:
                    parsed = parse_line(line, filename)
                    data.append(parsed)
                    severity_options.add(parsed['Severity'])
                    rule_options.add(parsed['RuleName'])

    # Sort options for dropdowns
    severity_options = sorted(severity_options)
    rule_options = sorted(rule_options)

    # Apply filters if any
    selected_severity = request.args.get('severity')
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

