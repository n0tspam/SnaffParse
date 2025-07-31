# Snaffler Parser

A powerful web-based tool for parsing, visualizing, and analyzing Snaffler security findings across multiple file formats.

## Features

### 🔍 Multi-Format Support
- **TSV Files**: Native Snaffler tab-separated output
- **JSON Files**: Structured JSON logs with security findings
- **TXT Files**: Structured text logs with pattern matching
- **Directory Processing**: Scan entire directories for supported files
- **Automatic Deduplication**: Removes duplicate findings when processing multiple files

### 📊 Advanced Data Visualization
- **Responsive Web Interface**: Built with Bootstrap and DataTables
- **Color-Coded Severity**: Visual indicators for Red, Yellow, Green, Black severities
- **Smart Column Sizing**: Raw Result column prioritizes readability with 50% table width
- **Text Wrapping**: All columns wrap text to show complete information
- **Real-Time Filtering**: 
  - Filter by Severity level
  - Multi-select Rule Name filtering
  - DataTables search box for instant text filtering
- **Entry Count Display**: Shows current view vs total findings with filter status

### 🎛️ Column Management
- **Show/Hide Columns**: Toggle visibility of any column
- **Optimized Layout**: Raw Result column takes majority of space
- **Full Path Priority**: Enhanced width for better path readability

### 📥 Export Capabilities
- **Export Current View**: CSV export respecting all active filters and hidden columns
- **Export All Data**: Complete unfiltered dataset export
- **Proper CSV Formatting**: Escaped quotes, handled commas and newlines

### 🛡️ Robust Error Handling
- **Pre-Validation**: Validates files/directories before starting server
- **Comprehensive Error Messages**: Clear feedback for:
  - Missing arguments
  - Non-existent files
  - Permission issues
  - Unsupported file types
  - Parsing errors
- **Processing Summary**: Shows files processed, findings extracted, and any errors

## Installation

1. Clone this repository
2. Install required dependencies:
   ```bash
   pip install flask
   ```

## Usage

### Single File Processing
```bash
python app.py snaffler_output.tsv
python app.py security_findings.json
python app.py scan_results.txt
```

### Directory Processing
```bash
python app.py /path/to/logs/directory/
```

### Help
```bash
python app.py --help
```

## Supported File Formats

### TSV Format (Snaffler Native)
Tab-separated values with columns:
- UserHost, Timestamp, LogType, Severity, RuleName, AccessLevel, MatchPattern, FileSize, DateModified, FullPath, AdditionalData

### JSON Format
```json
{
  "entries": [
    {
      "level": "Warn",
      "message": "[File] <RuleName|...> (FullPath) AdditionalData",
      "eventProperties": {
        "Red": true
      }
    }
  ]
}
```

### Text Format
Structured logs with pattern:
```
{Severity} [File] <RuleName|...|DateModified> (FullPath) AdditionalData
```

## Web Interface Guide

1. **Filtering**:
   - Use Severity dropdown for severity filtering
   - Use multi-select Rules dropdown for specific findings
   - Use search box for text-based filtering

2. **Column Visibility**:
   - Check/uncheck columns in the visibility panel
   - Use "Show All" / "Hide All" buttons for bulk operations

3. **Exporting**:
   - "Export Current View": Exports filtered data with visible columns only
   - "Export All Data": Exports complete dataset ignoring all filters

4. **Navigation**:
   - Pagination controls at bottom
   - Adjustable page size (10, 25, 50, All)
   - Column sorting by clicking headers

## Technical Details

- **Backend**: Flask (Python)
- **Frontend**: Bootstrap 3, jQuery, DataTables
- **Processing**: In-memory data processing with deduplication
- **Export**: Client-side CSV generation with proper escaping

## Security Note

This tool is designed for defensive security analysis. It helps security teams analyze Snaffler findings to identify and remediate sensitive file exposures in their environments.

## File Structure

```
snafflerparser/
├── app.py              # Main Flask application
├── templates/
│   └── index.html      # Web interface template
├── sample_output.tsv   # Sample Snaffler output
└── README.md          # This file
```

## Browser Compatibility

- Chrome/Chromium (recommended)
- Firefox
- Safari
- Edge

## Troubleshooting

### Common Issues

1. **File Encoding Errors**
   - Text files are read with `latin-1` encoding
   - JSON and TSV files use `utf-8` encoding

2. **Large Files**
   - The application loads all data into memory
   - For very large files, consider splitting them into smaller chunks

3. **Port Conflicts**
   - Default port is 5000
   - Modify `app.run()` in `app.py` to use a different port

### Debug Mode
Enable debug mode by ensuring `debug=True` in the `app.run()` call for detailed error messages.

## Example Usage Scenarios

### Snaffler Analysis
```bash
# Run Snaffler and save output
snaffler.exe -d domain.com -o snaffler_output.tsv

# Analyze the results
python app.py snaffler_output.tsv
```

### Bulk Log Analysis
```bash
# Analyze multiple log files from different sources
python app.py /security/logs/

# The tool will automatically:
# - Detect file types
# - Parse each format appropriately
# - Deduplicate findings
# - Present unified results
```

## Contributing

This project focuses on defensive security analysis. Contributions should maintain this focus and avoid implementing features that could be used maliciously.