#!/usr/bin/env python
"""
Full Flask application with background file-watch thread that:
- Allows uploads / pasted content analysis via /analyze (existing behavior)
- Accepts a file path to watch via POST /set_watch_path (JSON: {"path": "..."})
- Background thread polls the watched file's mtime and re-analyzes when changed
- Exposes latest analysis via GET /auto_results
- Export endpoints remain (csv, txt, json) using saved analysis files
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, Response
import time
import threading
import random
import os
import json
import datetime
import re
import csv
import io
from werkzeug.utils import secure_filename
from collections import Counter, defaultdict

# -----------------------
# Flask app configuration
# -----------------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'  # Directory for storing uploaded files and analysis results
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # Maximum file size: 50MB
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

# Create uploads directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# -----------------------
# LogAnalyzer
# -----------------------
class LogAnalyzer:

    def __init__(self):
        self.log_patterns = {
            'apache': re.compile(r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?$'),
            'nginx': re.compile(r'^(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\S+)(?: "([^"]*)" "([^"]*)")?$'),
            'syslog': re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s+(.+)$'),
            'mikrotik': re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+),\s*(\w+)\s+(.+)$'),
            'cisco': re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\d+):\s*(.+)$'),
            'juniper': re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:]+):\s+(.+)$'),
            'generic': re.compile(r'^(\S+)\s+(\S+)\s+(\S+)\s+(\S+.*)$')
        }

    def detect_log_format(self, sample_lines):
        for fmt, pattern in self.log_patterns.items():
            matches = 0
            for line in sample_lines[:10]:
                if pattern.match(line.strip()):
                    matches += 1
            if matches >= 5:
                return fmt
        return 'generic'

    def parse_logs(self, content, log_format=None):
        lines = content.split('\n')
        if not log_format:
            log_format = self.detect_log_format(lines)

        pattern = self.log_patterns.get(log_format, self.log_patterns['generic'])
        parsed_logs = []

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            match = pattern.match(line)
            if match:
                if log_format in ['apache', 'nginx']:
                    # match.group(5) contains "METHOD URL PROTOCOL"
                    method = ''
                    url = ''
                    try:
                        parts = match.group(5).split()
                        if len(parts) > 0:
                            method = parts[0]
                        if len(parts) > 1:
                            url = parts[1]
                    except Exception:
                        pass

                    parsed_logs.append({
                        'ip': match.group(1),
                        'timestamp': match.group(4),
                        'method': method,
                        'url': url,
                        'status': match.group(6),
                        'size': match.group(7),
                        'user_agent': match.group(8) or '',
                        'line_number': line_num
                    })
                elif log_format == 'mikrotik':
                    parsed_logs.append({
                        'timestamp': match.group(1),
                        'interface': match.group(2),
                        'facility': match.group(3),
                        'message': match.group(4),
                        'line_number': line_num
                    })
                elif log_format == 'cisco':
                    parsed_logs.append({
                        'timestamp': match.group(1),
                        'hostname': match.group(2),
                        'process_id': match.group(3),
                        'message': match.group(4),
                        'line_number': line_num
                    })
                elif log_format == 'juniper':
                    parsed_logs.append({
                        'timestamp': match.group(1),
                        'hostname': match.group(2),
                        'process': match.group(3),
                        'message': match.group(4),
                        'line_number': line_num
                    })
                elif log_format == 'syslog':
                    parsed_logs.append({
                        'timestamp': match.group(1),
                        'hostname': match.group(2),
                        'process': match.group(3),
                        'message': match.group(4),
                        'line_number': line_num
                    })
                else:  # generic
                    parsed_logs.append({
                        'field1': match.group(1),
                        'field2': match.group(2),
                        'field3': match.group(3),
                        'message': match.group(4),
                        'line_number': line_num
                    })

        return parsed_logs, log_format

    def analyze_logs(self, parsed_logs):
        if not parsed_logs:
            return {}

        analysis = {
            'total_entries': len(parsed_logs),
            'time_range': '',
            'top_ips': [],
            'status_codes': {},
            'error_count': 0,
            'warning_count': 0,
            'top_urls': [],
            'hourly_distribution': {},
            'daily_distribution': {}
        }

        first_log = parsed_logs[0] if parsed_logs else {}

        if 'ip' in first_log:
            top_ips = Counter(log.get('ip', '') for log in parsed_logs).most_common(10)
            status_codes = Counter(log.get('status', '') for log in parsed_logs)
            top_urls = Counter(log.get('url', '') for log in parsed_logs).most_common(10)

            analysis['top_ips'] = top_ips
            analysis['status_codes'] = dict(status_codes)
            analysis['top_urls'] = top_urls
            analysis['error_count'] = sum(1 for log in parsed_logs if str(log.get('status', '')).startswith(('4','5')))

            hourly = Counter()
            for log in parsed_logs:
                if log.get('timestamp'):
                    try:
                        dt = datetime.datetime.strptime(log['timestamp'], '%d/%b/%Y:%H:%M:%S')
                        hourly[dt.hour] += 1
                    except Exception:
                        pass
            analysis['hourly_distribution'] = dict(hourly)

        elif 'hostname' in first_log and 'interface' not in first_log and 'process_id' not in first_log:
            analysis['top_hostnames'] = Counter(log.get('hostname', '') for log in parsed_logs).most_common(10)
            analysis['top_processes'] = Counter(log.get('process', '') for log in parsed_logs).most_common(10)
            for log in parsed_logs:
                message = log.get('message', '').lower()
                if any(word in message for word in ['error', 'critical', 'failed', 'failure']):
                    analysis['error_count'] += 1
                elif any(word in message for word in ['warning', 'warn']):
                    analysis['warning_count'] += 1

        elif 'interface' in first_log:
            analysis['top_interfaces'] = Counter(log.get('interface', '') for log in parsed_logs).most_common(10)
            analysis['top_facilities'] = Counter(log.get('facility', '') for log in parsed_logs).most_common(10)
            for log in parsed_logs:
                message = log.get('message', '').lower()
                if 'drop' in message or 'denied' in message:
                    analysis['error_count'] += 1
                elif any(word in message for word in ['warning', 'warn', 'alert']):
                    analysis['warning_count'] += 1

        elif 'process_id' in first_log:
            analysis['top_hostnames'] = Counter(log.get('hostname', '') for log in parsed_logs).most_common(10)
            analysis['top_process_ids'] = Counter(log.get('process_id', '') for log in parsed_logs).most_common(10)
            for log in parsed_logs:
                message = log.get('message', '').lower()
                if 'updown' in message or 'changed state' in message:
                    if 'up' in message:
                        analysis['info_count'] = analysis.get('info_count', 0) + 1
                    elif 'down' in message:
                        analysis['warning_count'] += 1
                elif any(word in message for word in ['denied', 'blocked', 'violation']):
                    analysis['error_count'] += 1

        elif 'process' in first_log and 'hostname' in first_log:
            analysis['top_hostnames'] = Counter(log.get('hostname', '') for log in parsed_logs).most_common(10)
            analysis['top_processes'] = Counter(log.get('process', '') for log in parsed_logs).most_common(10)
            for log in parsed_logs:
                message = log.get('message', '').lower()
                if 'session' in message:
                    if 'create' in message or 'established' in message:
                        analysis['info_count'] = analysis.get('info_count', 0) + 1
                    elif 'close' in message or 'terminated' in message:
                        analysis['info_count'] = analysis.get('info_count', 0) + 1
                elif any(word in message for word in ['attack', 'threat', 'violation', 'intrusion']):
                    analysis['error_count'] += 1

        return analysis

    def apply_filters(self, parsed_logs, filters):
        if not filters or not parsed_logs:
            return parsed_logs

        filtered_logs = parsed_logs

        # Date/Time filter
        if filters.get('start_date') or filters.get('end_date'):
            try:
                if 'timestamp' in parsed_logs[0]:
                    new_filtered = []
                    for log in parsed_logs:
                        if log.get('timestamp'):
                            try:
                                log_dt = datetime.datetime.strptime(log['timestamp'], '%d/%b/%Y:%H:%M:%S')
                                if filters.get('start_date'):
                                    start_dt = datetime.datetime.strptime(filters['start_date'], '%Y-%m-%dT%H:%M')
                                    if log_dt < start_dt:
                                        continue
                                if filters.get('end_date'):
                                    end_dt = datetime.datetime.strptime(filters['end_date'], '%Y-%m-%dT%H:%M')
                                    if log_dt > end_dt:
                                        continue
                                new_filtered.append(log)
                            except Exception:
                                continue
                    filtered_logs = new_filtered
            except Exception:
                pass

        # IP filter
        if filters.get('ip_filter'):
            ip_filter = filters['ip_filter'].lower().strip()
            if ip_filter:
                filtered_logs = [log for log in filtered_logs if ip_filter in log.get('ip', '').lower()]

        # Status code filter
        if filters.get('status_filter'):
            status_filter = filters['status_filter'].strip()
            if status_filter:
                filtered_logs = [log for log in filtered_logs if log.get('status') == status_filter]

        # URL filter
        if filters.get('url_filter'):
            url_filter = filters['url_filter'].lower().strip()
            if url_filter:
                filtered_logs = [log for log in filtered_logs if url_filter in log.get('url', '').lower()]

        # Search text filter
        if filters.get('search_text'):
            search_text = filters['search_text'].lower().strip()
            if search_text:
                filtered_logs = []
                for log in parsed_logs:
                    log_text = str(log).lower()
                    if search_text in log_text:
                        filtered_logs.append(log)

        return filtered_logs

# -----------------------
# Global analyzer instance
# -----------------------
analyzer = LogAnalyzer()

# -----------------------
# Background watch globals
# -----------------------
watch_file_path = None
watch_last_mtime = None
watch_results = None
watch_lock = threading.Lock()

# -----------------------
# Routes
# -----------------------

@app.route('/')
def index():
    # This expects a template named e.g. auto_analytics.html in templates/
    # The user requested only the Flask file; keep the route for compatibility with front-end.
    return render_template('auto_analytics.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Analyze uploaded file or pasted content.
    Keeps original behavior: accepts file upload 'log_file' OR form field 'log_content'.
    Returns JSON with analysis results.
    """
    try:
        content = ''
        # Check if file was uploaded
        if 'log_file' in request.files and request.files['log_file'].filename:
            file = request.files['log_file']
            filename = secure_filename(file.filename or 'uploaded_file.log')
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        else:
            # Handle pasted content
            content = request.form.get('log_content', '')

        if not content or not content.strip():
            return jsonify({'error': 'No log content provided'}), 400

        parsed_logs, detected_format = analyzer.parse_logs(content)
        analysis_results = analyzer.analyze_logs(parsed_logs)

        analysis_results['detected_format'] = detected_format
        analysis_results['analyzed_at'] = datetime.datetime.now().isoformat()

        # Persist results to file for export endpoints
        results_file = f"analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        results_path = os.path.join(app.config['UPLOAD_FOLDER'], results_file)
        with open(results_path, 'w') as f:
            json.dump(analysis_results, f, indent=2)

        # Also update watch_results if this analyze was for the watched file
        try:
            # if request.form had a 'watched_file' field, update watch_results too
            wf = request.form.get('watched_file') or request.args.get('watched_file')
            if wf:
                with watch_lock:
                    global watch_results
                    watch_results = dict(analysis_results)
                    watch_results['watched_file'] = wf
        except Exception:
            pass

        return jsonify(analysis_results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/set_watch_path', methods=['POST'])
def set_watch_path():
    """
    Set a file path to be watched by the background thread.
    Expects JSON body: {"path": "/full/path/to/logfile.log"}
    """
    global watch_file_path, watch_last_mtime

    try:
        data = request.get_json(force=True)
        path = data.get("path")
    except Exception:
        return jsonify({"error": "Invalid JSON payload"}), 400

    if not path:
        return jsonify({"error": "No path provided"}), 400

    # Normalize path
    path = os.path.expanduser(path)

    if not os.path.isfile(path):
        return jsonify({"error": f"File does not exist: {path}"}), 400

    with watch_lock:
        watch_file_path = path
        watch_last_mtime = None  # force immediate scan

    return jsonify({"status": "watching", "path": path})

@app.route('/auto_results', methods=['GET'])
def auto_results():
    """
    Return the latest auto analysis result from background watcher.
    """
    with watch_lock:
        if watch_results is None:
            return jsonify({"status": "no_data"})
        return jsonify(watch_results)

@app.route('/export/<format_type>')
def export_results(format_type):
    """
    Export the most recent analysis_<timestamp>.json file in uploads/ to CSV/TXT/JSON.
    """
    try:
        results_files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if f.startswith('analysis_') and f.endswith('.json')]
        if not results_files:
            return Response("No analysis results found", mimetype='text/plain', status=404)

        latest_file = max(results_files, key=lambda f: os.path.getctime(os.path.join(app.config['UPLOAD_FOLDER'], f)))
        results_path = os.path.join(app.config['UPLOAD_FOLDER'], latest_file)

        with open(results_path, 'r') as f:
            results = json.load(f)

        # CSV export
        if format_type == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)

            writer.writerow(['LOG ANALYTICS REPORT'])
            writer.writerow(['Generated on', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow([])

            writer.writerow(['ANALYSIS SUMMARY'])
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Total Log Entries', results.get('total_entries', 0)])
            writer.writerow(['Error Count', results.get('error_count', 0)])
            writer.writerow(['Warning Count', results.get('warning_count', 0)])
            writer.writerow(['Log Format Detected', results.get('detected_format', 'Unknown')])

            if 'top_ips' in results and results['top_ips']:
                writer.writerow([])
                writer.writerow(['WEB SERVER ANALYSIS'])
                writer.writerow(['IP Address', 'Count'])
                for ip, count in results['top_ips']:
                    writer.writerow([ip, count])

            if 'status_codes' in results and results['status_codes']:
                writer.writerow([])
                writer.writerow(['HTTP Status Code', 'Count'])
                status_items = sorted(results['status_codes'].items(), key=lambda x: x[1], reverse=True)
                for status, count in status_items:
                    writer.writerow([status, count])

            # Hourly
            if 'hourly_distribution' in results and results['hourly_distribution']:
                writer.writerow([])
                writer.writerow(['Hour', 'Count'])
                for hour_str, count in sorted(results['hourly_distribution'].items(), key=lambda x: int(x[0]) if isinstance(x[0], str) and x[0].isdigit() else x[0]):
                    writer.writerow([hour_str, count])

            return Response(output.getvalue(), mimetype='text/csv',
                            headers={'Content-Disposition': f'attachment; filename="log_analysis_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'})

        # TXT export
        elif format_type == 'txt':
            output = io.StringIO()
            output.write("=" * 60 + "\n")
            output.write("LOG ANALYTICS REPORT\n")
            output.write("=" * 60 + "\n")
            output.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            output.write(f"Total Log Entries: {results.get('total_entries', 0)}\n")
            output.write(f"Log Format Detected: {results.get('detected_format', 'Unknown')}\n")
            output.write("\n")

            if 'top_ips' in results and results['top_ips']:
                output.write("Top IP Addresses:\n")
                for ip, count in results['top_ips']:
                    output.write(f"{ip:<20} {count:>6}\n")
                output.write("\n")

            if 'status_codes' in results and results['status_codes']:
                output.write("HTTP Status Codes:\n")
                for status, count in sorted(results['status_codes'].items(), key=lambda x: x[1], reverse=True):
                    output.write(f"{status:<8} {count:>6}\n")
                output.write("\n")

            return Response(output.getvalue(), mimetype='text/plain',
                            headers={'Content-Disposition': f'attachment; filename="log_analysis_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.txt"'})

        # JSON export
        elif format_type == 'json':
            enhanced_results = {
                'metadata': {
                    'export_timestamp': datetime.datetime.now().isoformat(),
                    'tool_version': '1.0.0',
                    'report_type': 'Log Analysis Report',
                    'total_entries': results.get('total_entries', 0),
                    'detected_format': results.get('detected_format', 'Unknown')
                },
                'summary': {
                    'total_entries': results.get('total_entries', 0),
                    'error_count': results.get('error_count', 0),
                    'warning_count': results.get('warning_count', 0),
                    'info_count': results.get('info_count', 0),
                    'detected_format': results.get('detected_format', 'Unknown'),
                    'analyzed_at': results.get('analyzed_at', '')
                },
                'raw_analysis_data': results
            }
            return Response(json.dumps(enhanced_results, indent=2), mimetype='application/json',
                            headers={'Content-Disposition': f'attachment; filename="log_analysis_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json"'})

        else:
            return Response("Unknown export format", mimetype='text/plain', status=400)

    except Exception as e:
        return Response(f"Export error: {str(e)}", mimetype='text/plain', status=500)

# -----------------------
# Background watcher
# -----------------------
def file_watch_worker(poll_interval=3):
    """
    Background thread worker that polls the watched file for modification and re-analyzes.
    """
    global watch_file_path, watch_last_mtime, watch_results

    while True:
        try:
            time.sleep(poll_interval)

            # If no path set, skip
            if not watch_file_path:
                continue

            # If file is gone, keep waiting (but clear results maybe)
            if not os.path.isfile(watch_file_path):
                # Optionally clear watch_results or set an error key
                with watch_lock:
                    watch_results = {"error": f"Watched file not found: {watch_file_path}", "watched_file": watch_file_path}
                continue

            mtime = os.path.getmtime(watch_file_path)

            # If first time or changed
            if watch_last_mtime is None or mtime != watch_last_mtime:
                watch_last_mtime = mtime
                try:
                    with open(watch_file_path, 'r', encoding='utf-8', errors='ignore') as fh:
                        content = fh.read()
                except Exception as e:
                    with watch_lock:
                        watch_results = {"error": f"Failed to read watched file: {str(e)}", "watched_file": watch_file_path}
                    continue

                parsed, fmt = analyzer.parse_logs(content)
                analysis = analyzer.analyze_logs(parsed)
                analysis['detected_format'] = fmt
                analysis['watched_file'] = watch_file_path
                analysis['updated_at'] = datetime.datetime.now().isoformat()

                # Save analysis to disk (so export endpoints can find it)
                try:
                    results_file = f"analysis_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    results_path = os.path.join(app.config['UPLOAD_FOLDER'], results_file)
                    with open(results_path, 'w') as rf:
                        json.dump(analysis, rf, indent=2)
                except Exception as e:
                    # Logging to stdout; continue
                    print(f"[WATCH] failed to persist analysis: {e}")

                with watch_lock:
                    watch_results = analysis

                print(f"[WATCH] Updated analysis for {watch_file_path} at {analysis['updated_at']}")

        except Exception as e:
            # Keep the watcher alive even if errors occur
            print(f"[WATCH ERROR] {e}")
            time.sleep(1)
            continue

# -----------------------
# App entrypoint
# -----------------------
if __name__ == '__main__':
    try:
        # Start watcher thread
        watcher_thread = threading.Thread(target=file_watch_worker, kwargs={'poll_interval': 3}, daemon=True)
        watcher_thread.start()
        print("👀 File watch thread started (poll interval: 3s)")

        print("🚀 Starting Log Analytics Tool...")
        print("📊 Web interface available at: http://localhost:5000")
        print("🔧 Debug mode: Enabled")
        print(f"📁 Upload directory: {app.config['UPLOAD_FOLDER']}/")
        app.run(debug=True, host='0.0.0.0', port=5000)

    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("💡 Make sure port 5000 is available and not used by another application")
