from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash, session
from werkzeug.utils import secure_filename
import os
import nessus_parser

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'nessus'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# default value during development
app.secret_key = 'dev'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def search_data(data, search_dict):
    if not search_dict:
        return data

    filtered_data = []

    for row in data:
        match = True
        for key, value in search_dict.items():
            if value:
                # Split the search query by commas and remove whitespace
                search_terms = [term.strip() for term in value.split(',')]
                
                # Check if any search term matches the field
                if not any(term.lower() in str(row[key]).lower() for term in search_terms):
                    match = False
                    break

        if match:
            filtered_data.append(row)

    return filtered_data

@app.route('/', methods=['GET', 'POST'])
def home():
    return render_template('home.html', current_url=request.url)


@app.route('/upload', methods=['POST'])
def upload():
    nessus_file = request.files['file']
    if nessus_file:
        filename = secure_filename(nessus_file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        nessus_file.save(filepath)
        session['nessus_file'] = filepath
        return jsonify({"url": url_for('parser')})
    else:
        flash('File is not supported or corrupted', 'error')
        return jsonify({"error": "File is not supported or corrupted"}), 400

@app.route('/process-parsing', methods=['POST'])
def process_parsing():
    # Retrieve form data
    nessus_file = session.get('nessus_file', None)
    microsoft_patches = request.form.get('microsoft_patches') is not None
    third_party = request.form.get('third_party') is not None
    output_format = request.form['output_format']

    if nessus_file:
        output_file = os.path.join(app.config['UPLOAD_FOLDER'], 'output.' + output_format)

        vulnerabilities = nessus_parser.parse_nessus_file(nessus_file, microsoft_patches, third_party)
        nessus_parser.print_output(vulnerabilities, output_format, output_file)

        return send_file(output_file, as_attachment=True, attachment_filename='output.' + output_format)
    else:
        return jsonify({"error": "File is not supported or corrupted"}), 400


@app.route('/parser', methods=['GET'])
def parser():
    if 'nessus_file' in session:
        filepath = session['nessus_file']
        return render_template('parser.html', nessus_file=filepath)
    return render_template('parser.html')


@app.route('/explorer', methods=['GET'])
def explorer():
    nessus_file = session.get('nessus_file', None)
    findings = nessus_parser.explore_nessus_file(nessus_file)
    
    return render_template('explorer.html', findings=findings)

@app.route('/search', methods=['POST'])
def search():
    nessus_file = session.get('nessus_file', None)
    findings = nessus_parser.explore_nessus_file(nessus_file)
    search_dict = {
        'host_ip': request.form.get('host-ip'),
        'plugin_name': request.form.get('plugin-name'),
        'hostname': request.form.get('host-name'),
        'plugin_id': request.form.get('plugin-id'),
        'risk_rating': request.form.get('risk'),
        'port': request.form.get('port'),
        'service': request.form.get('service'),
        'description_synopsis': request.form.get('description-synopsis')
    }
    filtered_findings = search_data(findings, search_dict)
    return jsonify(filtered_findings)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)


