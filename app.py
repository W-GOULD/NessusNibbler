from flask import Flask, render_template, request, send_from_directory, send_file, jsonify
from werkzeug.utils import secure_filename
import os
import nessus_parser

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads/')

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'nessus'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        return process()
    return render_template('index.html')

@app.route('/uploads/<path:path>')
def serve_file(path):
    return send_from_directory(app.config['UPLOAD_FOLDER'], path)

@app.route('/process', methods=['POST'])
def process():
    nessus_file = request.files['file']
    if nessus_file and allowed_file(nessus_file.filename):
        microsoft_patches = 'microsoft_patches' in request.form
        third_party = 'third_party' in request.form
        output_format = request.form.get('output_format', 'docx')  # Change this line
        output_file = os.path.join(app.config['UPLOAD_FOLDER'], 'output.' + output_format)

        nessus_file.save('uploaded_nessus_file.nessus')
        vulnerabilities = nessus_parser.parse_nessus_file('uploaded_nessus_file.nessus', microsoft_patches, third_party)
        nessus_parser.print_output(vulnerabilities, output_format, output_file)

        return send_file(output_file, as_attachment=True, attachment_filename='output.' + output_format)
    else:
        return jsonify({"error": "File is not supported or corrupted"}), 400 

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)