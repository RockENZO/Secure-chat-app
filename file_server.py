from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import stat

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Set permissions to 755 (rwxr-xr-x)
os.chmod(UPLOAD_FOLDER, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | 
                   stat.S_IRGRP | stat.S_IXGRP | 
                   stat.S_IROTH | stat.S_IXOTH)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Return a URL that points to the uploaded file
    return jsonify({"url": f"http://localhost:5001/files/{file.filename}"}), 200

@app.route('/files/<filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True, port=5001)