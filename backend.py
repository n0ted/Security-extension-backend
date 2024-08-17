from flask import Flask, request, jsonify
from flask_cors import CORS
from headers import SecurityHeaders# Ensure your_script.py contains the modified code above
def analyze_security_headers(url, max_redirects=10, no_check_certificate=False):
    try:
        header_check = SecurityHeaders(url, max_redirects, no_check_certificate)
        result = header_check.analyze_security_headers()
        result['ip'] = header_check.headers.get('ip')
        result['raw_headers'] = dict(header_check.headers) 
        return result
    except Exception as e:
        return {'error': str(e)}

app = Flask(__name__)
CORS(app, resources={r"/analyze*": {"origins": "http://localhost:3000"}})
CORS(app)  # Enable CORS for cross-origin AJAX requests
@app.route('/')
def home():
    return 'THIS IS THE BACKEND FOR YOUR CHROME EXTENSION AND ITS WORKING'
@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    result = analyze_security_headers(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
