from flask import Flask, request, jsonify, send_file
import os
import subprocess
import uuid

app = Flask(__name__)
# CA_BASE_DIR = os.getenv("CA_BASE_DIR", "/intermediateCA") 
BASE_DIR = os.path.dirname(__file__)
CERTS_DIR = os.path.join(BASE_DIR, 'certs')
CSRS_DIR = os.path.join(BASE_DIR, 'csrs')
CRL_PATH = os.path.join(BASE_DIR, 'crl', 'intermediate.crl.pem')
CA_CONF = os.path.join(BASE_DIR, 'openssl.cnf')
CA_DIR = BASE_DIR

os.makedirs(CERTS_DIR, exist_ok=True)
os.makedirs(CSRS_DIR, exist_ok=True)

def save_csr(csr_pem, common_name):
    filename = f"{common_name}_{uuid.uuid4().hex}.csr.pem"
    path = os.path.join(CSRS_DIR, filename)
    with open(path, "w") as f:
        f.write(csr_pem)
    return path

def sign_certificate(csr_path, cert_type='usr_cert'):
    cert_filename = f"{uuid.uuid4().hex}.crt.pem"
    cert_path = os.path.join(CERTS_DIR, cert_filename)

    subprocess.check_call([
        "openssl", "ca",
        "-config", CA_CONF,
        "-extensions", cert_type,
        "-days", "365",
        "-notext",
        "-md", "sha256",
        "-in", csr_path,
        "-out", cert_path,
        "-batch"
    ], cwd=CA_DIR)

    return cert_path

@app.route('/certs/user', methods=['POST'])
def issue_user_cert():
    data = request.get_json()
    csr = data.get('csr')
    cn = data.get('common_name', 'user')
    if not csr:
        return jsonify({"error": "CSR is required"}), 400

    csr_path = save_csr(csr, cn)
    cert_path = sign_certificate(csr_path, cert_type="usr_cert")
    with open(cert_path, "r") as f:
        return jsonify({"certificate": f.read()})

@app.route('/certs/server', methods=['POST'])
def issue_server_cert():
    data = request.get_json()
    csr = data.get('csr')
    cn = data.get('common_name', 'server')
    if not csr:
        return jsonify({"error": "CSR is required"}), 400

    csr_path = save_csr(csr, cn)
    cert_path = sign_certificate(csr_path, cert_type="server_cert")
    with open(cert_path, "r") as f:
        return jsonify({"certificate": f.read()})

@app.route('/certs/<serial>', methods=['GET'])
def get_cert(serial):
    cert_path = os.path.join(CERTS_DIR, f"{serial}.crt.pem")
    if not os.path.exists(cert_path):
        return jsonify({"error": "Not found"}), 404
    return send_file(cert_path)

@app.route('/certs/revoke', methods=['POST'])
def revoke_cert():
    data = request.get_json()
    serial = data.get("serial")
    cert_path = os.path.join(CERTS_DIR, f"{serial}.crt.pem")
    if not os.path.exists(cert_path):
        return jsonify({"error": "Not found"}), 404

    subprocess.check_call(["openssl", "ca", "-config", CA_CONF, "-revoke", cert_path], cwd=CA_DIR)
    subprocess.check_call(["openssl", "ca", "-gencrl", "-config", CA_CONF, "-out", CRL_PATH], cwd=CA_DIR)
    return jsonify({"revoked": serial})

@app.route('/crl', methods=['GET'])
def get_crl():
    if not os.path.exists(CRL_PATH):
        return jsonify({"error": "CRL not found"}), 404
    return send_file(CRL_PATH)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=4000)