from flask import Flask, request, jsonify, send_file
import os
import subprocess
import uuid

app = Flask(__name__)

# Get the CA base directory from environment variable or use default
CA_BASE_DIR = os.getenv("CA_BASE_DIR", "/intermediateCA") 

CERTS_DIR = os.path.join(CA_BASE_DIR, 'certs')
NEW_CERTS_DIR = os.path.join(CA_BASE_DIR, 'newcerts')
CSR_DIR = os.path.join(CA_BASE_DIR, 'csr')
CRL_PATH = os.path.join(CA_BASE_DIR, 'crl', 'intermediateCA.crl')
CA_CONF = os.path.join(CA_BASE_DIR, 'openssl_IntermediateCA.cnf')
INDEX_PATH = os.path.join(CA_BASE_DIR, "index.txt")
INTERMEDIATE_CERT = os.path.join(CA_BASE_DIR, "certs", "intermediateCA.cert.pem")

# Print the paths for debugging
print(f"CA base directory is set to: {CA_BASE_DIR}")
print(f"Certificates directory is set to: {CERTS_DIR}")
print(f"Certificate Signing Requests directory is set to: {CSR_DIR}")
print(f"Certificate Revocation List path is set to: {CRL_PATH}")
print(f"OpenSSL configuration file is set to: {CA_CONF}")

@app.route("/user", methods=["POST"])
def onboard_new_user():
    data = request.get_json()
    common_name = data.get("common_name", "client")

    # If the certificate with this common name already exists, return an error
    cert_path = os.path.join(CERTS_DIR, f"{common_name}.cert.pem")
    if os.path.exists(cert_path):
        return jsonify({"error": "Certificate already exists"}), 400
    
    # Create client folder
    user_folder = os.path.abspath(os.path.join(CA_BASE_DIR, "users", common_name))
    os.makedirs(user_folder, exist_ok=True)

    # Paths
    key_path = os.path.join(user_folder, f"{common_name}.key.pem")
    csr_path = os.path.join(user_folder, f"{common_name}.csr.pem")
    cert_path = os.path.join(CA_BASE_DIR, "certs", f"{common_name}.cert.pem")
    cert_path_in_user_folder = os.path.join(user_folder, f"{common_name}.cert.pem")
    chain_path = os.path.join(user_folder, f"{common_name}-chain.cert.pem")
    pkcs12_path = os.path.join(user_folder, f"{common_name}.p12")

    # Step 6.1 - Generate private key
    subprocess.check_call([
        "openssl", "genrsa", "-out", key_path, "2048"
    ])

    # Step 6.2 - Generate CSR
    subprocess.check_call([
        "openssl", "req", "-config", CA_CONF,
        "-key", key_path,
        "-passin", "pass:",
        "-new", "-sha256",
        "-out", csr_path,
        "-subj", f"/CN={common_name}/O=MyOrganization/OU=MyUnit/L=MyCity/ST=MyState/C=US"
    ])

    # Step 6.3 - Copy CSR to correct location and sign it
    csr_internal = os.path.join(CA_BASE_DIR, "csr", f"{common_name}.csr.pem")
    subprocess.check_call(["cp", csr_path, csr_internal])

    subprocess.check_call([
        "openssl", "ca",
        "-config", CA_CONF,
        "-extensions", "usr_cert",
        "-days", "375",
        "-notext",
        "-md", "sha256",
        "-in", csr_internal,
        "-out", cert_path,
        "-batch"
    ], cwd=CA_BASE_DIR)
    subprocess.check_call(["cp", cert_path, cert_path_in_user_folder])

    # Step 6.6 - Create certificate chain
    with open(chain_path, "w") as chain_file:
        with open(cert_path, "r") as user_cert:
            chain_file.write(user_cert.read())
        with open(INTERMEDIATE_CERT, "r") as intermediate_cert:
            chain_file.write(intermediate_cert.read())

    # Step 6.7 - Create .p12 (PKCS#12)
    subprocess.check_call([
        "openssl", "pkcs12", "-export",
        "-in", cert_path,
        "-inkey", key_path,
        "-passin", "pass:",
        "-certfile", chain_path,
        "-out", pkcs12_path,
        "-name", f"mTLS Cert for {common_name}",
        "-passout", "pass:"  # Nessuna password
    ])

    return send_file(
        pkcs12_path,
        mimetype="application/x-pkcs12",
        as_attachment=True,
        download_name=f"{common_name}.p12"
    )

@app.route('/certs/<serial>', methods=['GET'])
def get_cert(serial):
    cert_path = os.path.join(CERTS_DIR, f"{serial}.cert.pem")
    if not os.path.exists(cert_path):
        return jsonify({"error": "Not found"}), 404
    return send_file(cert_path)

@app.route('/newcerts/<serial>', methods=['GET'])
def get_new_cert(serial):
    cert_path = os.path.join(NEW_CERTS_DIR, f"{serial}.cert.pem")
    if not os.path.exists(cert_path):
        return jsonify({"error": "Not found"}), 404
    return send_file(cert_path)

@app.route('/certs/revoke', methods=['POST'])
def revoke_cert():
    data = request.get_json()
    cert_name = data.get("name")
    
    # Costruisci il path al certificato usando il nome
    cert_path = os.path.join(CERTS_DIR, f"{cert_name}.cert.pem")
    if not os.path.exists(cert_path):
        return jsonify({"error": "Certificate not found"}), 404

    try:
        # Revoca il certificato
        subprocess.check_call([
            "openssl", "ca",
            "-config", CA_CONF,
            "-revoke", cert_path
        ], cwd=CA_BASE_DIR)

        # Rigenera la CRL
        subprocess.check_call([
            "openssl", "ca",
            "-config", CA_CONF,
            "-gencrl",
            "-out", CRL_PATH
        ], cwd=CA_BASE_DIR)

        return jsonify({"message": "Certificate successfully revoked."})

    except subprocess.CalledProcessError as e:
        return jsonify({"error": "An error occurred during revocation", "details": str(e)}), 500

@app.route('/crl', methods=['GET'])
def get_crl():
    if not os.path.exists(CRL_PATH):
        return jsonify({"error": "CRL not found"}), 404
    return send_file(CRL_PATH)

@app.route('/crl/text', methods=['GET'])
def get_crl_info():
    try:
        output = subprocess.check_output([
            "openssl", "crl",
            "-in", CRL_PATH,
            "-text",
            "-noout"
        ], cwd=CA_BASE_DIR)

        return jsonify({
            "crl_info": output.decode("utf-8")
        })

    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Failed to read CRL", "details": str(e)}), 500

@app.route('/certs', methods=['GET'])
def list_certificates():
    if not os.path.exists(INDEX_PATH):
        return jsonify({"error": "index.txt not found"}), 500

    certs = []
    with open(INDEX_PATH, "r") as f:
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 6:
                continue  # skip malformed lines

            status = parts[0]
            expiry_date = parts[1]
            revocation_date = parts[2] if parts[2] else None
            serial = parts[3]
            filename = parts[4]  # normally always "unknown"
            subject = parts[5]

            certs.append({
                "serial": serial,
                "status": "revoked" if status == "R" else "valid",
                "expiry": expiry_date,
                "revoked_at": revocation_date,
                "subject": subject
            })

    return jsonify(certs)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=4000)
