from flask import Flask, jsonify, request, send_from_directory
import os
import subprocess
import shutil

app = Flask(__name__)

# Your actual PKI structure
BASE_PKI_PATH = "/Users/filiporlikowski/Documents/SEGPRD/project/pki"
INTERMEDIATE_CA_PATH = os.path.join(BASE_PKI_PATH, "intermediate")
INTERMEDIATE_CA_CERT = os.path.join(INTERMEDIATE_CA_PATH, "certs", "intermediateCA.crt")
INTERMEDIATE_CA_KEY = os.path.join(INTERMEDIATE_CA_PATH, "private", "intermediateCA.key")
OPENSSL_CONFIG = os.path.join(INTERMEDIATE_CA_PATH, "openssl.cnf")
CRL_PATH = os.path.join(INTERMEDIATE_CA_PATH, "crl", "crl.pem")
USER_CERTS_PATH = os.path.join(BASE_PKI_PATH, "users")

# Ensure users directory exists
os.makedirs(USER_CERTS_PATH, exist_ok=True)

def run_command(command):
    print(f"Running command:\n  {command}\n")
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print("Command output:\n", result.stdout.decode())
        return result.stdout.decode()
    except subprocess.CalledProcessError as e:
        print("Command FAILED:\n", e.stderr.decode())
        raise RuntimeError(f"Command failed:\n{e.stderr.decode()}")
    
## Example usage of the run_command function
#curl -X POST -F "name=john_doe" http://127.0.0.1:5000/create_user

@app.route('/create_user', methods=['POST'])
def create_user():
    user_name = request.form.get('name')
    if not user_name:
        return jsonify({'message': 'Missing user name.', 'status': 'error'})

    user_dir = os.path.join(USER_CERTS_PATH, user_name)
    os.makedirs(user_dir, exist_ok=True)

    key_file = os.path.join(user_dir, f"{user_name}.key")
    csr_file = os.path.join(user_dir, f"{user_name}.csr")
    cert_file = os.path.join(user_dir, f"{user_name}.crt")

    # Step 1: Generate private key
    run_command(f"openssl genpkey -algorithm RSA -out {key_file}")

    # Step 2: Create CSR
    run_command(f"openssl req -new -key {key_file} -out {csr_file} -subj \"/CN={user_name}\"")

    # Step 3: Sign CSR with Intermediate CA
    run_command(
        f"openssl ca -config {OPENSSL_CONFIG} "
        f"-in {csr_file} -batch "
        f"-cert {INTERMEDIATE_CA_CERT} -keyfile {INTERMEDIATE_CA_KEY}"
    )

    # Step 4: Copy the cert from newcerts/<serial>.pem
    # Use index.txt to find the last issued cert
    index_file = os.path.join(INTERMEDIATE_CA_PATH, 'index.txt')
    with open(index_file, 'r') as f:
        lines = f.readlines()

    # Get the last issued cert line
    cert_line = [line for line in lines if line.startswith('V')][-1]
    serial = cert_line.split('\t')[3].strip()
    issued_cert_path = os.path.join(INTERMEDIATE_CA_PATH, 'newcerts', f"{serial}.pem")

    if os.path.exists(issued_cert_path):
        shutil.copy(issued_cert_path, cert_file)
    else:
        return jsonify({
            'message': 'Cert was issued but not found in newcerts.',
            'status': 'error',
            'debug_serial': serial
        })

    return jsonify({
        'message': f'Certificate created for {user_name}',
        'status': 'success',
        'certificate_path': cert_file
    })



#Example usage of the download_certificate function
#curl -O http://127.0.0.1:5000/download_certificate/john_doe

@app.route('/download_certificate/<user_name>', methods=['GET'])
def download_certificate(user_name):
    user_dir = os.path.join(USER_CERTS_PATH, user_name)
    cert_file = os.path.join(user_dir, f"{user_name}.crt")
    if os.path.exists(cert_file):
        return send_from_directory(user_dir, f"{user_name}.crt", as_attachment=True)
    else:
        return jsonify({'message': f'Certificate for {user_name} not found.', 'status': 'error'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
