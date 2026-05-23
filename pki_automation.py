import os
import subprocess
import uuid
import time
from datetime import datetime

# ==============================
# CONFIGURATION
# ==============================

OPENSSL = r"Enter your openssl path here"

BASE = r"Enter your base path folder here (pki)"
ROOT_CA = os.path.join(BASE, "rootCA")
ISSUING_CA = os.path.join(BASE, "issuingCA")

ROOT_CERT = os.path.join(ROOT_CA, "certs", "root.crt")
ROOT_KEY = os.path.join(ROOT_CA, "private", "root.key")

ISSUING_CERT = os.path.join(ISSUING_CA, "certs", "issuing.crt")
ISSUING_KEY = os.path.join(ISSUING_CA, "private", "issuing.key")

OPENSSL_CNF = os.path.join(ISSUING_CA, "openssl.cnf")
CERT_DIR = os.path.join(ISSUING_CA, "certs")

# ==============================
# CERTIFICATE PROFILES
# ==============================

CERT_PROFILES = {
    "1": {"name": "Web Server", "eku": "serverAuth", "key_usage": "digitalSignature,keyEncipherment"},
    "2": {"name": "Client/User", "eku": "clientAuth", "key_usage": "digitalSignature"},
    "3": {"name": "Email", "eku": "emailProtection", "key_usage": "digitalSignature,keyEncipherment"},
    "4": {"name": "Code Signing", "eku": "codeSigning", "key_usage": "digitalSignature"}
}

# ==============================
# RUN COMMAND
# ==============================

def run(cmd):
    print("\nRunning:", cmd)
    result = subprocess.run(cmd, shell=True)
    return result.returncode == 0

# ==============================
# SETUP
# ==============================

def setup():

    os.makedirs(os.path.join(ROOT_CA, "certs"), exist_ok=True)
    os.makedirs(os.path.join(ROOT_CA, "private"), exist_ok=True)

    os.makedirs(os.path.join(ISSUING_CA, "certs"), exist_ok=True)
    os.makedirs(os.path.join(ISSUING_CA, "private"), exist_ok=True)
    os.makedirs(os.path.join(ISSUING_CA, "crl"), exist_ok=True)
    os.makedirs(os.path.join(ISSUING_CA, "csr"), exist_ok=True)

    open(os.path.join(ISSUING_CA, "index.txt"), "a").close()

    if not os.path.exists(os.path.join(ISSUING_CA, "serial")):
        with open(os.path.join(ISSUING_CA, "serial"), "w") as f:
            f.write("1000")

    if not os.path.exists(os.path.join(ISSUING_CA, "crlnumber")):
        with open(os.path.join(ISSUING_CA, "crlnumber"), "w") as f:
            f.write("1000")

# ==============================
# ROOT CA
# ==============================

def create_root():

    run(f'"{OPENSSL}" genrsa -out "{ROOT_KEY}" 4096')

    run(f'"{OPENSSL}" req -x509 -new -nodes -key "{ROOT_KEY}" '
        f'-sha256 -days 3650 -out "{ROOT_CERT}" '
        f'-subj "/CN=MyRootCA"')

    print("✅ Root CA Created")

# ==============================
# ISSUING CA
# ==============================

def create_issuing():

    csr = os.path.join(ISSUING_CA, "csr", "issuing.csr")

    run(f'"{OPENSSL}" genrsa -out "{ISSUING_KEY}" 4096')

    run(f'"{OPENSSL}" req -new -key "{ISSUING_KEY}" '
        f'-out "{csr}" -subj "/CN=MyIssuingCA"')

    run(f'"{OPENSSL}" x509 -req -in "{csr}" '
        f'-CA "{ROOT_CERT}" -CAkey "{ROOT_KEY}" '
        f'-CAcreateserial -out "{ISSUING_CERT}" '
        f'-days 1825 -sha256')

    print("✅ Issuing CA Created")

# ==============================
# ISSUE CERTIFICATE
# ==============================

def issue_certificate():

    print("\nSelect Certificate Type:")
    for k, v in CERT_PROFILES.items():
        print(f"{k}. {v['name']}")

    choice = input("Enter choice: ")
    profile = CERT_PROFILES.get(choice)

    if not profile:
        print("Invalid choice")
        return

    cn = input("Enter Common Name: ")

    uid = str(uuid.uuid4())

    key = os.path.join(ISSUING_CA, "private", f"{uid}.key")
    csr = os.path.join(ISSUING_CA, "csr", f"{uid}.csr")
    cert = os.path.join(ISSUING_CA, "certs", f"{uid}.crt")
    ext = os.path.join(ISSUING_CA, f"{uid}_ext.cnf")

    run(f'"{OPENSSL}" genrsa -out "{key}" 2048')

    run(f'"{OPENSSL}" req -new -key "{key}" '
        f'-out "{csr}" -subj "/CN={cn}"')

    with open(ext, "w") as f:
        f.write(f"""
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = {profile['key_usage']}
extendedKeyUsage = {profile['eku']}
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = {cn}
""")

    run(
        f'"{OPENSSL}" ca -batch -config "{OPENSSL_CNF}" '
        f'-in "{csr}" -out "{cert}" '
        f'-extensions v3_req -extfile "{ext}" '
        f'-days 365'   #for testing pupose use -days 1 to show the certificate is invalid
    )

    print("✅ Certificate Issued:", cert)

# ==============================
# REVOKE CERTIFICATE
# ==============================

def revoke_certificate():

    cert = input("Enter certificate filename: ").strip()

    cert_path = os.path.join(ISSUING_CA, "certs", cert)

    # Check if file exists
    if not os.path.exists(cert_path):
        print("❌ Certificate file not found")
        return

    print("\n🔄 Revoking Certificate...\n")

    # Revoke certificate
    revoke_cmd = (
        f'"{OPENSSL}" ca -config "{OPENSSL_CNF}" '
        f'-revoke "{cert_path}"'
    )

    if not run(revoke_cmd):
        print("❌ Revocation Failed")
        return

    # Generate CRL
    crl_cmd = (
        f'"{OPENSSL}" ca -config "{OPENSSL_CNF}" '
        f'-gencrl -out "{ISSUING_CA}\\crl\\ca.crl"'
    )

    if not run(crl_cmd):
        print("❌ CRL Generation Failed")
        return

    # Verify revocation inside index.txt

index_file = os.path.join(ISSUING_CA, "index.txt")

with open(index_file, "r") as f:

    revoked_entries = [line for line in f if line.startswith("R")]

if revoked_entries:
    print("✅ Certificate Successfully Revoked and Stored in index.txt")
else:
    print("⚠ No revoked certificates found in index.txt")

# ==============================
# VERIFY CERTIFICATE
# ==============================

def verify_certificate():

    cert = input("Enter certificate filename: ")
    cert_path = os.path.join(ISSUING_CA, "certs", cert)

    run(f'"{OPENSSL}" verify -CAfile "{ROOT_CERT}" '
        f'-untrusted "{ISSUING_CERT}" "{cert_path}"')


# ==============================
# GET CN FROM CERT
# ==============================

def get_cert_cn(cert_path):

    try:
        cmd = f'"{OPENSSL}" x509 -in "{cert_path}" -noout -subject'
        out = subprocess.check_output(cmd, shell=True).decode()

        if "CN=" in out:
            return out.split("CN=")[-1].strip()

    except:
        return None

    return None

# ==============================
# SHOW REVOKED FROM INDEX
# ==============================

def show_revoked():

    index_file = os.path.join(ISSUING_CA, "index.txt")

    print("\n📄 Revoked Certificates:\n")

    revoked = []

    # Read revoked entries
    with open(index_file, "r") as f:
        for line in f:
            if line.startswith("R"):
                revoked.append(line.split("\t")[-1].strip())

    # Check only .crt files (IMPORTANT FIX)
    for cert_file in os.listdir(CERT_DIR):

        if not cert_file.endswith(".crt"):   # ✅ FIX HERE
            continue

        cert_path = os.path.join(CERT_DIR, cert_file)

        try:
            cn = get_cert_cn(cert_path)
        except:
            continue   # skip invalid files

        for r in revoked:
            if cn and cn in r:
                print(f"🔴 {cert_file} → {cn}")

# ==============================
# MENU
# ==============================

def menu():

    setup()

    while True:

        print("\n====== PKI MENU ======")
        print("1 Root CA")
        print("2 Issuing CA")
        print("3 Issue Certificate")
        print("4 Revoke Certificate")
        print("5 Verify Certificate")
        print("6 Show Revoked (index.txt)")
        print("7 Exit")

        c = input("Choice: ")

        if c == "1": create_root()
        elif c == "2": create_issuing()
        elif c == "3": issue_certificate()
        elif c == "4": revoke_certificate()
        elif c == "5": verify_certificate()
        elif c == "6": show_revoked()
        elif c == "7": break
        else: print("Invalid option")

# ==============================

if __name__ == "__main__":
    menu()
