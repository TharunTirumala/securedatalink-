"""Key generation script for SecureLink tactical datalink."""

import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_keys(target_dir: str | Path = "keys", force: bool = False):
    path = Path(target_dir)
    path.mkdir(parents=True, exist_ok=True)

    salt_file = path / "session_salt.bin"
    aes_file = path / "shared_aes256.key"
    master_file = path / "master.key"
    priv_file = path / "uav_sender_1_priv.pem"
    pub_file = path / "uav_sender_1_pub.pem"

    existing = [f for f in (salt_file, aes_file, master_file, priv_file, pub_file) if f.exists()]
    if existing and not force:
        print(f"Refusing to overwrite existing keys in '{target_dir}'. Use --force to overwrite.")
        return

    # 1. 4-byte session salt
    salt = os.urandom(4)
    salt_file.write_bytes(salt)
    print(f"Generated session salt (4B): {salt.hex()} -> {salt_file}")

    # 2. 32-byte Master Secret & AES-256 key
    master_secret = os.urandom(32)
    master_file.write_bytes(master_secret)
    aes_file.write_bytes(master_secret)
    print(f"Generated 32-byte master secret -> {master_file}")

    # 3. UAV Sender 1 ECDSA P-256 keypair
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_file.write_bytes(priv_pem)
    try:
        os.chmod(priv_file, 0o600)
    except OSError:
        pass  # Windows file systems may ignore POSIX chmod bits
    pub_file.write_bytes(pub_pem)
    print(f"Generated ECDSA P-256 keypair for Sender ID 1 -> {priv_file}, {pub_file}")


if __name__ == "__main__":
    force_flag = "--force" in sys.argv or "-f" in sys.argv
    args = [a for a in sys.argv[1:] if a not in ("--force", "-f")]
    out_dir = args[0] if args else "keys"
    generate_keys(out_dir, force=force_flag)

