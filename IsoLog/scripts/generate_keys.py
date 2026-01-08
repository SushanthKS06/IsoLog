#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

def generate_keypair(output_dir: str):
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        print("Error: cryptography package required. Install with: pip install cryptography")
        sys.exit(1)
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_path = output_path / "update_signing_key.pem"
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    print(f"Private key saved: {private_path}")
    print("⚠️  Keep this file secure! Do not commit to version control.")
    
    public_path = output_path / "update_verify_key.pem"
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    print(f"Public key saved: {public_path}")
    print("This key should be embedded in the application for verification.")
    
    print("\n--- Public Key (for embedding) ---")
    import base64
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print(f"Base64: {base64.b64encode(pub_bytes).decode()}")

def main():
    parser = argparse.ArgumentParser(description="Generate update signing keypair")
    parser.add_argument(
        "output_dir",
        nargs="?",
        default="./keys",
        help="Output directory for keys (default: ./keys)",
    )
    
    args = parser.parse_args()
    generate_keypair(args.output_dir)

if __name__ == "__main__":
    main()
