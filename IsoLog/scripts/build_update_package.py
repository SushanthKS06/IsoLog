#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.updates.bundle import UpdateBundle

def main():
    parser = argparse.ArgumentParser(description="Build IsoLog update package")
    
    parser.add_argument(
        "--rules",
        help="Path to Sigma rules directory",
        default=None,
    )
    parser.add_argument(
        "--models",
        help="Path to ML models directory",
        default=None,
    )
    parser.add_argument(
        "--mitre",
        help="Path to MITRE ATT&CK data",
        default=None,
    )
    parser.add_argument(
        "--intel",
        help="Path to threat intelligence data",
        default=None,
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output directory",
        default="./updates",
    )
    parser.add_argument(
        "--version",
        "-v",
        help="Version string for the update",
        default=None,
    )
    parser.add_argument(
        "--description",
        "-d",
        help="Description of the update",
        default="",
    )
    parser.add_argument(
        "--sign",
        help="Path to private key for signing",
        default=None,
    )
    
    args = parser.parse_args()
    
    if not any([args.rules, args.models, args.mitre, args.intel]):
        print("Error: At least one content type must be specified")
        print("Use --rules, --models, --mitre, or --intel")
        sys.exit(1)
    
    bundle = UpdateBundle()
    
    try:
        package_path = bundle.create(
            output_dir=args.output,
            sigma_rules_path=args.rules,
            models_path=args.models,
            mitre_path=args.mitre,
            intel_path=args.intel,
            version=args.version,
            description=args.description,
        )
        
        print(f"\n✓ Update package created: {package_path}")
        
        if args.sign:
            sign_package(package_path, args.sign)
        
    except Exception as e:
        print(f"Error creating package: {e}")
        sys.exit(1)

def sign_package(package_path: str, private_key_path: str):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        with open(package_path, "rb") as f:
            package_data = f.read()
        
        signature = private_key.sign(package_data)
        
        sig_path = package_path + ".sig"
        with open(sig_path, "wb") as f:
            f.write(signature)
        
        print(f"✓ Package signed: {sig_path}")
        
    except ImportError:
        print("Warning: cryptography not installed, skipping signature")
    except Exception as e:
        print(f"Warning: Failed to sign package: {e}")

if __name__ == "__main__":
    main()
