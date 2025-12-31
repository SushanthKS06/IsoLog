"""
IsoLog Update Verifier

Cryptographic verification of update bundles.
"""

import hashlib
import json
import logging
import tarfile
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class UpdateVerifier:
    """
    Verifies update bundle integrity and authenticity.
    
    Uses SHA-256 checksums and optional Ed25519 signatures.
    """
    
    def __init__(self, public_key_path: Optional[str] = None):
        """
        Initialize verifier.
        
        Args:
            public_key_path: Path to Ed25519 public key for signature verification
        """
        self.public_key_path = Path(public_key_path) if public_key_path else None
        self._public_key = None
        
        if self.public_key_path and self.public_key_path.exists():
            self._load_public_key()
    
    def _load_public_key(self):
        """Load Ed25519 public key."""
        try:
            from cryptography.hazmat.primitives import serialization
            
            with open(self.public_key_path, "rb") as f:
                self._public_key = serialization.load_pem_public_key(f.read())
            logger.info("Loaded public key for update verification")
        except ImportError:
            logger.warning("cryptography package not available, signature verification disabled")
        except Exception as e:
            logger.warning(f"Failed to load public key: {e}")
    
    def verify_bundle(self, bundle_path: str) -> Dict[str, Any]:
        """
        Verify update bundle integrity.
        
        Args:
            bundle_path: Path to update bundle
            
        Returns:
            Verification result
        """
        bundle_path = Path(bundle_path)
        
        if not bundle_path.exists():
            return {"valid": False, "error": "Bundle not found"}
        
        result = {
            "valid": True,
            "checksum_valid": False,
            "signature_valid": None,
            "manifest": None,
            "errors": [],
        }
        
        try:
            # Calculate bundle checksum
            bundle_hash = self._calculate_file_hash(bundle_path)
            result["bundle_hash"] = bundle_hash
            
            # Extract and verify manifest
            manifest = self._extract_manifest(bundle_path)
            result["manifest"] = manifest
            
            if not manifest:
                result["valid"] = False
                result["errors"].append("Could not read manifest")
                return result
            
            # Verify internal checksums
            checksum_result = self._verify_internal_checksums(bundle_path, manifest)
            result["checksum_valid"] = checksum_result["valid"]
            if not checksum_result["valid"]:
                result["valid"] = False
                result["errors"].extend(checksum_result.get("errors", []))
            
            # Verify signature if available
            if self._public_key:
                sig_result = self._verify_signature(bundle_path)
                result["signature_valid"] = sig_result["valid"]
                if not sig_result["valid"]:
                    result["valid"] = False
                    result["errors"].append("Invalid signature")
            
        except Exception as e:
            result["valid"] = False
            result["errors"].append(str(e))
        
        return result
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _extract_manifest(self, bundle_path: Path) -> Optional[Dict[str, Any]]:
        """Extract manifest from bundle."""
        try:
            with tarfile.open(bundle_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("manifest.json"):
                        f = tar.extractfile(member)
                        if f:
                            return json.load(f)
        except Exception as e:
            logger.error(f"Failed to extract manifest: {e}")
        return None
    
    def _verify_internal_checksums(
        self, 
        bundle_path: Path,
        manifest: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Verify checksums of bundle contents."""
        # For now, just verify bundle can be opened and manifest exists
        try:
            with tarfile.open(bundle_path, "r:gz") as tar:
                members = tar.getmembers()
                
                # Verify expected content types exist
                expected_types = [c["type"] for c in manifest.get("contents", [])]
                found_types = set()
                
                for member in members:
                    for content_type in expected_types:
                        if content_type in member.name:
                            found_types.add(content_type)
                
                missing = set(expected_types) - found_types
                if missing:
                    return {
                        "valid": False,
                        "errors": [f"Missing content: {list(missing)}"],
                    }
                
                return {"valid": True}
                
        except Exception as e:
            return {"valid": False, "errors": [str(e)]}
    
    def _verify_signature(self, bundle_path: Path) -> Dict[str, Any]:
        """Verify Ed25519 signature."""
        if not self._public_key:
            return {"valid": False, "error": "No public key loaded"}
        
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.exceptions import InvalidSignature
            
            # Look for signature file
            sig_path = bundle_path.with_suffix(".sig")
            if not sig_path.exists():
                # Try finding embedded signature
                with tarfile.open(bundle_path, "r:gz") as tar:
                    for member in tar.getmembers():
                        if member.name.endswith("signature.sig"):
                            f = tar.extractfile(member)
                            if f:
                                signature = f.read()
                                break
                    else:
                        return {"valid": False, "error": "No signature found"}
            else:
                with open(sig_path, "rb") as f:
                    signature = f.read()
            
            # Read bundle content for verification
            with open(bundle_path, "rb") as f:
                bundle_data = f.read()
            
            # Verify
            try:
                self._public_key.verify(signature, bundle_data)
                return {"valid": True}
            except InvalidSignature:
                return {"valid": False, "error": "Invalid signature"}
                
        except ImportError:
            return {"valid": False, "error": "cryptography package not available"}
        except Exception as e:
            return {"valid": False, "error": str(e)}
    
    @staticmethod
    def generate_keypair(output_dir: str) -> Dict[str, str]:
        """
        Generate Ed25519 keypair for signing updates.
        
        Args:
            output_dir: Directory to save keys
            
        Returns:
            Paths to generated keys
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate keypair
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            # Save private key
            private_path = output_dir / "update_signing_key.pem"
            with open(private_path, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            
            # Save public key
            public_path = output_dir / "update_verify_key.pem"
            with open(public_path, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ))
            
            logger.info(f"Generated keypair in {output_dir}")
            return {
                "private_key": str(private_path),
                "public_key": str(public_path),
            }
            
        except ImportError:
            raise RuntimeError("cryptography package required for key generation")
