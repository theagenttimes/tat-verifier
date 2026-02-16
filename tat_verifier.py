"""
The Agent Times — Verifier SDK (Python)
Verify article signatures, evidence bundles, and revision chains.

Install: pip install cryptography httpx
Usage:
    from tat_verifier import TATVerifier
    v = TATVerifier()
    result = v.verify_article("https://theagenttimes.com/commerce.html")
    print(result)
"""

import hashlib
import base64
import json
import re
from dataclasses import dataclass, field
from typing import Optional

try:
    import httpx
except ImportError:
    httpx = None

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    Ed25519PublicKey = None
    serialization = None


__version__ = "1.0.0"

# Default public key (The Agent Times Ed25519)
DEFAULT_PUBLIC_KEY_B64 = "XSUnI/T3R7AgjKQjSXUeWM/RDSwR+BpQiY0oSd3ByDw="
DEFAULT_BASE_URL = "https://theagenttimes.com"

SIGNATURE_BLOCK_START = "<!-- TAT-SIGNATURE-START -->"
SIGNATURE_BLOCK_END = "<!-- TAT-SIGNATURE-END -->"


@dataclass
class SignatureResult:
    """Result of verifying an article's cryptographic signature."""
    file: str
    status: str  # VERIFIED | TAMPERED | UNSIGNED | ERROR
    content_hash: Optional[str] = None
    signed_at: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class EvidenceResult:
    """Result of verifying an evidence bundle."""
    article: str
    status: str  # VERIFIED | TAMPERED | ERROR
    total_claims: int = 0
    confirmed: int = 0
    reported: int = 0
    estimated: int = 0
    bundle_hash: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class ChainResult:
    """Result of verifying a revision chain."""
    article: str
    status: str  # INTACT | BROKEN | ERROR
    total_revisions: int = 0
    latest_revision: int = 0
    latest_timestamp: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class FullVerification:
    """Complete verification result for an article."""
    article: str
    signature: Optional[SignatureResult] = None
    evidence: Optional[EvidenceResult] = None
    chain: Optional[ChainResult] = None
    overall: str = "UNKNOWN"  # VERIFIED | PARTIAL | FAILED | ERROR

    def to_dict(self) -> dict:
        d = {"article": self.article, "overall": self.overall}
        if self.signature:
            d["signature"] = {
                "status": self.signature.status,
                "content_hash": self.signature.content_hash,
                "signed_at": self.signature.signed_at,
            }
        if self.evidence:
            d["evidence"] = {
                "status": self.evidence.status,
                "total_claims": self.evidence.total_claims,
                "confirmed": self.evidence.confirmed,
                "reported": self.evidence.reported,
                "estimated": self.evidence.estimated,
            }
        if self.chain:
            d["chain"] = {
                "status": self.chain.status,
                "total_revisions": self.chain.total_revisions,
                "latest_revision": self.chain.latest_revision,
            }
        return d


class TATVerifier:
    """
    Verify The Agent Times articles, evidence bundles, and revision chains.

    Usage:
        v = TATVerifier()

        # Verify everything for one article
        result = v.verify_article("commerce.html")

        # Verify just the signature
        sig = v.verify_signature(html_content)

        # Verify an evidence bundle
        ev = v.verify_evidence_bundle(bundle_json)

        # Verify a revision chain
        chain = v.verify_chain(revisions_json)
    """

    def __init__(self, base_url: str = DEFAULT_BASE_URL, public_key_b64: str = DEFAULT_PUBLIC_KEY_B64):
        self.base_url = base_url.rstrip("/")
        self.public_key_b64 = public_key_b64

        if Ed25519PublicKey and serialization:
            raw_key = base64.b64decode(public_key_b64)
            self.public_key = Ed25519PublicKey.from_public_bytes(raw_key)
        else:
            self.public_key = None

    def _fetch(self, path: str) -> Optional[str]:
        """Fetch a URL. Returns text or None."""
        if not httpx:
            raise ImportError("httpx is required for remote verification. Install: pip install httpx")
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            resp = httpx.get(url, timeout=15, follow_redirects=True)
            resp.raise_for_status()
            return resp.text
        except Exception:
            return None

    def _strip_signature_block(self, html: str) -> str:
        """Remove signature block from HTML for hashing."""
        pattern = re.compile(
            rf"\n?{re.escape(SIGNATURE_BLOCK_START)}.*?{re.escape(SIGNATURE_BLOCK_END)}\n?",
            re.DOTALL,
        )
        return pattern.sub("", html)

    def _extract_meta(self, html: str, name: str) -> Optional[str]:
        """Extract a tat-* meta tag value from HTML."""
        match = re.search(rf'name="{name}" content="([^"]+)"', html)
        return match.group(1) if match else None

    def _verify_ed25519(self, signature_b64: str, message: str) -> bool:
        """Verify an Ed25519 signature."""
        if not self.public_key:
            raise ImportError("cryptography is required for signature verification. Install: pip install cryptography")
        try:
            sig_bytes = base64.b64decode(signature_b64)
            self.public_key.verify(sig_bytes, message.encode("utf-8"))
            return True
        except Exception:
            return False

    # ─── Signature Verification ───

    def verify_signature(self, html: str, filename: str = "") -> SignatureResult:
        """Verify the Ed25519 signature embedded in an HTML article."""
        sig_b64 = self._extract_meta(html, "tat-signature")
        stored_hash = self._extract_meta(html, "tat-content-hash")
        signed_at = self._extract_meta(html, "tat-signed-at")

        if not sig_b64 or not stored_hash:
            return SignatureResult(file=filename, status="UNSIGNED", reason="No signature meta tags found")

        # Compute content hash
        clean_html = self._strip_signature_block(html)
        computed_hash = hashlib.sha256(clean_html.encode("utf-8")).hexdigest()

        if computed_hash != stored_hash:
            return SignatureResult(
                file=filename, status="TAMPERED",
                content_hash=computed_hash, signed_at=signed_at,
                reason=f"Content hash mismatch: expected {stored_hash[:16]}..., got {computed_hash[:16]}..."
            )

        # Verify cryptographic signature
        if not self._verify_ed25519(sig_b64, stored_hash):
            return SignatureResult(
                file=filename, status="TAMPERED",
                content_hash=computed_hash, signed_at=signed_at,
                reason="Ed25519 signature verification failed"
            )

        return SignatureResult(
            file=filename, status="VERIFIED",
            content_hash=computed_hash, signed_at=signed_at
        )

    # ─── Evidence Bundle Verification ───

    def verify_evidence_bundle(self, bundle_data: dict) -> EvidenceResult:
        """Verify a signed evidence bundle."""
        bundle = bundle_data.get("bundle", {})
        integrity = bundle_data.get("integrity", {})
        article = bundle.get("article", "unknown")

        if not integrity:
            return EvidenceResult(article=article, status="ERROR", reason="No integrity block")

        # Verify bundle hash
        bundle_json = json.dumps(bundle, indent=2, ensure_ascii=False)
        computed_hash = hashlib.sha256(bundle_json.encode("utf-8")).hexdigest()

        if computed_hash != integrity.get("hash"):
            return EvidenceResult(
                article=article, status="TAMPERED",
                reason="Bundle hash mismatch"
            )

        # Verify signature
        sig_b64 = integrity.get("signature", "")
        if not self._verify_ed25519(sig_b64, computed_hash):
            return EvidenceResult(
                article=article, status="TAMPERED",
                reason="Bundle signature verification failed"
            )

        conf = bundle.get("confidence_breakdown", {})
        return EvidenceResult(
            article=article, status="VERIFIED",
            total_claims=bundle.get("total_claims", 0),
            confirmed=conf.get("CONFIRMED", 0),
            reported=conf.get("REPORTED", 0),
            estimated=conf.get("ESTIMATED", 0),
            bundle_hash=computed_hash
        )

    # ─── Revision Chain Verification ───

    def verify_chain(self, log_data: dict) -> ChainResult:
        """Verify a revision chain's integrity."""
        article = log_data.get("article", "unknown")
        revisions = log_data.get("revisions", [])

        if not revisions:
            return ChainResult(article=article, status="ERROR", reason="No revisions found")

        for i, rev in enumerate(revisions):
            # Reconstruct entry for hashing
            entry_data = {
                "revision": rev["revision"],
                "timestamp": rev["timestamp"],
                "content_hash": rev["content_hash"],
                "previous_hash": rev["previous_hash"],
                "reason": rev["reason"],
                "type": rev["type"],
            }
            canonical = json.dumps(entry_data, sort_keys=True, ensure_ascii=False)
            computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            if computed_hash != rev.get("entry_hash"):
                return ChainResult(
                    article=article, status="BROKEN",
                    total_revisions=len(revisions),
                    reason=f"Revision {rev['revision']}: entry hash mismatch"
                )

            # Verify chain link
            if i == 0:
                if rev["previous_hash"] != "GENESIS":
                    return ChainResult(
                        article=article, status="BROKEN",
                        reason="Genesis entry has incorrect previous_hash"
                    )
            else:
                if rev["previous_hash"] != revisions[i - 1]["entry_hash"]:
                    return ChainResult(
                        article=article, status="BROKEN",
                        reason=f"Revision {rev['revision']}: chain link broken"
                    )

            # Verify signature
            sig_b64 = rev.get("signature", "")
            if not self._verify_ed25519(sig_b64, rev["entry_hash"]):
                return ChainResult(
                    article=article, status="BROKEN",
                    reason=f"Revision {rev['revision']}: signature invalid"
                )

        latest = revisions[-1]
        return ChainResult(
            article=article, status="INTACT",
            total_revisions=len(revisions),
            latest_revision=latest["revision"],
            latest_timestamp=latest["timestamp"]
        )

    # ─── Full Article Verification ───

    def verify_article(self, filename: str) -> FullVerification:
        """
        Verify everything about an article: signature, evidence bundle, and revision chain.
        Fetches data from the configured base_url.
        """
        result = FullVerification(article=filename)
        statuses = []

        # 1. Verify signature
        html = self._fetch(filename)
        if html:
            result.signature = self.verify_signature(html, filename)
            statuses.append(result.signature.status)
        else:
            result.signature = SignatureResult(file=filename, status="ERROR", reason="Could not fetch article")
            statuses.append("ERROR")

        # 2. Verify evidence bundle
        bundle_name = filename.replace(".html", "-evidence.json")
        bundle_text = self._fetch(f"trust/evidence/{bundle_name}")
        if bundle_text:
            try:
                bundle_data = json.loads(bundle_text)
                result.evidence = self.verify_evidence_bundle(bundle_data)
                statuses.append(result.evidence.status)
            except json.JSONDecodeError:
                result.evidence = EvidenceResult(article=filename, status="ERROR", reason="Invalid JSON")
                statuses.append("ERROR")

        # 3. Verify revision chain
        rev_name = filename.replace(".html", "-revisions.json")
        rev_text = self._fetch(f"trust/revisions/{rev_name}")
        if rev_text:
            try:
                rev_data = json.loads(rev_text)
                result.chain = self.verify_chain(rev_data)
                chain_status = "VERIFIED" if result.chain.status == "INTACT" else result.chain.status
                statuses.append(chain_status)
            except json.JSONDecodeError:
                result.chain = ChainResult(article=filename, status="ERROR", reason="Invalid JSON")
                statuses.append("ERROR")

        # Overall status
        if all(s in ("VERIFIED", "INTACT") for s in statuses):
            result.overall = "VERIFIED"
        elif any(s in ("TAMPERED", "BROKEN") for s in statuses):
            result.overall = "FAILED"
        elif any(s == "ERROR" for s in statuses):
            result.overall = "ERROR"
        else:
            result.overall = "PARTIAL"

        return result

    def verify_all(self) -> list:
        """Verify all articles listed in the signatures manifest."""
        manifest_text = self._fetch("trust/signatures.json")
        if not manifest_text:
            return []

        manifest = json.loads(manifest_text)
        results = []
        for entry in manifest.get("files", []):
            result = self.verify_article(entry["file"])
            results.append(result)
        return results


# ─── CLI ───

def main():
    import sys

    if len(sys.argv) < 2:
        print("TAT Verifier SDK v" + __version__)
        print()
        print("Usage:")
        print("  python tat_verifier.py verify <url_or_filename>")
        print("  python tat_verifier.py verify-all")
        print("  python tat_verifier.py verify-all --base-url https://theagenttimes.com")
        print()
        print("Examples:")
        print("  python tat_verifier.py verify commerce.html")
        print("  python tat_verifier.py verify-all")
        return

    cmd = sys.argv[1]

    base_url = DEFAULT_BASE_URL
    for i, arg in enumerate(sys.argv):
        if arg == "--base-url" and i + 1 < len(sys.argv):
            base_url = sys.argv[i + 1]

    v = TATVerifier(base_url=base_url)

    if cmd == "verify":
        filename = sys.argv[2] if len(sys.argv) > 2 else "index.html"
        result = v.verify_article(filename)
        print(json.dumps(result.to_dict(), indent=2))

    elif cmd == "verify-all":
        results = v.verify_all()
        for r in results:
            icon = {"VERIFIED": "✅", "FAILED": "🚨", "ERROR": "⚠️", "PARTIAL": "🟡"}.get(r.overall, "❓")
            sig = r.signature.status if r.signature else "—"
            ev = r.evidence.status if r.evidence else "—"
            ch = r.chain.status if r.chain else "—"
            print(f"  {icon} {r.article}: {r.overall}  (sig:{sig} ev:{ev} chain:{ch})")

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
