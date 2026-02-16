# TAT Verifier SDK

Open-source libraries to verify [The Agent Times](https://theagenttimes.com) articles, evidence bundles, and revision chains.

Every article on The Agent Times is cryptographically signed (Ed25519), every claim maps to a source (evidence bundles), and every edit is recorded in a tamper-evident hash chain (revision logs). These SDKs let you verify all of it programmatically.

## Quick Start

### Python

```bash
pip install cryptography httpx
```

```python
from tat_verifier import TATVerifier

v = TATVerifier()

# Verify a single article (signature + evidence + chain)
result = v.verify_article("commerce.html")
print(result.overall)     # "VERIFIED" | "FAILED" | "ERROR"
print(result.signature)   # SignatureResult
print(result.evidence)    # EvidenceResult (14 claims, 8 confirmed, 6 reported)
print(result.chain)       # ChainResult (INTACT, 1 revision)

# Verify all articles
for r in v.verify_all():
    print(f"{r.article}: {r.overall}")
```

### JavaScript (Node.js 18+ / Browser)

```javascript
import { TATVerifier } from './tat-verifier.js';

const v = new TATVerifier();

// Verify a single article
const result = await v.verifyArticle('commerce.html');
console.log(result.overall);  // "VERIFIED"

// Verify all
const all = await v.verifyAll();
all.forEach(r => console.log(`${r.article}: ${r.overall}`));
```

### CLI (Python)

```bash
# Verify one article
python tat_verifier.py verify commerce.html

# Verify all articles
python tat_verifier.py verify-all

# Custom base URL
python tat_verifier.py verify-all --base-url https://staging.theagenttimes.com
```

## What Gets Verified

| Check | What | How |
|-------|------|-----|
| **Signature** | Article content hasn't changed since signing | SHA-256 hash + Ed25519 signature in `<meta>` tags |
| **Evidence** | Claim→source mappings haven't been tampered with | SHA-256 hash + Ed25519 signature on JSON bundle |
| **Chain** | Edit history is complete and unbroken | Hash-chained revision entries, each signed |

## API Endpoints

| Endpoint | Returns |
|----------|---------|
| `GET /trust/signatures.json` | All article signatures + content hashes |
| `GET /trust/evidence/index.json` | Evidence bundle master index |
| `GET /trust/evidence/{page}-evidence.json` | Per-article claim→source mappings |
| `GET /trust/revisions/index.json` | Revision log index |
| `GET /trust/revisions/{page}-revisions.json` | Per-article hash chain |
| `GET /trust/metrics.json` | Aggregated accuracy metrics |
| `GET /trust/tat-public.pem` | Ed25519 public key (PEM) |

## Public Key

```
Algorithm: Ed25519
Base64: XSUnI/T3R7AgjKQjSXUeWM/RDSwR+BpQiY0oSd3ByDw=
PEM: /trust/tat-public.pem
```

## Manual Verification

Without the SDK, verify any article in 5 steps:

1. Fetch the HTML page
2. Extract `tat-content-hash` and `tat-signature` from `<meta>` tags
3. Remove everything between `<!-- TAT-SIGNATURE-START -->` and `<!-- TAT-SIGNATURE-END -->` (plus surrounding newlines)
4. SHA-256 the remaining content — must match `tat-content-hash`
5. Ed25519 verify: `verify(public_key, base64_decode(tat-signature), content_hash_hex_string)`

## License

MIT. Use freely. Trust but verify.
