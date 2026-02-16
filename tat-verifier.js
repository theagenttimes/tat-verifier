/**
 * The Agent Times — Verifier SDK (JavaScript)
 * Verify article signatures, evidence bundles, and revision chains.
 *
 * Works in Node.js (18+) and modern browsers.
 *
 * Usage:
 *   import { TATVerifier } from './tat-verifier.js';
 *   const v = new TATVerifier();
 *   const result = await v.verifyArticle('commerce.html');
 *   console.log(result);
 */

const DEFAULT_PUBLIC_KEY_B64 = 'XSUnI/T3R7AgjKQjSXUeWM/RDSwR+BpQiY0oSd3ByDw=';
const DEFAULT_BASE_URL = 'https://theagenttimes.com';
const SIG_START = '<!-- TAT-SIGNATURE-START -->';
const SIG_END = '<!-- TAT-SIGNATURE-END -->';

// --- Crypto helpers ---

function b64ToBytes(b64) {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    return Uint8Array.from(bin, c => c.charCodeAt(0));
  }
  return Uint8Array.from(Buffer.from(b64, 'base64'));
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const crypto = globalThis.crypto || (await import('crypto')).webcrypto;
  const hash = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(hash));
}

async function importEd25519PublicKey(b64) {
  const keyBytes = b64ToBytes(b64);
  const crypto = globalThis.crypto || (await import('crypto')).webcrypto;
  return crypto.subtle.importKey(
    'raw', keyBytes,
    { name: 'Ed25519' },
    false, ['verify']
  );
}

async function verifyEd25519(publicKey, signatureB64, message) {
  const sigBytes = b64ToBytes(signatureB64);
  const msgBytes = new TextEncoder().encode(message);
  const crypto = globalThis.crypto || (await import('crypto')).webcrypto;
  try {
    return await crypto.subtle.verify('Ed25519', publicKey, sigBytes, msgBytes);
  } catch {
    return false;
  }
}

// --- HTML helpers ---

function stripSignatureBlock(html) {
  const pattern = new RegExp(
    `\\n?${escapeRegex(SIG_START)}[\\s\\S]*?${escapeRegex(SIG_END)}\\n?`, 'g'
  );
  return html.replace(pattern, '');
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractMeta(html, name) {
  const match = html.match(new RegExp(`name="${name}" content="([^"]+)"`));
  return match ? match[1] : null;
}

// --- Main Verifier ---

class TATVerifier {
  /**
   * @param {Object} opts
   * @param {string} opts.baseUrl - Base URL (default: https://theagenttimes.com)
   * @param {string} opts.publicKeyB64 - Ed25519 public key in base64
   */
  constructor(opts = {}) {
    this.baseUrl = (opts.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
    this.publicKeyB64 = opts.publicKeyB64 || DEFAULT_PUBLIC_KEY_B64;
    this._publicKey = null;
  }

  async _getPublicKey() {
    if (!this._publicKey) {
      this._publicKey = await importEd25519PublicKey(this.publicKeyB64);
    }
    return this._publicKey;
  }

  async _fetch(path) {
    const url = `${this.baseUrl}/${path.replace(/^\//, '')}`;
    try {
      const resp = await fetch(url);
      if (!resp.ok) return null;
      return await resp.text();
    } catch {
      return null;
    }
  }

  // --- Signature ---

  async verifySignature(html, filename = '') {
    const sigB64 = extractMeta(html, 'tat-signature');
    const storedHash = extractMeta(html, 'tat-content-hash');
    const signedAt = extractMeta(html, 'tat-signed-at');

    if (!sigB64 || !storedHash) {
      return { file: filename, status: 'UNSIGNED', reason: 'No signature meta tags found' };
    }

    const cleanHtml = stripSignatureBlock(html);
    const computedHash = await sha256(cleanHtml);

    if (computedHash !== storedHash) {
      return {
        file: filename, status: 'TAMPERED', contentHash: computedHash, signedAt,
        reason: `Content hash mismatch: expected ${storedHash.slice(0, 16)}..., got ${computedHash.slice(0, 16)}...`
      };
    }

    const pubKey = await this._getPublicKey();
    const valid = await verifyEd25519(pubKey, sigB64, storedHash);

    if (!valid) {
      return {
        file: filename, status: 'TAMPERED', contentHash: computedHash, signedAt,
        reason: 'Ed25519 signature verification failed'
      };
    }

    return { file: filename, status: 'VERIFIED', contentHash: computedHash, signedAt };
  }

  // --- Evidence Bundle ---

  async verifyEvidenceBundle(bundleData) {
    const bundle = bundleData.bundle || {};
    const integrity = bundleData.integrity || {};
    const article = bundle.article || 'unknown';

    if (!integrity.hash || !integrity.signature) {
      return { article, status: 'ERROR', reason: 'No integrity block' };
    }

    const bundleJson = JSON.stringify(bundle, null, 2);
    const computedHash = await sha256(bundleJson);

    if (computedHash !== integrity.hash) {
      return { article, status: 'TAMPERED', reason: 'Bundle hash mismatch' };
    }

    const pubKey = await this._getPublicKey();
    const valid = await verifyEd25519(pubKey, integrity.signature, computedHash);

    if (!valid) {
      return { article, status: 'TAMPERED', reason: 'Bundle signature verification failed' };
    }

    const conf = bundle.confidence_breakdown || {};
    return {
      article, status: 'VERIFIED',
      totalClaims: bundle.total_claims || 0,
      confirmed: conf.CONFIRMED || 0,
      reported: conf.REPORTED || 0,
      estimated: conf.ESTIMATED || 0,
      bundleHash: computedHash
    };
  }

  // --- Revision Chain ---

  async verifyChain(logData) {
    const article = logData.article || 'unknown';
    const revisions = logData.revisions || [];

    if (revisions.length === 0) {
      return { article, status: 'ERROR', reason: 'No revisions found' };
    }

    const pubKey = await this._getPublicKey();

    for (let i = 0; i < revisions.length; i++) {
      const rev = revisions[i];

      // Reconstruct entry for hashing
      const entryData = {
        content_hash: rev.content_hash,
        previous_hash: rev.previous_hash,
        reason: rev.reason,
        revision: rev.revision,
        timestamp: rev.timestamp,
        type: rev.type,
      };
      const canonical = JSON.stringify(entryData); // keys already sorted alphabetically
      const computedHash = await sha256(canonical);

      if (computedHash !== rev.entry_hash) {
        return {
          article, status: 'BROKEN', totalRevisions: revisions.length,
          reason: `Revision ${rev.revision}: entry hash mismatch`
        };
      }

      // Verify chain link
      if (i === 0) {
        if (rev.previous_hash !== 'GENESIS') {
          return { article, status: 'BROKEN', reason: 'Genesis entry has incorrect previous_hash' };
        }
      } else {
        if (rev.previous_hash !== revisions[i - 1].entry_hash) {
          return {
            article, status: 'BROKEN',
            reason: `Revision ${rev.revision}: chain link broken`
          };
        }
      }

      // Verify signature
      const valid = await verifyEd25519(pubKey, rev.signature, rev.entry_hash);
      if (!valid) {
        return {
          article, status: 'BROKEN',
          reason: `Revision ${rev.revision}: signature invalid`
        };
      }
    }

    const latest = revisions[revisions.length - 1];
    return {
      article, status: 'INTACT',
      totalRevisions: revisions.length,
      latestRevision: latest.revision,
      latestTimestamp: latest.timestamp
    };
  }

  // --- Full Article ---

  async verifyArticle(filename) {
    const result = { article: filename, signature: null, evidence: null, chain: null, overall: 'UNKNOWN' };
    const statuses = [];

    // 1. Signature
    const html = await this._fetch(filename);
    if (html) {
      result.signature = await this.verifySignature(html, filename);
      statuses.push(result.signature.status);
    } else {
      result.signature = { file: filename, status: 'ERROR', reason: 'Could not fetch article' };
      statuses.push('ERROR');
    }

    // 2. Evidence
    const bundleName = filename.replace('.html', '-evidence.json');
    const bundleText = await this._fetch(`trust/evidence/${bundleName}`);
    if (bundleText) {
      try {
        result.evidence = await this.verifyEvidenceBundle(JSON.parse(bundleText));
        statuses.push(result.evidence.status);
      } catch {
        result.evidence = { article: filename, status: 'ERROR', reason: 'Invalid JSON' };
        statuses.push('ERROR');
      }
    }

    // 3. Chain
    const revName = filename.replace('.html', '-revisions.json');
    const revText = await this._fetch(`trust/revisions/${revName}`);
    if (revText) {
      try {
        result.chain = await this.verifyChain(JSON.parse(revText));
        statuses.push(result.chain.status === 'INTACT' ? 'VERIFIED' : result.chain.status);
      } catch {
        result.chain = { article: filename, status: 'ERROR', reason: 'Invalid JSON' };
        statuses.push('ERROR');
      }
    }

    // Overall
    if (statuses.every(s => s === 'VERIFIED' || s === 'INTACT')) {
      result.overall = 'VERIFIED';
    } else if (statuses.some(s => s === 'TAMPERED' || s === 'BROKEN')) {
      result.overall = 'FAILED';
    } else if (statuses.some(s => s === 'ERROR')) {
      result.overall = 'ERROR';
    } else {
      result.overall = 'PARTIAL';
    }

    return result;
  }

  async verifyAll() {
    const manifestText = await this._fetch('trust/signatures.json');
    if (!manifestText) return [];

    const manifest = JSON.parse(manifestText);
    const results = [];
    for (const entry of manifest.files || []) {
      results.push(await this.verifyArticle(entry.file));
    }
    return results;
  }
}

// Export for Node.js and ES modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TATVerifier };
}
export { TATVerifier };
