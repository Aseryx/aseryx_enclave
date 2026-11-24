// Reads the SEV-SNP firmware versions from an Azure Attestation token after checking that Microsoft signed it.
// This only reports: it never gates a key. The workload identity and runtime data are the ones the watch deployed.
//
// Usage: node verify.mjs <token file> <expected hostdata hex> <runtime data base64>
// Prints one JSON line: {"chipFamily","snpfw","microcode","bootloader","tee"}.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const ISSUER = 'https://sharedeus.eus.attest.azure.net';
export const MAX_AGE_SECONDS = 600;

const claimOf = (claims, name) => claims[`x-ms-sevsnpvm-${name}`];

// Returns the firmware versions of a token, or throws with the reason it was refused.
export function readTcb(token, { keys, expectedHostdata, runtimeData, now }) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('not a JWT');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  if (header.alg !== 'RS256') throw new Error('not RS256');
  const jwk = keys.find((key) => key.kid === header.kid && key.kty === 'RSA');
  if (!jwk) throw new Error('unknown signing key');
  const publicKey = createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: 'jwk' });
  if (!verify('sha256', Buffer.from(`${parts[0]}.${parts[1]}`), publicKey, Buffer.from(parts[2], 'base64url'))) {
    throw new Error('bad signature');
  }
  if (claims.iss !== ISSUER) throw new Error('wrong issuer');
  if (!(claims.exp > now) || !(claims.iat <= now + 60) || now - claims.iat > MAX_AGE_SECONDS) throw new Error('not fresh');
  if (claims['x-ms-attestation-type'] !== 'sevsnpvm') throw new Error('not SEV-SNP');
  if (String(claimOf(claims, 'hostdata')).toLowerCase() !== expectedHostdata.toLowerCase()) throw new Error('wrong workload identity');
  const reportdata = createHash('sha256').update(runtimeData).digest('hex') + '0'.repeat(64);
  if (claimOf(claims, 'reportdata') !== reportdata) throw new Error('runtime data not attested');
  const versions = {
    chipFamily: claimOf(claims, 'chip-family'),
    snpfw: claimOf(claims, 'snpfw-svn'),
    microcode: claimOf(claims, 'microcode-svn'),
    bootloader: claimOf(claims, 'bootloader-svn'),
    tee: claimOf(claims, 'tee-svn'),
  };
  const numbers = [versions.snpfw, versions.microcode, versions.bootloader, versions.tee];
  if (typeof versions.chipFamily !== 'string' || !numbers.every(Number.isInteger)) throw new Error('missing firmware versions');
  return versions;
}

async function main() {
  const [tokenFile, expectedHostdata, runtimeDataBase64] = process.argv.slice(2);
  const token = readFileSync(tokenFile, 'utf8').trim();
  const response = await fetch(`${ISSUER}/certs`, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`issuer keys: ${response.status}`);
  const { keys } = await response.json();
  const versions = readTcb(token, {
    keys,
    expectedHostdata,
    runtimeData: Buffer.from(runtimeDataBase64, 'base64'),
    now: Math.floor(Date.now() / 1000),
  });
  console.log(JSON.stringify(versions));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`verify failed: ${error.message}`);
    process.exit(1);
  });
}
