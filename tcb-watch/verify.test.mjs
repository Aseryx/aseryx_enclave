import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { ISSUER, readTcb } from './verify.mjs';

const fixture = (name) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8').trim();
const token = fixture('token.jwt');
const keys = JSON.parse(fixture('issuer-keys.json')).keys;
const hostdata = fixture('hostdata.txt');
const runtimeData = Buffer.from(fixture('runtime-data.b64'), 'base64');
const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
const options = (over = {}) => ({ keys, expectedHostdata: hostdata, runtimeData, now: claims.iat + 60, ...over });

test('a real East US token gives its firmware versions', () => {
  assert.deepEqual(readTcb(token, options()), { chipFamily: 'Genoa', snpfw: 23, microcode: 84, bootloader: 10, tee: 0 });
});

test('a real token is refused when it is stale, altered, for another identity or for other runtime data', () => {
  assert.throws(() => readTcb(token, options({ now: claims.iat + 601 })), /not fresh/);
  assert.throws(() => readTcb(token, options({ now: claims.iat - 61 })), /not fresh/);
  assert.throws(() => readTcb(token, options({ expectedHostdata: '0'.repeat(64) })), /workload identity/);
  assert.throws(() => readTcb(token, options({ runtimeData: Buffer.from('{}') })), /not attested/);
  assert.throws(() => readTcb(token, options({ keys: [] })), /unknown signing key/);
  const [h, , s] = token.split('.');
  const altered = Buffer.from(JSON.stringify({ ...claims, 'x-ms-sevsnpvm-snpfw-svn': 99 })).toString('base64url');
  assert.throws(() => readTcb(`${h}.${altered}.${s}`, options()), /bad signature/);
});

// A token signed by a test key, to reach the checks a real token cannot fail.
function signed(over, alg = 'RS256') {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  const reportdata = createHash('sha256').update(runtimeData).digest('hex') + '0'.repeat(64);
  const body = { ...claims, 'x-ms-sevsnpvm-reportdata': reportdata, ...over };
  const part = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const text = `${part({ alg, kid: 'k' })}.${part(body)}`;
  const signature = sign('sha256', Buffer.from(text), privateKey).toString('base64url');
  return { token: `${text}.${signature}`, keys: [{ kid: 'k', kty: 'RSA', n: jwk.n, e: jwk.e }] };
}

test('tokens with another issuer, platform, algorithm or missing versions are refused', () => {
  const run = (over, alg) => {
    const t = signed(over, alg);
    return () => readTcb(t.token, options({ keys: t.keys }));
  };
  const ok = signed({});
  assert.equal(readTcb(ok.token, options({ keys: ok.keys })).snpfw, 23);
  assert.throws(run({ exp: claims.iat + 30 }), /not fresh/);
  const other = signed({});
  assert.throws(() => readTcb(other.token, options({ keys: other.keys.map((key) => ({ ...key, kty: 'EC' })) })), /unknown signing key/);
  assert.throws(run({ iss: 'https://other.attest.azure.net' }), /wrong issuer/);
  assert.throws(run({ 'x-ms-attestation-type': 'tpm' }), /not SEV-SNP/);
  assert.throws(run({}, 'HS256'), /not RS256/);
  assert.throws(run({ 'x-ms-sevsnpvm-snpfw-svn': '23' }), /missing firmware versions/);
  assert.throws(run({ 'x-ms-sevsnpvm-chip-family': undefined }), /missing firmware versions/);
  assert.equal(ISSUER, claims.iss);
});
