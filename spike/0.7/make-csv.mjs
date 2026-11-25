// Writes a synthetic CSV of a given size for the 0.7 timing runs: seeded, so the same size gives the same bytes, with no
// personal data. A mix of numeric, categorical, date and free-text columns.
//
//   node spike/0.7/make-csv.mjs <GiB> <output path> [seed]
//
// Prints the file's size in bytes, its row count and its SHA-256.
import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { once } from 'node:events';

const [gib, output, seedText = '7'] = process.argv.slice(2);
const targetBytes = Math.round(Number(gib) * 1024 ** 3);
if (!(targetBytes > 0) || !output) {
  console.error('usage: node make-csv.mjs <GiB> <output path> [seed]');
  process.exit(2);
}

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const random = mulberry32(Number(seedText));
const CITIES = ['Denver', 'Austin', 'Boston', 'Seattle', 'Chicago', 'Miami', 'Phoenix', 'Portland', 'Atlanta', 'Dallas'];
const PLANS = ['basic', 'plus', 'pro', 'team'];
const WORDS = ['alpha', 'bravo', 'delta', 'echo', 'kilo', 'lima', 'omega', 'sigma', 'tango', 'zulu'];
const pick = (list) => list[Math.floor(random() * list.length)];

const hash = createHash('sha256');
const stream = createWriteStream(output);
let bytes = 0;
let rows = 0;
let buffer = '';

async function write(text) {
  const chunk = Buffer.from(text);
  hash.update(chunk);
  bytes += chunk.length;
  if (!stream.write(chunk)) await once(stream, 'drain');
}

await write('id,age,income,city,plan,signup_date,rating,notes\n');
while (bytes < targetBytes) {
  const day = 1 + Math.floor(random() * 28);
  const month = 1 + Math.floor(random() * 12);
  const note = `${pick(WORDS)} ${pick(WORDS)} ${Math.floor(random() * 1000)}`;
  buffer += `${rows},${18 + Math.floor(random() * 70)},${(20000 + random() * 180000).toFixed(2)},${pick(CITIES)},${pick(PLANS)},` +
    `20${String(10 + Math.floor(random() * 15))}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')},` +
    `${1 + Math.floor(random() * 5)},${note}\n`;
  rows += 1;
  if (buffer.length > 1 << 20) {
    await write(buffer);
    buffer = '';
  }
}
if (buffer) await write(buffer);
stream.end();
await once(stream, 'finish');
console.log(JSON.stringify({ path: output, bytes, rows, sha256: hash.digest('hex') }));
