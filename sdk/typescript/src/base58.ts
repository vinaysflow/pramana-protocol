/**
 * Base58btc encoder/decoder — identical algorithm to Python identity.py.
 * Leading zero bytes encode as '1' characters (Bitcoin convention).
 */

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function b58Encode(data: Uint8Array): string {
  if (data.length === 0) return "";

  // Convert bytes to BigInt
  let n = BigInt(0);
  for (const byte of data) {
    n = n * BigInt(256) + BigInt(byte);
  }

  const result: string[] = [];
  while (n > BigInt(0)) {
    const r = Number(n % BigInt(58));
    n = n / BigInt(58);
    result.push(B58_ALPHABET[r]);
  }

  // Leading zero bytes become '1'
  for (const byte of data) {
    if (byte === 0) {
      result.push("1");
    } else {
      break;
    }
  }

  return result.reverse().join("");
}

export function b58Decode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);

  let n = BigInt(0);
  for (const char of s) {
    const idx = B58_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base58 character: '${char}'`);
    n = n * BigInt(58) + BigInt(idx);
  }

  // Count leading '1's → leading zero bytes
  let leadingZeros = 0;
  for (const char of s) {
    if (char === "1") leadingZeros++;
    else break;
  }

  // Convert BigInt back to bytes
  const hex = n.toString(16).padStart(2, "0");
  const padded = hex.length % 2 === 0 ? hex : "0" + hex;
  const bytes: number[] = [];
  for (let i = 0; i < padded.length; i += 2) {
    bytes.push(parseInt(padded.slice(i, i + 2), 16));
  }

  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(bytes, leadingZeros);
  return result;
}
