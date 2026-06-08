/**
 * Sibna Protocol v3.0.1 — Safety Numbers (JavaScript)
 */

import { sha512Hash, hmacSha256 } from './crypto';

export class SafetyNumber {
  readonly digits: string;
  readonly fingerprint: Uint8Array;
  readonly version: number;

  static readonly VERSION = 1;

  private constructor(digits: string, fingerprint: Uint8Array, version = 1) {
    this.digits = digits;
    this.fingerprint = fingerprint;
    this.version = version;
  }

  static calculate(ourIdentity: Uint8Array, theirIdentity: Uint8Array): SafetyNumber {
    const [first, second] = compareBytes(ourIdentity, theirIdentity)
      ? [ourIdentity, theirIdentity]
      : [theirIdentity, ourIdentity];

    const hasher = new Uint8Array([
      SafetyNumber.VERSION,
      ...new TextEncoder().encode('SIBNA_SAFETY_NUMBER_V1'),
      ...first,
      ...second,
    ]);
    const hash = sha512Hash(hasher);
    const fingerprint = hash.slice(0, 32);
    const digits = bytesToDigits(fingerprint);

    return new SafetyNumber(digits, fingerprint);
  }

  static calculateWithExtra(
    ourIdentity: Uint8Array, theirIdentity: Uint8Array, extraData: Uint8Array,
  ): SafetyNumber {
    const [first, second] = compareBytes(ourIdentity, theirIdentity)
      ? [ourIdentity, theirIdentity]
      : [theirIdentity, ourIdentity];

    const parts = new Uint8Array([
      SafetyNumber.VERSION,
      ...new TextEncoder().encode('SIBNA_SAFETY_NUMBER_V1_EXTRA'),
      ...first, ...second, ...extraData,
    ]);
    const hash = sha512Hash(parts);
    const fingerprint = hash.slice(0, 32);
    return new SafetyNumber(bytesToDigits(fingerprint), fingerprint);
  }

  static fromString(s: string): SafetyNumber {
    const digits = s.replace(/\D/g, '');
    if (digits.length !== 80) throw new Error(`Expected 80 digits, got ${digits.length}`);
    const fingerprint = digitsToBytes(digits);
    return new SafetyNumber(digits, fingerprint);
  }

  asString(): string { return this.digits; }

  formatted(groupSize = 5, groupsPerLine = 8): string {
    const groups: string[] = [];
    for (let i = 0; i < this.digits.length; i += groupSize) {
      groups.push(this.digits.substring(i, i + groupSize));
    }
    const lines: string[] = [];
    for (let i = 0; i < groups.length; i += groupsPerLine) {
      lines.push(groups.slice(i, i + groupsPerLine).join(' '));
    }
    return lines.join('\n');
  }

  qrData(): Uint8Array {
    const qr = new Uint8Array(36);
    qr[0] = this.version;
    qr.set(new TextEncoder().encode('SB1'), 1);
    qr.set(this.fingerprint, 4);
    return qr;
  }

  verify(other: SafetyNumber): boolean {
    const k = new Uint8Array(32);
    const a = hmacSha256(k, this.fingerprint);
    const b = hmacSha256(k, other.fingerprint);
    return a.every((v, i) => v === b[i]);
  }

  equals(other: SafetyNumber): boolean {
    if (this.fingerprint.length !== other.fingerprint.length) return false;
    let diff = 0;
    for (let i = 0; i < this.fingerprint.length; i++) {
      diff |= this.fingerprint[i] ^ other.fingerprint[i];
    }
    return diff === 0;
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return true;
    if (a[i] > b[i]) return false;
  }
  return false;
}

function bytesToDigits(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < 32; i += 2) {
    const value = (bytes[i] << 8) | bytes[i + 1];
    parts.push(String(value % 100000).padStart(5, '0'));
  }
  return parts.join('');
}

function digitsToBytes(digits: string): Uint8Array {
  const result = new Uint8Array(32);
  for (let i = 0; i < 80; i += 5) {
    const value = parseInt(digits.substring(i, i + 5));
    const byteIdx = (i / 5) * 2;
    result[byteIdx] = (value >> 8) & 0xFF;
    result[byteIdx + 1] = value & 0xFF;
  }
  return result;
}
