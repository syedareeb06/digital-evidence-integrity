/* Cryptography used by CustodyChain (everything runs in the browser, files never leave it):
 *  - SHA-256  (FIPS 180-4, Merkle-Damgard construction) with the Web Crypto API
 *  - SHA3-256 (FIPS 202, Keccak sponge construction) with js-sha3 (vendor/sha3.min.js).
 *    This is the real SHA-3, not Ethereum's keccak256: the two differ only in the padding
 *    byte (0x06 vs 0x01), which gives completely different digests.
 *  Dual hashing: a forger would need a file that collides in BOTH unrelated designs at once.
 *  - helpers that compare two digests digit by digit and bit by bit (the avalanche effect)
 */
(function () {
  const SHA256_ABC = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  const SHA3_ABC = "0x3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";

  const sha3 = (data) => "0x" + window.sha3_256(UI.toBytes(data));
  const sha256 = (data) => UI.sha256(data);

  /** Both fingerprints of the exact bytes of a file. */
  async function fingerprint(bytes) {
    return { sha256: await sha256(bytes), sha3: sha3(bytes) };
  }

  /** Known-answer test (FIPS test vector "abc") and proof that SHA3-256 is not keccak256. */
  async function selfTest() {
    const keccak = ethers.keccak256(ethers.toUtf8Bytes("abc"));
    return (await sha256("abc")) === SHA256_ABC && sha3("abc") === SHA3_ABC && keccak !== SHA3_ABC;
  }

  const strip = (h) => (h || "").replace(/^0x/, "").toLowerCase();

  /** For each of the 64 hex digits: does it differ between a and b? */
  function digitMask(a, b) {
    const x = strip(a);
    const y = strip(b);
    return Array.from({ length: Math.max(x.length, y.length) }, (_, i) => x[i] !== y[i]);
  }

  /** The 256 bits of a XOR b (1 = this bit flipped). */
  function bitMask(a, b) {
    const x = BigInt("0x" + (strip(a) || "0")) ^ BigInt("0x" + (strip(b) || "0"));
    return x.toString(2).padStart(256, "0").split("").map(Number);
  }

  /** How different two 256-bit digests are: { digits: of 64, bits: of 256 }. */
  function compare(a, b) {
    return {
      digits: digitMask(a, b).filter(Boolean).length,
      bits: bitMask(a, b).reduce((n, v) => n + v, 0),
    };
  }

  window.CustodyCrypto = { sha256, sha3, fingerprint, selfTest, digitMask, bitMask, compare, SHA256_ABC, SHA3_ABC };
})();
