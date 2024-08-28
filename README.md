# AppCrypto

`AppCrypto` is a Dart class providing various cryptographic functionalities for secure data handling, including encryption, decryption, key derivation, and hashing. This class leverages the `pointycastle` library for cryptographic operations and utilizes Dart isolates for performing computationally intensive tasks off the main thread.

## Features

- **File Encryption and Decryption**: Encrypt and decrypt files using AES with CBC mode and PKCS7 padding.
- **Key Derivation**: Derive keys from passwords using PBKDF2 with HMAC and SHA-256.
- **HMAC Generation**: Generate HMACs using SHA-256.
- **Elliptic Curve Cryptography**: Generate and encode/decode EC key pairs and derive shared secrets.
- **Random Salt Generation**: Generate secure random salts for hashing.
- **Hashing with Salt**: Compute SHA-256 hashes with optional salts.

## Installation

Add `pointycastle` to your `pubspec.yaml`:

```yaml
dependencies:
  pointycastle: ^3.1.0
```

`static FileEncryptionService fileEncryptionService(String pin)`

`static Uint8List generateSaltPRNG()`

`static Uint8List deriveKey(String input)`

`static Future<Uint8List> deriveKeyIsolate(String input)`

`static Uint8List _generateRandomBytes(int length)`

`static Future<Uint8List> encryptAESInIsolate(Uint8List plaintext, Uint8List key)`

`static Uint8List encryptAES(Uint8List plaintext, Uint8List key)`

`static Future<void> decryptFileAES(String inputPath, String outputPath, Uint8List key)`

`static Future<void> encryptFileAES(String inputPath, String outputPath, Uint8List key)`

`static Future<Uint8List> generateHMACIsolate(Uint8List key, Uint8List message)`

`static Future<Uint8List> decryptAESInIsolate(Uint8List bytes, Uint8List sharedKey)`

`static Uint8List decryptAES(Uint8List ciphertext, Uint8List key)`

`static AsymmetricKeyPair<ECPublicKey, ECPrivateKey> generateECKeyPair({int bitLength = 2048})`

`static SecureRandom _secureRandom()`

`static Uint8List deriveSharedSecret(ECPrivateKey privateKey, ECPublicKey serverPublicKey)`

`static String encodeECPublicKey(ECPublicKey publicKey)`

`static ECPublicKey decodeECPublicKey(String base64String)`

`static Uint8List _bigIntToByteArray(BigInt bigInt)`

`static Uint8List sha256Digest(Uint8List input, {List? salt})`

`static Uint8List generateHMAC(Uint8List key, Uint8List message)`

`static Uint8List hashWithSalt(Uint8List data, Uint8List salt)`

`static Uint8List generateSalt({int length = 16})`

`static bool verifyHash(Uint8List input, Uint8List storedHash, Uint8List salt)`
