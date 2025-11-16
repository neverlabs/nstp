import 'dart:typed_data';
import 'dart:convert';
import 'dart:math';
import 'package:pointycastle/export.dart';

Uint8List randomBytes(int length) {
  final rnd = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => rnd.nextInt(256)));
}

Uint8List deriveKey(String password, String username, Uint8List deviceSalt, int keyLen) {
  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
  final salt = Uint8List.fromList(deviceSalt + utf8.encode(username));
  pbkdf2.init(Pbkdf2Parameters(salt, 600000, keyLen)); // 600k iterations
  return pbkdf2.process(Uint8List.fromList(utf8.encode(password)));
}

Uint8List hmacSha256(Uint8List key, Uint8List data) {
  final hmac = HMac(SHA256Digest(), 64)..init(KeyParameter(key));
  return hmac.process(data);
}

Uint8List aesGcmEncrypt(Uint8List key, Uint8List nonce, Uint8List plaintext) {
  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
  return cipher.process(plaintext);
}

Uint8List aesGcmDecrypt(Uint8List key, Uint8List nonce, Uint8List ciphertext) {
  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(false, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
  return cipher.process(ciphertext);
}

bool listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
