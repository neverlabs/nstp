import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';
import 'lib/crypto_utils.dart';

final deviceSalt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);

void main() async {
  print('[DEBUG] Connecting to server...');
  final socket = await Socket.connect('127.0.0.1', 8080);

  final username = 'alice';
  final password = 'userpassword';

  final usernameBytes = utf8.encode(username);

  print('[DEBUG] Sending username length: ${usernameBytes.length}');
  socket.add([usernameBytes.length]);
  print('[DEBUG] Sending username: $username');
  socket.add(usernameBytes);

  // Generate and send client nonce (16 bytes)
  final clientNonce = randomBytes(16);
  print('[DEBUG] Sending client nonce: $clientNonce');
  socket.add(clientNonce);

  // Create a buffer to read from socket
  final buffer = <int>[];
  int state = 0; // 0: handshake, 1: send, 2: receive responses
  int responses = 0;
  int messagesSent = 0;
  Uint8List? sessionNonce;
  Uint8List? sessionKey;

  await for (final chunk in socket) {
    print('[DEBUG] Received chunk: $chunk');
    buffer.addAll(chunk);

    // State machine for handshake
    if (state == 0 && buffer.length >= 8) {
      // Read 8-byte session nonce
      sessionNonce = Uint8List.fromList(buffer.sublist(0, 8));
      buffer.removeRange(0, 8);
      print('[DEBUG] Received session nonce: $sessionNonce');

      // Derive keys
      final psk = deriveKey(password, username, deviceSalt, 32);
      print('[DEBUG] Derived PSK: $psk');
      final sessionId = Uint8List.fromList(clientNonce + sessionNonce);
      print('[DEBUG] Session ID: $sessionId');
      sessionKey = hmacSha256(psk, sessionId);
      print('[DEBUG] Session key: $sessionKey');

      // Send client HMAC
      final clientHmac = hmacSha256(
        sessionKey,
        Uint8List.fromList(clientNonce + sessionNonce + usernameBytes),
      );
      print('[DEBUG] Sending client HMAC: $clientHmac');
      socket.add(clientHmac);

      state = 1; // Move to next state: wait for server HMAC
    }

    if (state == 1 && buffer.length >= 32) {
      // Read server HMAC
      final serverHmac = Uint8List.fromList(buffer.sublist(0, 32));
      buffer.removeRange(0, 32);
      print('[DEBUG] Received server HMAC: $serverHmac');

      final expectedServerHmac = hmacSha256(
        sessionKey!,
        Uint8List.fromList(sessionNonce! + clientNonce + usernameBytes),
      );
      print('[DEBUG] Expected server HMAC: $expectedServerHmac');

      if (!listEquals(serverHmac, expectedServerHmac)) {
        print('[DEBUG] Server authentication failed');
        await socket.close();
        return;
      }

      print('[DEBUG] Handshake successful!');

      // Send encrypted messages
      for (int counter = 0; counter < 5; counter++) {
        final msg = utf8.encode('Hello server! Message #$counter');
        print('[DEBUG] Plaintext to send: $msg');
        final nonce = Uint8List(12)
          ..setRange(0, 8, sessionNonce)
          ..buffer.asByteData().setUint32(8, counter, Endian.big);
        print('[DEBUG] Nonce for message: $nonce');

        final ciphertext = aesGcmEncrypt(sessionKey, nonce, Uint8List.fromList(msg));
        print('[DEBUG] Ciphertext: $ciphertext');
        socket.add(Uint8List.fromList(nonce + ciphertext));
        print('[DEBUG] Message sent');
        await Future.delayed(Duration(milliseconds: 500));
        messagesSent++;
      }

      print('[DEBUG] All messages sent, waiting for server responses...');
      await socket.flush();
      state = 2;
    }

    if (state == 2 && buffer.length >= 2) {
      // Read and decrypt all complete server responses in buffer
      while (buffer.length >= 2) {
        final packetLen = (buffer[0] << 8) | buffer[1];
        if (buffer.length < 2 + packetLen) break;
        final responseNonce = Uint8List.fromList(buffer.sublist(2, 14));
        final responseCiphertext = Uint8List.fromList(buffer.sublist(14, 2 + packetLen));
        try {
          final responsePlain = aesGcmDecrypt(sessionKey!, responseNonce, responseCiphertext);
          final responseText = utf8.decode(responsePlain);
          print('[DEBUG] Decrypted server response: $responseText');
        } catch (e) {
          print('[DEBUG] Failed to decrypt server response: $e');
        }
        buffer.removeRange(0, 2 + packetLen);
        responses++;
        if (responses >= messagesSent) {
          print('[DEBUG] Closing socket.');
          await socket.close();
          return;
        }
      }
    }
  }
}
