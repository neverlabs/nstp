import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';
import 'lib/crypto_utils.dart';

final Map<String, int> sessionCounters = {};

Future<void> main() async {
  final deviceSalt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
  final server = await ServerSocket.bind(InternetAddress.anyIPv4, 8080);
  print('[DEBUG] Server listening on port 8080');

  await for (final socket in server) {
    print('[DEBUG] New client connection');
    handleClient(socket, deviceSalt);
  }
}

void handleClient(Socket socket, Uint8List deviceSalt) async {
  try {
    final buffer = <int>[];
    int state = 0;

    String? username;
    Uint8List? sessionKey;
    String? sessionKeyBase64;
    Uint8List? clientNonce;
    Uint8List? sessionNonce;

    await for (final chunk in socket) {
      print('[DEBUG] Received chunk: $chunk');
      buffer.addAll(chunk);

      // State 0: Read username
      if (state == 0 && buffer.isNotEmpty) {
        final usernameLen = buffer[0];
        print('[DEBUG] Username length: $usernameLen');
        if (buffer.length >= 1 + usernameLen) {
          username = utf8.decode(buffer.sublist(1, 1 + usernameLen));
          print('[DEBUG] Username: $username');
          buffer.removeRange(0, 1 + usernameLen);
          state = 1;
        }
      }

      // State 1: Read client nonce and send session nonce
      if (state == 1 && buffer.length >= 16) {
        clientNonce = Uint8List.fromList(buffer.sublist(0, 16));
        print('[DEBUG] Client nonce: $clientNonce');
        buffer.removeRange(0, 16);

        // Generate 8-byte session nonce
        sessionNonce = randomBytes(8);
        print('[DEBUG] Generated session nonce: $sessionNonce');
        socket.add(sessionNonce);

        // Derive keys
        final password = 'userpassword';
        final psk = deriveKey(password, username!, deviceSalt, 32);
        print('[DEBUG] Derived PSK: $psk');
        final sessionId = Uint8List.fromList(clientNonce + sessionNonce);
        print('[DEBUG] Session ID: $sessionId');
        sessionKey = hmacSha256(psk, sessionId);
        print('[DEBUG] Session key: $sessionKey');
        sessionKeyBase64 = base64.encode(sessionId);
        print('[DEBUG] Session key (base64): $sessionKeyBase64');

        // Store expected client HMAC data for verification
        socket.add([]); // Flush to ensure nonce is sent

        state = 2;
      }

      // State 2: Verify client HMAC
      if (state == 2 && buffer.length >= 32) {
        final clientHmac = Uint8List.fromList(buffer.sublist(0, 32));
        print('[DEBUG] Received client HMAC: $clientHmac');
        buffer.removeRange(0, 32);

        // Reconstruct expected client HMAC
        final expectedClientHmac = hmacSha256(
          sessionKey!,
          Uint8List.fromList(clientNonce! + sessionNonce! + utf8.encode(username!)),
        );
        print('[DEBUG] Expected client HMAC: $expectedClientHmac');
        if (!listEquals(clientHmac, expectedClientHmac)) {
          print('[DEBUG] Client authentication failed for $username');
          socket.destroy();
          return;
        }

        // Send server HMAC
        final serverHmac = hmacSha256(
          sessionKey,
          Uint8List.fromList(sessionNonce + clientNonce + utf8.encode(username)),
        );
        print('[DEBUG] Sending server HMAC: $serverHmac');
        socket.add(serverHmac);

        print('[DEBUG] Handshake successful with $username');

        // Initialize counter for replay protection
        sessionCounters[sessionKeyBase64!] = -1;

        state = 3;
      }

      // State 3: Process encrypted messages
      if (state == 3) {
        while (buffer.length >= 12 + 16) {
          final nonce = Uint8List.fromList(buffer.sublist(0, 12));
          print('[DEBUG] Received message nonce: $nonce');
          // Find end of ciphertext (we need to know the message length)
          // For now, assume the rest of buffer is one message
          final ciphertext = Uint8List.fromList(buffer.sublist(12));
          print('[DEBUG] Received ciphertext: $ciphertext');
          buffer.clear();

          final counter = nonce.buffer.asByteData().getUint32(8, Endian.big);
          final lastCounter = sessionCounters[sessionKeyBase64] ?? -1;
          print('[DEBUG] Counter: $counter, Last counter: $lastCounter');
          if (counter <= lastCounter) {
            print('[DEBUG] Replay detected: $counter <= $lastCounter');
            continue;
          }

          try {
            final plaintext = aesGcmDecrypt(sessionKey!, nonce, ciphertext);
            final message = utf8.decode(plaintext);
            print('[DEBUG] Decrypted message: $message');
            sessionCounters[sessionKeyBase64!] = counter;
            // Encrypt and send a response to the client
            final responsePlain = utf8.encode('Server received: $message');
            final responseNonce = randomBytes(12);
            final responseCiphertext = aesGcmEncrypt(sessionKey, responseNonce, Uint8List.fromList(responsePlain));
            final responsePacket = Uint8List(2 + 12 + responseCiphertext.length);
            final packetView = responsePacket.buffer.asByteData();
            packetView.setUint16(0, 12 + responseCiphertext.length, Endian.big); // length of nonce+ciphertext
            responsePacket.setRange(2, 14, responseNonce);
            responsePacket.setRange(14, 14 + responseCiphertext.length, responseCiphertext);
            socket.add(responsePacket);
            print('[DEBUG] Sent encrypted response to client (length: ${responsePacket.length})');
          } catch (e) {
            print('[DEBUG] Decryption failed: $e');
          }
        }
      }
    }
  } catch (e) {
    if (e is SocketException) {
      print('[DEBUG] Socket closed by client.');
    } else {
      print('[DEBUG] Connection error: $e');
    }
    await socket.close();
  }
}
