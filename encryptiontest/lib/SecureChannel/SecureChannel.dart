import 'dart:convert';
import 'dart:typed_data';
import 'package:encryptiontest/SecureChannel/Models/ResponseModel.dart';
import 'package:rsa_encrypt/rsa_encrypt.dart';
import 'package:pointycastle/api.dart' as crypto;
import 'package:http/http.dart' as http;
import 'Models/Globals.dart';

class SecureChannel {
  Future<bool> createServerSession() async {
    try {
      ResponseModel rModel = await createSession();

      if (rModel != null &&
          rModel.SessionId != null &&
          rModel.SessionId != '' &&
          rModel.PublicKey != null &&
          rModel.PublicKey != '') {
        var helper = RsaKeyHelper();

        Globals.sessionId = rModel.SessionId;

        var serverPublic = helper.parsePublicKeyFromPem(rModel.PublicKey);

        crypto.AsymmetricKeyPair keyPair =
            getRsaKeyPair(helper.getSecureRandom());

        var pubKey = keyPair.publicKey;
        var priKey = keyPair.privateKey;

        String pubKeyPem = helper.encodePublicKeyToPemPKCS1(pubKey);

        List<String> pKeyChunks = splitStringByLength(pubKeyPem, 256);

        String wholeEncrypted = '';

        pKeyChunks.forEach((element) {
          String encText = encrypt(element, serverPublic);
          Uint8List encBytes = Uint8List.fromList(encText.codeUnits);
          String base64Encoded = base64Encode(encBytes);

          wholeEncrypted += base64Encoded + '≡';
        });

        wholeEncrypted = wholeEncrypted.substring(0, wholeEncrypted.length - 1);

        ResponseModel keyModel =
            await getSessionKeys(rModel.SessionId, wholeEncrypted);

        if (keyModel != null &&
            keyModel.EKey != null &&
            keyModel.EKey != '' &&
            keyModel.IKey != null &&
            keyModel.IKey != '') {
          Globals.encKey = decrypt(
              String.fromCharCodes(base64Decode(keyModel.EKey)), priKey);
          Globals.ivKey = decrypt(
              String.fromCharCodes(base64Decode(keyModel.IKey)), priKey);

          return true;
        }
      }
    } catch (Exception) {}

    return false;
  }

  Future<ResponseModel> createSession() async {
    try {
      String url = 'http://192.168.1.38/CAuthService/Auth/CreateSession';
      Map<String, String> headers = {"Content-type": "application/json"};
      String json =
          '{ "ClientSecret": "MmU4MjJlZDAtZDZjMi00NWQxLThhYmQtNThhNDg3MGEzNTQw" }';

      http.Response response =
          await http.post(url, headers: headers, body: json);

      String body = response.body;

      Map<String, dynamic> jsonMap = jsonDecode(body);

      return new ResponseModel(jsonMap['SessionId'], jsonMap['PublicKey'],
          jsonMap['EKey'], jsonMap['IKey']);
    } catch (Exception) {
      return null;
    }
  }

  Future<ResponseModel> getSessionKeys(
      String sessionId, String clientPublic) async {
    try {
      String url = 'http://192.168.1.38/CAuthService/Auth/ShareSessionKeys';
      Map<String, String> headers = {"Content-type": "application/json"};
      String json = '{ "SessionId": "' +
          sessionId +
          '", "ClientPublic": "' +
          clientPublic +
          '" }';

      http.Response response =
          await http.post(url, headers: headers, body: json);

      String body = response.body;

      Map<String, dynamic> jsonMap = jsonDecode(body);

      return new ResponseModel(jsonMap['SessionId'], jsonMap['PublicKey'],
          jsonMap['EKey'], jsonMap['IKey']);
    } catch (Exception) {
      return null;
    }
  }

  List<String> splitStringByLength(String str, int maxLength) {
    List<String> data = [];

    for (int index = 0; index < str.length; index += maxLength) {
      if (index + maxLength < str.length) {
        data.add(str.substring(index, index + maxLength));
      } else {
        data.add(str.substring(index));
      }
    }

    return data;
  }
}
