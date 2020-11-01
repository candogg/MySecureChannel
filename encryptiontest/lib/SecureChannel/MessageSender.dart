import 'package:http/http.dart' as http;
import 'Models/Globals.dart';
import 'Models/MessageModel.dart';
import 'dart:convert';

class MessageSender {
  Future<MessageModel> sendMessageToServer(String message) async {
    try {
      String url = 'http://192.168.1.38/CAuthService/Auth/GetServerMessage';
      Map<String, String> headers = {"Content-type": "application/json"};
      String json = '{ "SessionId": "' +
          Globals.sessionId +
          '", "Message": "' +
          message +
          '" }';

      http.Response response =
          await http.post(url, headers: headers, body: json);

      String body = response.body;

      Map<String, dynamic> jsonMap = jsonDecode(body);

      return new MessageModel(jsonMap['SessionId'], jsonMap['Message']);
    } catch (Exception) {
      return null;
    }
  }
}
