import 'package:encryptiontest/SecureChannel/MessageSender.dart';
import 'package:encryptiontest/SecureChannel/Models/MessageModel.dart';
import 'package:encryptiontest/SecureChannel/SecureChannel.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'SecureChannel/Models/Globals.dart';

SecureChannel _secureChannel = new SecureChannel();
MessageSender _messageSender = new MessageSender();

startSecureChannel() async {
  bool isSecure = await _secureChannel.createServerSession();

  if (!isSecure) {
    SystemNavigator.pop(animated: true);
  }
}

sendMessageToServer() async {
  //Encrypt aes

  final key = encrypt.Key.fromUtf8(Globals.encKey);
  final iv = encrypt.IV.fromUtf8(Globals.ivKey);

  final encrypter = encrypt.Encrypter(encrypt.AES(key));

  final cipher = encrypter.encrypt('MESSAGE FROM CLIENT', iv: iv);

  MessageModel serverMessage =
      await _messageSender.sendMessageToServer(cipher.base64);

  String sMessage = serverMessage.Message;
}

void main() {
  runApp(MyApp());
}

class MyApp extends StatelessWidget {
  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure App Test',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        visualDensity: VisualDensity.adaptivePlatformDensity,
      ),
      home: MyHomePage(title: 'Secure Messaging Test'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  MyHomePage({Key key, this.title}) : super(key: key);

  final String title;

  @override
  _MyHomePageState createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  @override
  void initState() {
    super.initState();
    startSecureChannel();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
        ),
      ),
      floatingActionButton: FloatingActionButton(
          child: Icon(Icons.lock),
          onPressed: () {
            showDialog(
              context: context,
              builder: (BuildContext context) {
                sendMessageToServer();

                return AlertDialog(
                  title: Text('Key Information'),
                  content: SingleChildScrollView(
                    child: ListBody(
                      children: <Widget>[
                        Text('ENCKey: ' +
                            Globals.encKey +
                            '\n\nIVKey: ' +
                            Globals.ivKey),
                      ],
                    ),
                  ),
                  actions: <Widget>[
                    TextButton(
                      child: Text('Approve'),
                      onPressed: () {
                        Navigator.of(context).pop();
                      },
                    ),
                  ],
                );
              },
            );
          }),
    );
  }
}
