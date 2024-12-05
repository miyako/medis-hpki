![platform](https://img.shields.io/static/v1?label=platform&message=win-64&color=blue)

# medis-hpki
はじめてのHPKI　～実装の手引き～

https://www.medis.or.jp/8_hpki/video.html

**HPKIカードドライバ**をWindowsにインストールします。インストーラーをダウンロードをは，[日本医師会電子認証センターのサイト](https://www.jmaca.med.or.jp/service/#HPKICD)にログインすることで入手できます。

* setup_x64.msi
* setup_x86.msi

「ドライバ」をインストールすると，カードリーダーと通信するための仕組みが[暗号化サービスプロバイダー（CSP）](https://learn.microsoft.com/ja-jp/windows/win32/seccrypto/cryptographic-service-providers)に登録され，ローレベルのAPDU実装を気にすることなく，ハイレベルの抽象化レイヤーである[CryptoAPI](https://learn.microsoft.com/ja-jp/windows/win32/seccrypto/cryptoapi-system-architecture)でアクセスできるようになります。
