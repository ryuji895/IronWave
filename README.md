# IronWave
起業をやめてのっけることにしたシステムの一部
今月で19になるから18才までの実力を遺したくて、
あと、まだ実力不足だし、社会経験も足りなかった。
本当は今はAIのニューラルネットワーク、ReLU、微分のReLU、損失関数MSEってきてて、あとは逆伝播だけだった、本当はAIを載せたかったけど、自分の実力はこれまでだっただから1ヶ月程前に作ったコードになってしまうけどのせておく。
本当はkeventでopenbsdで動く予定のプログラムだけど、linux仕様にしてepollにした


本当はepollはevent.eventsがEPOLLINかEPOLLOUTかを観察して、送信と受信と処理を完全に分け、更に2faから送られてくるのもアドレス直接ではなくフラグ方式にし、torkenサーバーのデータでは書名はEd25519をつかい、
クライアント通信でもaes256cgmを指定したり(本当は鍵交換でもx25619を使いたかったけどTLS1.3だと指定できない)、makefileを使用し、include、src、code、など様々なディレクトリに分けていた。
リファクタされたコードはここに載ってるlogin.cとは比にならないのだが、開発していたコンピュータのバックアップを取る前に違うOSを入れてしまったため、ロストテクノロジーみたいになっている。
全体のコードが軽いため、loginシステム以外もすべて普通のパソコンで動かせる予定だった、(13th以上16GB、520GB以上 1GBps の話)

コンパイルコマンドは以下となる
gcc login.c -lssl -lcrypto -lpq -largon2 -fstack-protector-all -D_FORTIFY_SOURCE=3 -O2 -Wl,-z,relro,-z,now -fPIE -pie -fstack-clash-protection -fcf-protection=full -D_GLIBCXX_ASSERTIONS -Wextra -Wall -Werror -Wshadow -Wcast-align -Wconversion -Wformat=2 -Wnull-dereference -Wfloat-equal -Wpedantic -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition -Wunreachable-code -Wduplicated-cond -Wlogical-op -Wrestrict -Wno-unused-parameter -Wformat-security -Werror=format-security -fsanitize=address,undefined -Wl,-z,noexecstack && strip ./a.out
