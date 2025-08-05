# IronWave
適当に作ったプログラム
今月で19になるから18才までの実力を遺したくて、
本当は今はAIのニューラルネットワーク、ReLU、微分のReLU、損失関数MSEってきてて、あとは逆伝播だけだった、本当はAIを載せたかったけど、自分の実力はこれまでだっただから1ヶ月程前に作ったコードになってしまうけどのせておく。
本当はkeventでopenbsdで動く予定のプログラムだけど、linux仕様にしてepollにした


本当はepollはevent.evを観察して、送信と受信と処理を完全に分けられるのだが、まぁ、未熟だったなら仕方無い。今の自分はまだギリ18だができる。

コンパイルコマンドは以下となる
gcc login.c -lssl -lcrypto -lpq -largon2 -fstack-protector-all -D_FORTIFY_SOURCE=3 -O2 -Wl,-z,relro,-z,now -fPIE -pie -fstack-clash-protection -fcf-protection=full -D_GLIBCXX_ASSERTIONS -Wextra -Wall -Werror -Wshadow -Wcast-align -Wconversion -Wformat=2 -Wnull-dereference -Wfloat-equal -Wpedantic -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition -Wunreachable-code -Wduplicated-cond -Wlogical-op -Wrestrict -Wno-unused-parameter -Wformat-security -Werror=format-security -fsanitize=address,undefined -Wl,-z,noexecstack && strip ./a.out
