# SimpleRunPECrypter

Простой пример криптера на c++ использующий технику скрытия RunPE.

getdata.cpp - принимает входящий файл "input.exe", генерирует ключ, шифрует байты xor`ом и на выходе output.h (заголовочный файл в котором уже хранятся зашифрованные байты с ключем).

main.cpp - сам уже криптер где уже используется заголовочный файл с зашифрованными данными. Короче мне лень расписывать тут. Эта фигня просто расшифровывает байты и юзает их в RunPE.

output.h - пример выходного файла.

