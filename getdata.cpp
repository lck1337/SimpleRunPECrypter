#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <cstdlib>


std::string generate_random_text(int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const int charset_size = sizeof(charset) - 1;
    std::string result;
    result.reserve(length);
    for (int i = 0; i < length; i++) {
        result += charset[rand() % charset_size];
    }
    return result;
}

void xorEncrypt(char* buffer, int size, const char* key, int keySize) {
    for (int i = 0; i < size; i++) {
        buffer[i] ^= key[i % keySize];
    }
}

int main() {
    const char* inputFile = "input.exe";
    const char* outputFile = "output.h";
    const int length = 58;
    std::string text = generate_random_text(length);
    const char* key = text.c_str();

    std::ifstream ifs(inputFile, std::ios::binary);
    if (!ifs.is_open()) {
        std::cerr << "Error opening input file: " << inputFile << std::endl;
        return 1;
    }

    ifs.seekg(0, std::ios::end);
    int fileSize = ifs.tellg();
    ifs.seekg(0, std::ios::beg);


    char* buffer = new char[fileSize];

    ifs.read(buffer, fileSize);
    ifs.close();

    xorEncrypt(buffer, fileSize, key, strlen(key));

    std::ofstream ofs(outputFile);
    if (!ofs.is_open()) {
        std::cerr << "Error opening output file: " << outputFile << std::endl;
        return 1;
    }

    ofs << "#pragma once\n\n";
    ofs << "const char* key = \042" << key << "\042;\n\n";
    ofs << "const unsigned char encryptedData[] = {\n";
    for (int i = 0; i < fileSize; i++) {
        ofs << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i];
        if (i != fileSize - 1) {
            ofs << ",";
        }
        if ((i + 1) % 16 == 0) {
            ofs << "\n";
        }
        else {
            ofs << " ";
        }
    }
    ofs << "\n};\n";
    ofs.close();

    delete[] buffer;

    std::cout << "Encryption completed successfully." << std::endl;

    return 0;
}