#include <iostream>
#include <string>
#include <fstream>
#include "cryptopp/cryptlib.h"
#include "cryptopp/ripemd.h"
#include "cryptopp/hmac.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"

// Function to hash the file with RIPEMD-128
std::string hashFile(const std::string &filename)
{
    using namespace CryptoPP;

    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        std::cerr << "Unable to open file: " << filename << std::endl;
        return "";
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    byte *fileData = new byte[fileSize];
    file.read(reinterpret_cast<char *>(fileData), fileSize);

    byte digest[RIPEMD128::DIGESTSIZE];
    RIPEMD128().CalculateDigest(digest, fileData, fileSize);

    HexEncoder encoder;
    std::string output;
    encoder.Attach(new StringSink(output));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();

    delete[] fileData;

    return output;
}

bool verifyFile(const std::string &filename, const std::string &expectedHash)
{
    std::string actualHash = hashFile(filename);
    return actualHash == expectedHash;
}

int main()
{
    // Case 1:
    std::cout << "Case 1: File integrity check" << std::endl;

    std::string filename = "HelloWorld.txt";
    std::string expectedHash = "24E23E5C25BC06C8AA43B696C1E11669";

    if (verifyFile(filename, expectedHash))
    {
        std::cout << "File integrity verified!" << std::endl;
    }
    else
    {
        std::cout << "File integrity verification failed!" << std::endl;
    }

    return 0;
}