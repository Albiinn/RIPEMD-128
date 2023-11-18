#include <iostream>
#include <string>
#include <fstream>
#include "cryptopp/cryptlib.h"
#include "cryptopp/ripemd.h"
#include "cryptopp/hmac.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"

// Function to generate RIPEMD-128 hash using HMAC
std::string generateHMAC(const std::string &message, const std::string &key)
{
    CryptoPP::HMAC<CryptoPP::RIPEMD128> hmac((const CryptoPP::byte *)key.data(), key.size());
    std::string digest;
    CryptoPP::StringSource(message, true,
        new CryptoPP::HashFilter(hmac,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest)
            )
        )
    );
    return digest;
}
 

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

    // Case 2:
    std::cout << "\nCase 2: Message integrity check" << std::endl;
 
    // Shared secret key between Alice and Bob
    std::string secretKey = "SuperSecretKey";
 
    // Message from Alice to Bob
    std::string aliceMessage = "Meet me at the secret location.";
 
    // Alice generates HMAC for the message
    std::string aliceHMAC = generateHMAC(aliceMessage, secretKey);
 
    // Simulate message transmission
    std::cout << "Alice sends the message: " << aliceMessage << std::endl;
    std::cout << "Alice sends the HMAC: " << aliceHMAC << std::endl;
 
    // Bob receives the message and HMAC
    // (In a real scenario, these would be transmitted securely)
 
    // Bob verifies the integrity of the message
    std::string bobReceivedHMAC = generateHMAC(aliceMessage, secretKey);
 
    if (bobReceivedHMAC == aliceHMAC)
    {
        std::cout << "Bob received the message intact. It's from Alice!" << std::endl;
    }
    else
    {
        std::cout << "Warning: Message integrity compromised. Possible tampering!" << std::endl;
    }

    return 0;
}