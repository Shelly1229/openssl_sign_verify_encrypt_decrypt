#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <time.h>
#include <sstream>
#include <string.h>

// 生成RSA密钥对
bool generateRSAKeyPair(const std::string& privateKeyFile, const std::string& publicKeyFile) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    if (!rsa || !bn) {
        std::cerr << "Failed to allocate memory for RSA key pair generation." << std::endl;
        return false;
    }

    if (BN_set_word(bn, RSA_F4) != 1 || RSA_generate_key_ex(rsa, 2048, bn, nullptr) != 1) {
        std::cerr << "Failed to generate RSA key pair." << std::endl;
        RSA_free(rsa);
        BN_free(bn);
        return false;
    }

    // 写入私钥
    std::FILE* privateKeyFP = std::fopen(privateKeyFile.c_str(), "wb");
    if (!privateKeyFP) {
        std::cerr << "Failed to open private key file for writing." << std::endl;
        RSA_free(rsa);
        BN_free(bn);
        return false;
    }
    if (PEM_write_RSAPrivateKey(privateKeyFP, rsa, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        std::cerr << "Failed to write private key." << std::endl;
        std::fclose(privateKeyFP);
        RSA_free(rsa);
        BN_free(bn);
        return false;
    }
    std::fclose(privateKeyFP);

    // 写入公钥
    std::FILE* publicKeyFP = std::fopen(publicKeyFile.c_str(), "wb");
    if (!publicKeyFP) {
        std::cerr << "Failed to open public key file for writing." << std::endl;
        RSA_free(rsa);
        BN_free(bn);
        return false;
    }
    if (PEM_write_RSAPublicKey(publicKeyFP, rsa) != 1) {
        std::cerr << "Failed to write public key." << std::endl;
        std::fclose(publicKeyFP);
        RSA_free(rsa);
        BN_free(bn);
        return false;
    }
    std::fclose(publicKeyFP);

    RSA_free(rsa);
    BN_free(bn);
    return true;
}

// 使用私钥对消息进行签名
bool signMessage(const std::string& privateKeyFile, std::string message, const std::string& signatureFile) {
    std::FILE* privateKeyFP = std::fopen(privateKeyFile.c_str(), "rb");
    if (!privateKeyFP) {
        std::cerr << "Failed to open private key file for reading." << std::endl;
        return false;
    }
    RSA* rsa = PEM_read_RSAPrivateKey(privateKeyFP, nullptr, nullptr, nullptr);
    std::fclose(privateKeyFP);
    if (!rsa) {
        std::cerr << "Failed to read private key." << std::endl;
        return false;
    }

    unsigned char signature[RSA_size(rsa)];
    unsigned int signatureLength;
    if (RSA_sign(NID_sha256, reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), signature, &signatureLength, rsa) != 1) {
        std::cerr << "Failed to sign the message." << std::endl;
        RSA_free(rsa);
        return false;
    }

    std::FILE* signatureFP = std::fopen(signatureFile.c_str(), "wb");
    if (!signatureFP) {
        std::cerr << "Failed to open signature file for writing." << std::endl;
        RSA_free(rsa);
        return false;
    }
    if (std::fwrite(signature, sizeof(unsigned char), signatureLength, signatureFP) != signatureLength) {
        std::cerr << "Failed to write the signature." << std::endl;
        std::fclose(signatureFP);
        RSA_free(rsa);
        return false;
    }
    std::fclose(signatureFP);

    RSA_free(rsa);
    return true;
}

// 使用公钥验证签名
bool verifySignature(const std::string& publicKeyFile, std::string message, const std::string& signatureFile) {
    std::FILE* publicKeyFP = std::fopen(publicKeyFile.c_str(), "rb");
    if (!publicKeyFP) {
        std::cerr << "Failed to open public key file for reading." << std::endl;
        return false;
    }
    RSA* rsa = PEM_read_RSAPublicKey(publicKeyFP, nullptr, nullptr, nullptr);
    std::fclose(publicKeyFP);
    if (!rsa) {
        std::cerr << "Failed to read public key." << std::endl;
        return false;
    }


    unsigned char signature[RSA_size(rsa)];
    unsigned int signatureLength;
    std::FILE* signatureFP = std::fopen(signatureFile.c_str(), "rb");
    if (!signatureFP) {
        std::cerr << "Failed to open signature file for reading." << std::endl;
        RSA_free(rsa);
        return false;
    }
    signatureLength = std::fread(signature, sizeof(unsigned char), sizeof(signature), signatureFP);
    std::fclose(signatureFP);

    int result = RSA_verify(NID_sha256, reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), signature, signatureLength, rsa);
    RSA_free(rsa);
    if (result != 1) {
        std::cerr << "Failed to verify signature." << std::endl;
        return false;
    }

    std::cout << "Signature is verified successfully." << std::endl;
    return true;
}

RSA* createRSA(const std::string& keyPath, bool isPublic) {
    FILE* fp = fopen(keyPath.c_str(), "rb");
    if (!fp) {
        // 处理打开密钥文件失败的情况
        std::cout<<"file open fail"<<std::endl;
        return nullptr;
    }

    RSA* rsaKey = nullptr;
    if (isPublic) {
        rsaKey = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    } else {
        rsaKey = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
    }

    fclose(fp);
    return rsaKey;
}

int rsaEncrypt(std::string plaintext, const std::string& publicKeyPath, const std::string& encryptedPath) {
    std::ofstream encryptedFile(encryptedPath, std::ios::binary);
    if (!encryptedFile) {
        // 处理打开密文文件失败的情况
        std::cout<<"open encryptedfile fail"<<std::endl;
        return -1;
    }
	
	std::FILE* publicKeyFP = std::fopen(publicKeyPath.c_str(), "rb");
    if (!publicKeyFP) {
        std::cerr << "Failed to open public key file for reading." << std::endl;
        return -1;
    }
    RSA* rsaKey = PEM_read_RSAPublicKey(publicKeyFP, nullptr, nullptr, nullptr);
    std::fclose(publicKeyFP);
    if (!rsaKey) {
        std::cerr << "Failed to read public key." << std::endl;
        encryptedFile.close();
        return -1;
    }

    int encryptedLen = RSA_size(rsaKey);
    std::vector<unsigned char> encryptedText(encryptedLen);

    int result = RSA_public_encrypt(plaintext.size(), reinterpret_cast<const unsigned char*>(plaintext.data()),
                                    encryptedText.data(), rsaKey, RSA_PKCS1_PADDING);
    if (result == -1) {
        // 处理加密失败的情况
        std::cout<<"encrypt fail too"<<std::endl;
        encryptedFile.close();
        RSA_free(rsaKey);
        return -1;
    }

    encryptedFile.write(reinterpret_cast<const char*>(encryptedText.data()), result);

    encryptedFile.close();
    RSA_free(rsaKey);
    return 0;
}

int rsaDecrypt(const std::string& encryptedPath, const std::string& privateKeyPath, const std::string& decryptedPath) {
    std::ifstream encryptedFile(encryptedPath, std::ios::binary);
    if (!encryptedFile) {
        // 处理打开密文文件失败的情况
        std::cout<<"de encryptfile fail"<<std::endl;
        return -1;
    }

    std::ofstream decryptedFile(decryptedPath, std::ios::binary);
    if (!decryptedFile) {
        // 处理打开解密后的文件失败的情况
        std::cout<<"de decryptfile fail"<<std::endl;
        encryptedFile.close();
        return -1;
    }

    std::vector<unsigned char> encryptedText((std::istreambuf_iterator<char>(encryptedFile)),
                                             std::istreambuf_iterator<char>());

    RSA* rsaKey = createRSA(privateKeyPath, false);
    if (!rsaKey) {
        // 处理加载私钥失败的情况
        std::cout<<"prikey fail"<<std::endl;
        encryptedFile.close();
        decryptedFile.close();
        return -1;
    }

    int decryptedLen = RSA_size(rsaKey);
    std::vector<unsigned char> decryptedText(decryptedLen);

    int result = RSA_private_decrypt(encryptedText.size(), encryptedText.data(), decryptedText.data(), rsaKey,
                                     RSA_PKCS1_PADDING);
    if (result == -1) {
        // 处理解密失败的情况
        std::cout<<"decrypt fail too"<<std::endl;
        encryptedFile.close();
        decryptedFile.close();
        RSA_free(rsaKey);
        return -1;
    }

    decryptedFile.write(reinterpret_cast<const char*>(decryptedText.data()), result);

    encryptedFile.close();
    decryptedFile.close();
    RSA_free(rsaKey);
    return 0;
}

int main() {
	double timestamp=clock();
	std::cout<<"time is:"<<timestamp<<std::endl;
    const std::string encryptedPath = "encrypted.txt";
    const std::string decryptedPath = "decrypted.txt";
    std::string signatureFile = "signature.bin";
    std::string privateKeyFile = "private_key.pem";
    std::string publicKeyFile = "public_key.pem";

	std::ifstream srcFile("../jsonfile/topoadd.json",std::ios::binary);
	if(!srcFile.is_open()){
		std::cout<<"Fail to open json file"<<std::endl; 
	}
	std::stringstream buffer;
    buffer << srcFile.rdbuf();
	std::string plaintext=buffer.str();
	std::cout<<plaintext<<std::endl;
    
    // 生成RSA密钥对
    if (!generateRSAKeyPair(privateKeyFile, publicKeyFile)) {
        std::cerr << "Failed to generate RSA key pair." << std::endl;
        return 1;
    }

    // 使用私钥对消息进行签名
    if (!signMessage(privateKeyFile, plaintext, signatureFile)) {
        std::cerr << "Failed to sign the message." << std::endl;
        return 1;
    }

    // 使用公钥验证签名
    if (!verifySignature(publicKeyFile, plaintext, signatureFile)) {
        std::cerr << "Failed to verify the signature." << std::endl;
        return 1;
    }

    // 加密
    int result = rsaEncrypt(plaintext, publicKeyFile, encryptedPath);
    if (result == -1) {
        // 处理加密失败的情况
        std::cout<<"encrypt fail"<<std::endl;
        return -1;
    }

    // 解密
    result = rsaDecrypt(encryptedPath, privateKeyFile, decryptedPath);
    if (result == -1) {
        // 处理解密失败的情况
        std::cout<<"decrypt fail"<<std::endl;
        return -1;
    }

    // 验证
    std::ifstream decryptedFile(decryptedPath, std::ios::binary);


    std::string decryptedText((std::istreambuf_iterator<char>(decryptedFile)), std::istreambuf_iterator<char>());

    if (plaintext == decryptedText) {
        std::cout << "encrypt decrypt success!" << std::endl;
    } else {
        std::cout << "encrypt decrypt fail!" << std::endl;
    }

    decryptedFile.close();
    double timestamp_end=clock();
//	std::cout<<"time is:"<<timestamp_end<<std::endl;
	std::cout<<"RSA cost time is:"<<(float)(timestamp_end-timestamp)/CLOCKS_PER_SEC<<"s"<<std::endl;
    return 0;
}
