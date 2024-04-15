#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
#include <string>
#include <string.h>
#include <time.h>
#include <sstream>
#include <iostream>
#include <json/json.h>

void handleErrors(void);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
			unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
			unsigned char *iv, unsigned char *plaintext);

char *get_file(char *filename, unsigned int *size)
{
	FILE	*file;
	char	*buffer;
	int	file_size, bytes_read;
    
	file = fopen(filename, "rb");
	if (file == NULL)
		return 0;
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	fseek(file, 0, SEEK_SET);
	buffer = new char [file_size + 1];
	bytes_read = (int)fread(buffer, sizeof(char), file_size, file);
	if (bytes_read != file_size)
	{
		delete [] buffer;
		fclose(file);
		return 0;
	}
	fclose(file);
	buffer[file_size] = '\0';

	if (size != NULL)
	{
		*size = file_size;
	}
	return buffer;
}

int write_file(char *filename, const char *bytes, int size)
{
    FILE *fp = fopen(filename, "wb");
    int ret;
    
    if (fp == NULL)
    {
        perror("Unable to open file for writing");
        return -1;
    }
    
    ret = fwrite(bytes, sizeof(char), size, fp);
    
    if (ret != size)
    {
        printf("fwrite didnt write all data\n");
	fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}
void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
			unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/*
	 * Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/*
	 * Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		handleErrors();
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
			unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/*
	 * Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary.
	 */
	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/*
	 * Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}
int main() {
	double timestamp=clock();
	std::cout<<"time is:"<<timestamp<<std::endl;
	
	
	std::ifstream srcFile("../jsonfile/topoadd.json",std::ios::binary);
	if(!srcFile.is_open()){
		std::cout<<"Fail to open json file"<<std::endl; 
	}
	std::stringstream buffer;
    buffer << srcFile.rdbuf();
	std::string messnew=buffer.str();
	std::cout<<messnew<<std::endl;
	
	
    // 创建 EC_KEY 对象并设置椭圆曲线参数
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    
    // 生成 EC_KEY 的公私钥对
    EC_KEY_generate_key(ec_key);
    
    
    // 设置签名的消息内容
    unsigned char* message = (unsigned char*)messnew.c_str();
//    unsigned char* message = (unsigned char*)"Hello, World!";
    size_t message_len = strlen((char*)message);
    
    // 使用私钥对消息进行签名
    ECDSA_SIG* signature = ECDSA_do_sign(message, message_len, ec_key);
    
    // 将签名序列化为 DER 编码格式
    unsigned char* der_signature = NULL;
    int der_signature_len = i2d_ECDSA_SIG(signature, &der_signature);
    
    // 使用公钥和签名来验证消息的完整性
    int result = ECDSA_do_verify(message, message_len, signature, ec_key);
    
    if (result == 1) {
        printf("Signature is valid.\n");
    } else if (result == 0) {
        printf("Signature is invalid.\n");
    } else {
        printf("Signature verification error.\n");
    }
    
    // 释放内存和资源
    ECDSA_SIG_free(signature);
    EC_KEY_free(ec_key);
    free(der_signature);
    
//    double timestamp_signend=clock();
//	std::cout<<"time is:"<<timestamp_signend<<std::endl;
//	std::cout<<"cost sign time is:"<<timestamp_signend-timestamp<<std::endl;
	
	const int KEY_SIZE = 2048;
    const int IV_SIZE = 1024;

    // Generate a random key
    unsigned char key[KEY_SIZE];
    if (RAND_bytes(key, KEY_SIZE) != 1) {
        std::cerr << "Error generating random key" << std::endl;
        return 1;
    }

    // Save the key to a file
    std::ofstream keyFile("key.txt", std::ios::out | std::ios::binary);
    if (!keyFile) {
        std::cerr << "Error opening key file" << std::endl;
        return 1;
    }
    keyFile.write(reinterpret_cast<const char*>(key), KEY_SIZE);
    keyFile.close();

    // Generate a random IV
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        std::cerr << "Error generating random IV" << std::endl;
        return 1;
    }

    // Save the IV to a file
    std::ofstream ivFile("iv.txt", std::ios::out | std::ios::binary);
    if (!ivFile) {
        std::cerr << "Error opening IV file" << std::endl;
        return 1;
    }
    ivFile.write(reinterpret_cast<const char*>(iv), IV_SIZE);
    ivFile.close();

    std::cout << "Key and IV successfully generated and saved." << std::endl;
    
    
    unsigned char *ciphertext = (unsigned char *)malloc(strlen((char *)message) * 2);
	if (ciphertext == NULL)
	{
		perror("malloc failed");
		return -1;
	}
	
	
	int ciphertext_len;
	
		/* Encrypt the plaintext */
	ciphertext_len = encrypt (message, strlen ((char *)message), key, iv, ciphertext);
	
		/* Do something useful with the ciphertext here */
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
	
//	write_file((char *)"file.enc", (char *)ciphertext, ciphertext_len);
		
	//	/* Message to be encrypted */
	//	char *filename = (char *)argv[3];
	unsigned int size = strlen((char*)message);
//	unsigned char *ciphertext = (unsigned char *)get_file("file.enc", &size);
	
		/* Buffer for the decrypted text */
	unsigned char* decryptedtext = (unsigned char* )malloc(size);
	if (decryptedtext == NULL)
	{
		perror("malloc failed");
		return -1;
	}
	
	
	int decryptedtext_len = size;
	
//	printf("Ciphertext is:\n");
//	BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
	
		/* Decrypt the ciphertext */
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);
		/* Add a NULL terminator. We are expecting printable text */
	decryptedtext[decryptedtext_len] = '\0';
	
		/* Show the decrypted text */
	printf("Decrypted text is:\n");
	printf("%s\n", decryptedtext);
	
	if(memcmp(message, decryptedtext, strlen((char*)message) + 1) == 0){
		std::cout<<"encrypt decrypt success"<<std::endl;
	}
	else{
		std::cout<<"encrypt decrypt fail"<<std::endl;
	}
		
//	write_file((char *)"file.txt", (char *)decryptedtext, decryptedtext_len);
	
	
	
	double timestamp_end=clock();
//	std::cout<<"time is:"<<timestamp_end<<std::endl;
	std::cout<<"our algorithm cost time is:"<<(float)(timestamp_end-timestamp)/CLOCKS_PER_SEC<<"s"<<std::endl;

    return 0;
}
