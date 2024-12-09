#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <dlfcn.h>

#define PACKED __attribute__ ((packed))


#define FW_IDENTITY_LEN					16
#define POWER_CHIP_FW_LABEL				16
#define POWER_CHIP_MODEL_INFO_LEN		16
#define BUF_SIZE (100*1024)
#define POWER_CHIP_FW_SIZE_MAX			BUF_SIZE
#define IRPS5401_FW						"irps5401_U1_V"
#define IRPS5401_SUBMODEL				"IRPS5401_U1"
#define POWER_FW						IRPS5401_FW
#define POWER_SIGNATURE					"$FW@MyCompany"
#define POWER_MODEL						"MYDEV_POWER"
#define POWER_SUBMODEL					IRPS5401_SUBMODEL
#define MAX_BIN_SIZE					(100*1024)			//暂定100K大小
#define IRPS5401_VERSION_ADDR			0x002A

#define PRIVATE_KEY_PATH		"power_chip_private_key.pem"
#define PUBLIC_KEY_PATH			"power_chip_public.pem"

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

typedef struct
{
    uint8_t		Signature[FW_IDENTITY_LEN];				//内容固定为POWER_SIGNATURE
    uint8_t		DevModel[POWER_CHIP_FW_LABEL];			//内容固定为POWER_MODEL
    uint8_t		SubModel[POWER_CHIP_MODEL_INFO_LEN];	//内容与电源芯片有关，如"IRPS5401_U1"、"XDPE12284C_U21"
    uint8_t		FwRev;									//固件版本
    uint32_t	ImgOffset;								//官方固件的位置
    uint32_t	ImgSize;								//官方固件的大小
    uint32_t	ImgCRC32;								//固件的CRC32值
    uint32_t	sha256_sig_offset;						//SHA256 签名位置
    uint8_t		Reserved[59];							//保留
    uint32_t	HdrCRC32;								//以上内容的CRC32值
}PACKED power_chip_hd_t;

typedef struct
{
	uint16_t reg;
	uint8_t value;
	uint8_t mask;
}PACKED power_chip_data_t;

unsigned long  CrcLookUpTable[256] =
{
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
	0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
	0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
	0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
	0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
	0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
	0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
	0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
	0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,

	0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
	0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
	0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
	0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
	0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
	0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
	0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
	0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
	0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,

	0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
	0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
	0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
	0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
	0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
	0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
	0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
	0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
	0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,

	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
	0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
	0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
	0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
	0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
	0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
	0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
	0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
	0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};

unsigned int CalculateCRC32(unsigned char *Buffer, unsigned int Size)
{
	unsigned int i,crc32 = 0xFFFFFFFF;

	/* Read the data and calculate crc32 */	
	for(i = 0; i < Size; i++)
	crc32 = ((crc32) >> 8) ^ CrcLookUpTable[(Buffer[i]) ^ ((crc32) & 0x000000FF)];
	
	return ~crc32;
}

void DoCRC32(unsigned int *crc32, unsigned char Data)
{
	*crc32=((*crc32) >> 8) ^ CrcLookUpTable[Data ^ ((*crc32) & 0x000000FF)];
	return;
}

int vr_irps_fw_image_crc_verify(char *file)
{
    FILE *fp;
    char buf[256];
    int start_crc = 0;
    int len;
    unsigned int crc32 = 0xFFFFFFFF;
    unsigned int crc32_val = 0;
    unsigned int i;

    if (NULL == file)
    {
        printf("File name is NULL\n");
        return -1;
    }

    fp = fopen(file, "r");
    if (NULL == fp)
    {
        perror("Error opening file");
        return 1;
    }

    while (NULL != fgets(buf, sizeof(buf), fp))
    {
        if (0 == start_crc)
        {
            if (0 == memcmp(buf, "//CRC32 : ", 10))
            {
                start_crc = 1;
                crc32_val = strtoul(&buf[10], NULL, 0);
                
            }

            continue;
        }

        len = strlen(buf);
        if (len < 3)
        {
            fclose(fp);
            printf("Invaild line length %d\n", len);
            return -1;
        }

        /* NOTE: Skip the "/r/n" at the end of line */
        for (i = 0; i < (len - 2); i++)
        {
            DoCRC32(&crc32, buf[i]);
        }
    }

    fclose(fp);
    printf("CRC32=%08X vs %08X\n", crc32_val, ~crc32);

    if (crc32_val != (~crc32))
    {
        printf("IRPS Firmware Image CRC32 verify failed !!!\n");
        return -1;
    }

    printf("IRPS Firmware Image CRC32 verify OK\n");
    return 0;
}

// 计算 SHA-256 哈希值
void compute_sha256(const unsigned char *data, size_t len, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(hash, &sha256);
}

// 从文件中读取私钥
RSA *load_private_key(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("Error opening private key file");
        return NULL;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (rsa == NULL) {
        fprintf(stderr, "Error reading private key from file\n");
        ERR_print_errors_fp(stderr);
    }

    return rsa;
}

// 从文件中读取公钥
RSA *load_public_key(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("Error opening public key file");
        return NULL;
    }

    RSA *rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (rsa == NULL) {
        fprintf(stderr, "Error reading public key from file\n");
        ERR_print_errors_fp(stderr);
    }

    return rsa;
}

// 使用私钥对哈希值进行签名
int sign_with_private_key(RSA *rsa, const unsigned char *hash, unsigned char *signature, unsigned int *sig_len) {
    return RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, rsa);
}

// 验证签名
int verify_signature(RSA *rsa, const unsigned char *hash, const unsigned char *signature, unsigned int sig_len) {
    return RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, rsa);
}

int rsasignature(char *data, size_t data_len, char *signature, unsigned int *sig_len) {

    // 计算 SHA-256 哈希值
    unsigned char hash[SHA256_DIGEST_LENGTH];
    compute_sha256((const unsigned char *)data, data_len, hash);

    printf("SHA-256 Hash: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    // 从文件中加载私钥
    RSA *private_key = load_private_key(PRIVATE_KEY_PATH);
    if (private_key == NULL) {
        return -1;
    }

    // 使用私钥对哈希值进行签名
    if (!sign_with_private_key(private_key, hash, signature, sig_len)) {
        printf("Signature failed.\n");
        RSA_free(private_key);
        return -1;
    }

    printf("Signature length: %u\n", *sig_len);

    // 从文件中加载公钥
    RSA *public_key = load_public_key(PUBLIC_KEY_PATH);
    if (public_key == NULL) {
        RSA_free(private_key);
        return -1;
    }

    // 验证签名
    if (!verify_signature(public_key, hash, signature, *sig_len)) {
        fprintf(stderr, "Verification failed.\n");
        RSA_free(private_key);
        RSA_free(public_key);
        return -1;
    }

    printf("Signature verified successfully.\n");

    // 清理资源
    RSA_free(private_key);
    RSA_free(public_key);

    return 0;
}

int txt2bin(char *filename)
{
	power_chip_hd_t *head = NULL;
	char buf[256];
	uint32_t version;
    int len;
    uint32_t  i;
	uint32_t  register_num = 0;
	power_chip_data_t data;
	char *bin_buf = NULL;
	int num = 0;
	unsigned char *signature = NULL;
    unsigned int sig_len;
	int ret = 0;
	char bin_name[32] = {0};
	char *p_image_offset = NULL;
	uint32_t temp_reg, temp_value, temp_mask;
	
	
	FILE *fp = fopen(filename, "r");
    if (NULL == fp)
    {
        perror("Error opening file");
        return 1;
    }

	bin_buf = malloc(MAX_BIN_SIZE);
	if(NULL == bin_buf)
	{
		perror("malloc bin_buf");
		fclose(fp);
		return -1;
	}
	memset(bin_buf, 0, MAX_BIN_SIZE);
	head = (power_chip_hd_t *)bin_buf;
	memcpy(&head->Signature, POWER_SIGNATURE, strlen(POWER_SIGNATURE));
	memcpy(&head->DevModel, POWER_MODEL, strlen(POWER_MODEL));
	memcpy(&head->SubModel, POWER_SUBMODEL, strlen(POWER_SUBMODEL));
	head->ImgOffset = sizeof(power_chip_hd_t);
	p_image_offset = bin_buf + sizeof(power_chip_hd_t);
    while (NULL != fgets(buf, sizeof(buf), fp))
    {
		memset(&data, 0, sizeof(data));
		if (0 == memcmp(buf, "//", 2))
        {
            continue;
        }
        len = strlen(buf);
        if (len < 8)
        {
            fclose(fp);
            printf("Invaild line length %d\n", len);
            return -1;
        }

		num = sscanf(buf, "%4hx %2hhx %2hhx", &data.reg, &data.value, &data.mask);
		if(3 != num)
		{
			perror("format fail");
			fclose(fp);
			free(bin_buf);
			printf("Resolve txt file fail.\n");
			return -1;
		}
		if(IRPS5401_VERSION_ADDR == data.reg)
		{
			head->FwRev = data.value;
		}
		memcpy(p_image_offset, (char *)&data, sizeof(data));
		register_num++;
		p_image_offset = p_image_offset + sizeof(data);
    }
	fclose(fp);
	head->ImgSize = register_num * sizeof(data);
	head->ImgCRC32 = CalculateCRC32(bin_buf + sizeof(power_chip_hd_t), head->ImgSize);
	head->sha256_sig_offset = sizeof(power_chip_hd_t) + head->ImgSize;
	head->HdrCRC32 = CalculateCRC32((unsigned char *)head, sizeof(power_chip_hd_t) - sizeof(head->HdrCRC32));
	signature = (unsigned char *)(bin_buf + head->sha256_sig_offset);
	ret = rsasignature(bin_buf, head->sha256_sig_offset, signature, &sig_len);
	if(ret != 0)
	{
		free(bin_buf);
		printf("Resolve txt file fail.\n");
		return -1;
	}

	memset(bin_name, 0, sizeof(bin_name));
	snprintf(bin_name, sizeof(bin_name), "%s%d.%d.bin", POWER_FW, head->FwRev>>8,head->FwRev&0xff);
	FILE *fbin = fopen(bin_name, "wb");
	if(NULL == fbin)
	{
		fclose(fbin);
		free(bin_buf);
		perror("Error to create bin file");
		return -1;
	}
	if(1 != fwrite(bin_buf, head->sha256_sig_offset + sig_len, 1, fbin))
	{
		fclose(fbin);
		free(bin_buf);
		perror("Error to write head to bin file");
		return -1;
	}

	fclose(fbin);
	free(bin_buf);
	printf("================Create bin file success, file name:%s ==================\n",bin_name);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	if(argc < 2)
	{
		printf("Please run command with power chip update file.\n");
		return -1;
	}

	ret = vr_irps_fw_image_crc_verify(argv[1]);
	if(ret != 0)
	{
		printf("Input txt file %s CRC32 verify fail!!!!!\n", argv[1]);
		return 0;
	}
	return txt2bin(argv[1]);
}

