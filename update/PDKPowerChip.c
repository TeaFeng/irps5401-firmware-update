#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/prctl.h>
#include "PDKPowerChip.h"
#include "dictionary.h"
#include "checksum.h"
#include "libi2c.h"
#include "PDKPlatform.h"
#include "IPMI_OEMCmds.h"
#include "IPMIDefs.h"
#include "Debug.h"
#include "OSPort.h"

#define IRPS5401_PAGE_MIN				0
#define IRPS5401_PAGE_MAX				0x17
#define IRPS5401_PAGE_SIZE				256
#define IRPS5401_I2C_DEV				"/dev/i2c4"
#define IRPS5401_I2C_ADDR				0x14			//7bit address
#define IRPS5401_CONF_WRITE_MAX_COUNT	5
#define IRPS5401_USER_WRITE_MAX_COUNT	26
#define POWER_CHIP_CONF_WARN_COUNT		0				//剩余升级次数低于此值会要求特权命令才能升级
#define POWER_CHIP_USER_WARN_COUNT		0				//剩余升级次数低于此值会要求特权命令才能升级
#define IRPS5401_SILICON_VERSION_MIN	2				//支持固件升级的irps5401芯片的最低硬件版本

#define FW_IDENTITY_LEN					16
#define POWER_CHIP_FW_LABEL				16
#define POWER_CHIP_MODEL_INFO_LEN		16
#define POWER_CHIP_PROGRAM_TIME			(250*1000)		//电源芯片缓存当前寄存器值到OTP需要使用的时间,单位微秒
#define POWER_CHIP_FW_IMG_SIGN			"$FW@MyCompany"	//固件签名标志，一般使用公司或者设备名称
#define DEVMODEL_MYDEV_POWER	   		"MYDEV_POWER"	//设备型号，与POWER_CHIP_FW_IMG_SIGG共同构成固件类型的识别
#define MYDEV_IRPS5401_U1				"IRPS5401_U1"	//要升级的具体设备，在board_power_chip_info中关联到具体器件信息
#define IRPSFW_IMG_FILE            		"/var/powerChip.bin"
#define IRPSFW_IMG_USED_FILE       		"/var/powerChip.bin_used.bin"
#define POWER_CHIP_FILE					IRPSFW_IMG_FILE
#define POWER_CHIP_USED_FILE			IRPSFW_IMG_USED_FILE
#define POWER_CHIP_IMG_SIGN_PUBLIC_FILE	"/etc/power_chip_public.pem"		//解密用的公钥位置
#define POWER_CHIP_IMG_DIGEST_SIGN_SIZE	128
#define BUF_SIZE						(100*1024)
#define POWER_CHIP_FW_SIZE_MAX			BUF_SIZE

//register define
#define IRPS5401_REG_START				0x0000
#define IRPS5401_REG_END				0x17FF
#define IRPS5401_REG_0B					0x000B		//寄存器意义不明，官方未说明，升级时使用
#define IRPS5401_VERSION_REG			0x002A
#define IRPS5401_SWITCHE_EN_REG			0x0038		//[bit4-0]=1 means LDO-D-C-B-A is disable
#define IRPS5401_SWITCHE_COMBINE_REG	0x0023		//bit4=1 则将D的控制器关闭
#define IRPS5401_NVRAM_IMAGE_REG		0x0052
#define IRPS5401_CONF_LEFT_REG			0x0056
#define IRPS5401_USER_LEFT_REG0			0x0058
#define IRPS5401_USER_LEFT_REG1			0x005A
#define IRPS5401_PASSWD_REG				0x006C
#define IRPS5401_LOCK_REG				0x0086
#define IRPS5401_NVM_CMD_REG			0x0088
#define IRPS5401_NVM_CMD_REG_H			0x0089
#define IRPS5401_TRIM_TRY_PWD_REG0		0x008A
#define IRPS5401_TRIM_TRY_PWD_REG1		0x008B
#define IRPS5401_SILICON_VERSION_REG	0x00FD
#define IRPS5401_PAGE_REG				0xFF

//#define __PC_DBG						//取消注释，调试时执行升级流程但不实际升级，避免耗尽升级次数
#define PRINT		//printf			//取消注释可以打开部分调试打印

typedef power_chip_info_t irps5401_info_t;
typedef otp_section	irps5401_opt_section;
typedef struct{
	otp_section	section;
	INT8U page;
	INT16U sec_start;
	INT16U sec_end;
}section_info_t;

typedef section_info_t irps5401_section_info;

typedef struct
{
    INT8U		Signature[FW_IDENTITY_LEN];				//内容固定为POWER_CHIP_FW_IMG_SIGN
    INT8U		DevModel[POWER_CHIP_FW_LABEL];			//内容固定为DEVMODEL_MYDEV_POWER
    INT8U		SubModel[POWER_CHIP_MODEL_INFO_LEN];	//内容与电源芯片有关，如"IRPS5401_U1"、"XDPE12284C_U21"
    INT8U		FwRev;									//固件版本
    INT32U		ImgOffset;								//官方固件的位置
    INT32U		ImgSize;								//官方固件的大小
    INT32U		ImgCRC32;								//固件的CRC32值
    INT32U		sha256_sig_offset;						//SHA256 签名位置
    INT8U		Reserved[59];							//保留
    INT32U		HdrCRC32;								//以上内容的CRC32值
}PACKED power_chip_hd_t;

//固件bin文件实际内容的组织结构
typedef struct
{
	INT16U reg;
	INT8U value;
	INT8U mask;
}PACKED power_chip_data_t;

typedef struct
{	INT8U Devinst;
	INT8U *DevModel;	
	INT8U *SubModel;
	irps5401_info_t chip_info;
	void *section_info;
	INT8U section_count;
}board_power_chip_info_t;

typedef enum
{
    POWER_REG_COMMON_SECTION,
    POWER_REG_LOOP_A_SECTION,
    POWER_REG_LOOP_B_SECTION,
    POWER_REG_LOOP_C_SECTION,
    POWER_REG_LOOP_D_SECTION,
    POWER_REG_LOOP_LDO_SECTION,
}power_chip_reg_loop_section;

typedef struct{
	power_chip_reg_loop_section reg_section;
	INT16U start_addr;
	INT16U end_addr;
	bool loop_en;
}power_chip_reg_section_info_t;

//线程锁，用于与其他线程互斥访问电源芯片所在I2C链路
OS_THREAD_MUTEX_DEFINE(PowerChipIrps5401U1Mutex);

power_chip_req_t power_chip_req[POWER_CHIP_COUNT_MAX] ;

power_chip_update_t power_chip_update[POWER_CHIP_COUNT_MAX];

static irps5401_section_info irps5401_sec[] = {
	{POWER_CHIP_SECTION_CONF,	0x00,	0x0000,	0x0001},
	{POWER_CHIP_SECTION_USER,	0x00,	0x0020,	0x003B},
	{POWER_CHIP_SECTION_USER,	0x04,	0x0420,	0x042B},
	{POWER_CHIP_SECTION_USER,	0x06,	0x0600,	0x06FF},
	{POWER_CHIP_SECTION_USER,	0x07,	0x0700,	0x07FF},
	{POWER_CHIP_SECTION_USER,	0x08,	0x0820,	0x082B},
	{POWER_CHIP_SECTION_USER,	0x0A,	0x0A00,	0x0AFF},
	{POWER_CHIP_SECTION_USER,	0x0B,	0x0B00,	0x0BFF},
	{POWER_CHIP_SECTION_USER,	0x0C,	0x0C20,	0x0C2B},
	{POWER_CHIP_SECTION_USER,	0x0E,	0x0E00,	0x0EFF},
	{POWER_CHIP_SECTION_USER,	0x0F,	0x0F00,	0x0FFF},
	{POWER_CHIP_SECTION_USER,	0x10,	0x1020,	0x102B},
	{POWER_CHIP_SECTION_USER,	0x12,	0x1200,	0x12FF},
	{POWER_CHIP_SECTION_USER,	0x13,	0x1300,	0x13FF},
	{POWER_CHIP_SECTION_USER,	0x14,	0x1420,	0x1421},
	{POWER_CHIP_SECTION_USER,	0x16,	0x1600,	0x16FF},
	{POWER_CHIP_SECTION_USER,	0x17,	0x1700,	0x17FF}
};

board_power_chip_info_t board_power_chip_info[] = {
	{
		0,	
		DEVMODEL_MYDEV_POWER,	
		MYDEV_IRPS5401_U1,	
	{
		IRPS5401_I2C_DEV,
		IRPS5401_I2C_ADDR,
		IRPS5401_PAGE_REG,
		IRPS5401_PAGE_MIN,
		IRPS5401_PAGE_MAX,
		IRPS5401_PAGE_SIZE
	}, 
	irps5401_sec, 
	sizeof(irps5401_sec)/sizeof(irps5401_sec[0])
	}
};

//寄存器分布
power_chip_reg_section_info_t irps5401_reg_section[]= {
	{POWER_REG_COMMON_SECTION,		0x0000,	0x03FF,	true},
	{POWER_REG_LOOP_A_SECTION,		0x0400,	0x07FF,	true},
	{POWER_REG_LOOP_B_SECTION,		0x0800,	0x0BFF,	true},
	{POWER_REG_LOOP_C_SECTION,		0x0C00,	0x0FFF,	true},
	{POWER_REG_LOOP_D_SECTION,		0x1000,	0x13FF,	true},
	{POWER_REG_LOOP_LDO_SECTION,	0x1400,	0x17FF,	true}
};
//官方明确指出不需要校验的寄存器
INT16U verify_ignored_reg[] = {0x16F9, 0x16FB, 0x16FD, 0x17B0, 0x17BC};


pthread_t PowerChipFwUpdateThreadID[POWER_CHIP_COUNT_MAX]  = {0};

//校验的大部分时间都耗费在了通过I2C读取寄存器上，而不是寄存器内容的比对上，因此将读取寄存器的时间包含到校验进度中，
//对各步骤的百分比施加权重
typedef enum
{
    VERIFY_PROGRESS_PREPARE = 10,
	VERIFY_PROGRESS_REG_READ = 90,
	VERIFY_PROGRESS_REG_COMPARE = 100,	
} VERIFY_PROGRESS;



/*****************************************************************************
 * Function     : PDK_Irps5401U1MutexBlockLock
 * Description  : irps5401 u1 pthread block lock 
 * Params       : 
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/

static int PDK_Irps5401U1MutexBlockLock(void)
{
    int LockRet = -1;
    OS_THREAD_MUTEX_ACQUIRE_LOCK(&PowerChipIrps5401U1Mutex, LockRet);
    if (LockRet == -1)
    {
        TWARN("Irps5401 Mutex Lock Failed\n");
        return -1;
    }
    return 0;
}

/*****************************************************************************
 * Function     : PDK_Irps5401U1MutexLock
 * Description  : irps5401 u1 pthread lock 
 * Params       : 
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401U1MutexLock(void)
{
    int LockRet = -1;
    OS_THREAD_MUTEX_ACQUIRE_TRY(&PowerChipIrps5401U1Mutex, LockRet);
    if (LockRet == -1)
    {
        TWARN("CDFP Mutex Lock Failed\n");
        return -1;
    }
    return 0;
}

/*****************************************************************************
 * Function     : PDK_Irps5401U1Unlock
 * Description  : irps5401 u1 release pthread lock 
 * Params       : 
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int  PDK_Irps5401U1Unlock(void)
{
    OS_THREAD_MUTEX_RELEASE(&PowerChipIrps5401U1Mutex);
    return 0;
}

/*****************************************************************************
 * Function     : PDK_Irps5401U1MuxLock
 * Description  : irps5401 u1 unblock pthread lock 
 * Params       : Lock:0-unlock,other-lock
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
int PDK_Irps5401U1MuxLock(int Lock)
{
    if (Lock)
        return PDK_Irps5401U1MutexLock();

    return PDK_Irps5401U1Unlock();
}
/*****************************************************************************
 * Function     : PDK_Irps5401U1MuxLock
 * Description  : irps5401 u1 block pthread lock 
 * Params       : Lock:0-unlock, other-lock
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
int PDK_Irps5401MuxBlockLock(int Lock)
{
    if (Lock)
        return PDK_Irps5401U1MutexBlockLock();

    return PDK_Irps5401U1Unlock();
}

/*****************************************************************************
 * Function     : PDK_Irps5401SetPage
 * Description  : set irps5401 access page 
 * Params       : page,0x0-0x17
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401SetPage(irps5401_info_t chip_info, INT8U page)
{
	ssize_t ret = 0;
	INT8U send_data[2] = {chip_info.page_reg, page};
	if(chip_info.page_min > page || chip_info.page_max < page)
		return -1;
	if(sizeof(send_data) != i2c_master_write(chip_info.i2c_dev, chip_info.slave_addr, send_data, sizeof(send_data)))
	{
		perror("PDK_Irps5401SetPage");
		return -1;
	}
	return 0;
}

/*****************************************************************************
 * Function     : PDK_Irps5401GetPage
 * Description  : get irps5401 access page 
 * Params       : chip_info:power chip info struct;page:pointer to page
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401GetPage(irps5401_info_t chip_info, INT8U *page)
{
	INT8U send_data = chip_info.page_reg;
	INT8U read_data = 0;

	if(NULL == page)
		return -1;

	if(0 != i2c_writeread(chip_info.i2c_dev, chip_info.slave_addr, &send_data, &read_data, sizeof(send_data),sizeof(read_data)))
	{
		perror("PDK_Irps5401GetPage");
		return -1;
	}
	*page = read_data;
	return 0;
}


/*****************************************************************************
 * Function     : PDK_PowertChipSetPage
 * Description  : set  access page 
 * Params       : chip_info:power chip info struct;reg:destination register
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_PowertChipSetPage(power_chip_info_t chip_info, INT16U reg)
{
	ssize_t ret = 0;

	if(chip_info.page_size <=0 )
		return -1;
	INT8U page = reg / chip_info.page_size;
	INT8U send_data[2] = {chip_info.page_reg, page};

	if(chip_info.page_min > page || chip_info.page_max < page)
		return -1;
	if(NULL == chip_info.i2c_dev)
		return -1;

	ret = i2c_master_write(chip_info.i2c_dev, chip_info.slave_addr, send_data, sizeof(send_data));
	if(ret != sizeof(send_data))
	{
		perror("PDK_PowertChipSetPage");
		return -1;
	}
	return 0;
}


/*****************************************************************************
 * Function     : PDK_PowertChipGetPage
 * Description  : Get access page 
 * Params       : chip_info:power chip info struct; page:pointer to page
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_PowertChipGetPage(power_chip_info_t chip_info, INT8U *page)
{
	ssize_t ret = 0;
	INT8U send_data = chip_info.page_reg;
	INT8U read_data = 0;

	if(NULL == chip_info.i2c_dev)
		return -1;

	ret = i2c_writeread(chip_info.i2c_dev, chip_info.slave_addr, &send_data, &read_data, sizeof(send_data),sizeof(read_data));
	if(ret != sizeof(send_data))
	{
		perror("PDK_PowertChipGetPage");
		return -1;
	}
	*page = read_data;
	return 0;
}


/*****************************************************************************
 * Function     : PDK_Irps5401WriteByteWithPageSet
 * Description  : set page ,and send a byte to irps5401
 * Params       : chip_info:power chip info struct;reg:16 bit register address; data:data to be sent
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
int PDK_Irps5401WriteByteWithPageSet(irps5401_info_t chip_info, INT16U reg, INT8U data)
{
	INT8U page = reg / chip_info.page_size;
	INT8U byte_address = reg % chip_info.page_size;
	INT8U send_data[2] = {byte_address, data};
	if(0 == PDK_Irps5401SetPage(chip_info, page))
	{
		if(sizeof(send_data) == i2c_master_write(chip_info.i2c_dev, chip_info.slave_addr, send_data, sizeof(send_data)))
		{
			return 0;
		}
		else
		{	
			perror("PDK_Irps5401WriteByteWithPageSet error");
			return -1;
		}
	}
	else
	{
		return -1;
	}
}


/*****************************************************************************
 * Function     : PDK_Irps5401ReadByteWithPageSet
 * Description  : set page ,and read a byte from irps5401
 * Params       : chip_info:power chip info struct;reg:16 bit register address; data:data buf
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
int PDK_Irps5401ReadByteWithPageSet(irps5401_info_t chip_info, INT16U reg, INT8U *data)
{
	INT8U page = reg / chip_info.page_size;
	INT8U byte_address = reg % chip_info.page_size;
	INT8U send_data = byte_address;
	INT8U read_data = 0;

	if(NULL == data)
		return -1;
	if(0 == PDK_Irps5401SetPage(chip_info, page))
	{
		if(0 == i2c_writeread(chip_info.i2c_dev, chip_info.slave_addr, &send_data, &read_data, sizeof(send_data), sizeof(read_data)))
		{
			*data = read_data;
			return 0;
		}
		else
		{	
			perror("PDK_Irps5401ReadByteWithPageSet error");
			return -1;
		}
	}
	else
	{
		return -1;
	}
}


/*****************************************************************************
 * Function     : PDK_Irps5401WriteByteWithoutPageSet
 * Description  : just send a byte to irps5401
 * Params       : chip_info:power chip info struct;reg:8 bit register address; data:data to be sent
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401WriteByteWithoutPageSet(irps5401_info_t chip_info, INT8U reg, INT8U data)
{
	INT8U send_data[2] = {reg, data};
	if(sizeof(send_data) == i2c_master_write(chip_info.i2c_dev, chip_info.slave_addr, send_data, sizeof(send_data)))
	{
		return 0;
	}
	else
	{	
		perror("PDK_Irps5401WriteByteWithoutPageSet error");
		return -1;
	}
}

/*****************************************************************************
 * Function     : PDK_Irps5401ReadWordWithPageSet
 * Description  : set page ,and read a word from irps5401
 * Params       : chip_info:power chip info struct;reg:16 bit register address; data:data buf
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/

static int PDK_Irps5401ReadWordWithPageSet(irps5401_info_t chip_info, INT16U reg, uint16 *data)
{
	INT8U page = reg / chip_info.page_size;
	INT8U byte_address = reg % chip_info.page_size;
	INT8U send_data = byte_address;
	INT8U read_data[sizeof(INT16U)] = {0, 0};

	if(NULL == data)
		return -1;
	if(0 == PDK_Irps5401SetPage(chip_info, page))
	{
		if(0 == i2c_writeread(chip_info.i2c_dev, chip_info.slave_addr,  &send_data, &read_data, sizeof(send_data), sizeof(read_data)))
		{
			*data = read_data[0];
			*data |= read_data[1] << 8;
			return 0;
		}
		else
		{	
			perror("PDK_Irps5401ReadWordWithPageSet error");
			return -1;
		}
	}
	else
	{
		return -1;
	}
}


/*****************************************************************************
 * Function     : PDK_Irps5401WriteWordWithPageSet
 * Description  : set page ,and write wortd to irps5401
 * Params       : chip_info:power chip info struct;reg:16 bit register address; data:data buf
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/

static int PDK_Irps5401WriteWordWithPageSet(irps5401_info_t chip_info, INT16U reg, INT16U data)
{
	INT8U page = reg / chip_info.page_size;
	INT8U byte_address = reg % chip_info.page_size;
	
	INT8U send_data[] = {byte_address, data & 0xff, data >> 8};
	if(0 == PDK_Irps5401SetPage(chip_info, page))
	{
		if(sizeof(send_data) == i2c_master_write(chip_info.i2c_dev, chip_info.slave_addr, send_data, sizeof(send_data)))
		{
			return 0;
		}
		else
		{	
			perror("PDK_Irps5401WriteWordWithPageSet error");
			return -1;
		}
	}
	else
	{
		return -1;
	}
}


/*****************************************************************************
 * Function     : PDK_Irps5401WriteByteWithoutPageSet
 * Description  : just send a word to irps5401
 * Params       : chip_info:power chip info struct;reg:8 bit register address; data:data to be sent
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401WriteWordWithoutPageSet(irps5401_info_t chip_info, INT8U reg, uint16 *data)
{
	if(NULL == data)
		return -1;

	INT8U send_data[2] = {reg, data[0], data[1]};
	if(sizeof(send_data) == i2c_master_write(chip_info.i2c_dev, chip_info.slave_addr,  send_data, sizeof(send_data)))
	{
		return 0;
	}
	else
	{	
		perror("PDK_Irps5401WriteWordWithoutPageSet error");
		return -1;
	}
}


/*****************************************************************************
 * Function     : PDK_Irps5401ReadByteWithoutPageSet
 * Description  : just read a byte from irps5401
 * Params       : chip_info:power chip info struct;reg:8 bit register address; data:data buf
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401ReadByteWithoutPageSet(irps5401_info_t chip_info, INT8U reg, INT8U *data)
{
	INT8U send_data = reg;
	INT8U read_data = 0;
	if(0 == i2c_writeread(chip_info.i2c_dev, chip_info.slave_addr,  &send_data, &read_data, sizeof(send_data), sizeof(read_data)))
	{
		*data = read_data;
		return 0;
	}
	else
	{	
		perror("PDK_Irps5401ReadByteWithoutPageSet error");
		return -1;
	}
}

/*****************************************************************************
 * Function     : PDK_Irps5401ConfWriteLeftGet
 * Description  : get left count can be written of conf section 
 * Params       : chip_info:power chip info struct;write_left:pointer to left count 
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
int PDK_Irps5401ConfWriteLeftGet(irps5401_info_t chip_info, INT8U *write_left)
{
    int      ret                = 0;
    INT16U temp_value         = 0;
    INT32U writes_left_status = 0;

    if(0 != PDK_Irps5401ReadWordWithPageSet(chip_info, IRPS5401_CONF_LEFT_REG, &temp_value))
    {
        return -1;
    }
    writes_left_status = temp_value;

    temp_value = 0;
    while(writes_left_status & 0x01)
    {
        temp_value++;
        if(temp_value >= IRPS5401_CONF_WRITE_MAX_COUNT)
        {
            break;
        }
        writes_left_status >>= 1;
    }
    temp_value = IRPS5401_CONF_WRITE_MAX_COUNT - temp_value;

    *write_left = temp_value;
    return 0;
}


/*****************************************************************************
 * Function     : PDK_Irps5401UserWritesLeftGet
 * Description  : get left count can be written of user section 
 * Params       : chip_info:power chip info struct;write_left:pointer to left count 
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
int PDK_Irps5401UserWriteLeftGet(irps5401_info_t chip_info, INT8U *write_left)
{
    int      ret                = 0;
    INT16U temp_value         = 0;
    INT32U writes_left_status = 0;

    if(0 != PDK_Irps5401ReadWordWithPageSet(chip_info, IRPS5401_USER_LEFT_REG0, &temp_value))
    {
        return -1;
    }
    writes_left_status = ((INT32U)temp_value) << 16;

    if(0 != PDK_Irps5401ReadWordWithPageSet(chip_info, IRPS5401_USER_LEFT_REG1, &temp_value))
    {
        return -1;
    }
    writes_left_status |= temp_value;

    temp_value = 0;
    while(writes_left_status & 0x01)
    {
        temp_value++;
        if(temp_value >= IRPS5401_USER_WRITE_MAX_COUNT)
        {
            break;
        }
        writes_left_status >>= 1;
    }
    temp_value = IRPS5401_USER_WRITE_MAX_COUNT - temp_value;

    *write_left = temp_value;
    return ret;
}

/*****************************************************************************
 * Function     : PDK_Irps5401VersionGet
 * Description  : get current firmware version 
 * Params       : chip_info:power chip info struct;version:pointer to version
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401FWVersionGet(irps5401_info_t chip_info, INT8U *version)
{
	INT8U data = 0;

	if(NULL == version)
		return -1;

	if(0 == PDK_Irps5401ReadByteWithPageSet(chip_info, IRPS5401_VERSION_REG, &data))
	{
		*version = data;
		return 0;
	}
	return -1;
}

/*****************************************************************************
 * Function     : PDK_Irps5401VersionGet
 * Description  : get current firmware version 
 * Params       : chip_info:power chip info struct;version:pointer to version
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
int PDK_PowerChipFWVersionGet(INT8U Devinst, INT8U *FwRevStr, INT16U *ResLen, int BMCInst)
{
	INT8U data = 0;

	if(NULL == FwRevStr)
		return -1;
	if( Devinst >= POWER_CHIP_COUNT_MAX || Devinst >= sizeof(board_power_chip_info)/sizeof(board_power_chip_info_t))
	{
		return CC_PARAM_OUT_OF_RANGE;
	}
	irps5401_info_t *chip_info = &board_power_chip_info[Devinst].chip_info;
	if(PDK_Irps5401U1MuxLock(1))return CC_NODE_BUSY;

	if(0 == PDK_Irps5401FWVersionGet(*chip_info, &data))
	{
		PDK_Irps5401U1MuxLock(0);
		*ResLen = snprintf(FwRevStr, POWER_CHIP_FW_VER_LEN, "V%u.%02u", data>>4, data&0x0f);
		return CC_NORMAL;
	}
	PDK_Irps5401U1MuxLock(0);
	return CC_UNSPECIFIED_ERR;
}

/*****************************************************************************
 * Function     : PDK_PowerChipFWVersionGetWithoutLock
 * Description  : get current firmware version without lock 
 * Params       : chip_info:power chip info struct;version:pointer to version
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
int PDK_PowerChipFWVersionGetWithoutLock(INT8U Devinst, INT8U *FwRevStr, INT16U *ResLen, int BMCInst)
{
	INT8U data = 0;

	if(NULL == FwRevStr)
		return -1;
	if( Devinst >= POWER_CHIP_COUNT_MAX || Devinst >= sizeof(board_power_chip_info)/sizeof(board_power_chip_info_t))
	{
		return CC_PARAM_OUT_OF_RANGE;
	}
	irps5401_info_t *chip_info = &board_power_chip_info[Devinst].chip_info;
	if(0 == PDK_Irps5401FWVersionGet(*chip_info, &data))
	{
		*ResLen = snprintf(FwRevStr, POWER_CHIP_FW_VER_LEN, "V%u.%02u", data>>4, data&0x0f);
		return CC_NORMAL;
	}
	return CC_UNSPECIFIED_ERR;
}

/*****************************************************************************
 * Function     : PDK_Irps5401VersionGet
 * Description  : get current firmware version 
 * Params       : chip_info:power chip info struct;version:pointer to version
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401SiliconVersionGet(irps5401_info_t chip_info, INT8U *version)
{
	INT8U data = 0;

	if(NULL == version)
		return -1;

	if(0 == PDK_Irps5401ReadByteWithPageSet(chip_info, IRPS5401_SILICON_VERSION_REG, &data))
	{
		*version = data;
		return 0;
	}
	return -1;
}

/*****************************************************************************
 * Function     : PDK_IrpsUpdatePrepareCommon
 * Description  : Do preparation for user and conf section update 
 * Params       : chip:power chip update info struct
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_IrpsUpdatePrepareCommon(power_chip_update_t *chip)
{
    INT8U data8 = 0;

	if(0 != PDK_Irps5401WriteByteWithoutPageSet(chip->chip, IRPS5401_LOCK_REG, 0x00))
    {
        TWARN("Update power chip %d setp 1 fail,lock i2c address error.\n", chip->chip_inst);
        return -1;
    }

   
	if(0 != PDK_Irps5401ReadByteWithoutPageSet(chip->chip, IRPS5401_PASSWD_REG, &data8))
    {
        TWARN("Update power chip %d setp 2 fail,read passwd register error.\n", chip->chip_inst);
        return -1;
    }
	
    if(0 == (data8 & 0x02))
    {
        if(0 != PDK_Irps5401WriteByteWithoutPageSet(chip->chip, IRPS5401_TRIM_TRY_PWD_REG0, 0x5a))
	    {
	        TWARN("Update power chip %d setp 2-1 fail,set 0x5a to reg 0x8a error.\n", chip->chip_inst);
	        return -1;
	    }

		if(0 != PDK_Irps5401WriteByteWithoutPageSet(chip->chip, IRPS5401_TRIM_TRY_PWD_REG1, 0xa5))
		{
			TWARN("Update power chip %d setp 2-1 fail,set 0x5a to reg 0x8a error.\n", chip->chip_inst);
			return -1;
		}
    }
   if(0 != PDK_Irps5401WriteByteWithoutPageSet(chip->chip, IRPS5401_REG_0B, 0x00))
	{
		TWARN("Update power chip %d setp 3 fail,set 0x0 to reg 0x0b error.\n", chip->chip_inst);
		return -1;
	}
    return 0;
}

/*****************************************************************************
 * Function     : PDK_IrpsUpdateConfSectionPrepare
 * Description  : Do preparation for conf section update 
 * Params       : chip:power chip update info struct
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_IrpsUpdateConfSectionPrepare(power_chip_update_t *chip)
{
	if(NULL == chip)
		return -1;
	if(0 != PDK_IrpsUpdatePrepareCommon(chip))
	{
		TWARN("Prepare for updating conf section fail.\n");
		return -1;
	}
	if(0 != PDK_Irps5401ConfWriteLeftGet(chip->chip, &chip->conf_wirte_left))
	{
		TWARN("Prepare for updating conf section fail, get left written times fail.\n");
		return -1;
	}
	return CC_NORMAL;
}

/*****************************************************************************
 * Function     : PDK_IrpsUpdateUserSectionPrepare
 * Description  : Do preparation for user section update 
 * Params       : chip:power chip update info struct
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_IrpsUpdateUserSectionPrepare(power_chip_update_t *chip)
{
	if(NULL == chip)
		return -1;
	if(0 != PDK_IrpsUpdatePrepareCommon(chip))
	{
		TWARN("Prepare for updating user section fail.\n");
		return -1;
	}
	if(0 != PDK_Irps5401UserWriteLeftGet(chip->chip, &chip->user_wirte_left))
	{
		TWARN("Prepare for updating user section fail, get left written times fail.\n");
		return -1;
	}
	return CC_NORMAL;
}


/*****************************************************************************
 * Function     : PDK_IrpsUpdateConfSectionPost
 * Description  : Do preparation for user section update 
 * Params       : chip:power chip update info struct
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_IrpsUpdateConfSectionPost(power_chip_update_t *chip)
{
	INT8U image_number = 0; 
	INT16U send_data = 0;
	INT8U read_data = 0;

	if(NULL == chip)
		return -1;

	image_number = IRPS5401_CONF_WRITE_MAX_COUNT - chip->conf_wirte_left;		//计算需要使用的分区并写入
	send_data = (image_number << 8) | 0x0012;
	if(0 != PDK_Irps5401WriteWordWithPageSet(chip->chip, IRPS5401_NVM_CMD_REG, send_data))
	{
		TWARN("Update power chip %d fail,restore CONF value to regiser map fail.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	usleep(POWER_CHIP_PROGRAM_TIME);		//等待寄存器写入
	if(0 != PDK_Irps5401ReadByteWithPageSet(chip->chip, IRPS5401_NVM_CMD_REG_H, &read_data))
	{
		TWARN("Update power chip %d fail, read CONF program status fail.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	if(! (read_data&0x80))
	{
		TWARN("Update power chip %d fail, values of register have not been restored to OTP.\n", chip->chip_inst);
		return CC_DEV_IN_FIRMWARE_PROTECT_MODE;	
	}

	//确认编程后，芯片是否确认要使用新的固件了
	if(0 != PDK_Irps5401ConfWriteLeftGet(chip->chip, &read_data))
	{
		TWARN("Update power chip %d fail, read left written times of conf fail.\n", chip->chip_inst);
		return CC_BUS_ERR;	
	}
	if(read_data  == chip->conf_wirte_left - 1 )
	{
		TWARN("Update power chip %d successfully, new section number is %d\n", chip->chip_inst, IRPS5401_CONF_WRITE_MAX_COUNT - read_data - 1);
		return 0;
	}
	else
	{
		TWARN("Update power chip %d fail, new section number is %d\n", chip->chip_inst, IRPS5401_CONF_WRITE_MAX_COUNT - read_data - 1);
		return CC_ERR_EXIT_FW_UPDATE;
	}
	return CC_NORMAL;
}

/*****************************************************************************
 * Function     : PDK_IrpsUpdateUserSectionPost
 * Description  : Do preparation for user section update 
 * Params       : chip:power chip update info struct
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_IrpsUpdateUserSectionPost(power_chip_update_t *chip)
{
	INT8U image_number = 0; 
	INT16U send_data = 0;
	INT8U read_data = 0;

	if(NULL == chip)
		return -1;

	image_number = IRPS5401_USER_WRITE_MAX_COUNT - chip->user_wirte_left;		//计算需要使用的分区并写入
	send_data = (image_number << 8) | 0x0042;
	if(0 != PDK_Irps5401WriteWordWithPageSet(chip->chip, IRPS5401_NVM_CMD_REG, send_data))
	{
		TWARN("Update power chip %d fail,restore User value to regiser map fail.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	usleep(POWER_CHIP_PROGRAM_TIME);		//等待寄存器写入
	if(0 != PDK_Irps5401ReadByteWithPageSet(chip->chip, IRPS5401_NVM_CMD_REG_H, &read_data))
	{
		TWARN("Update power chip %d fail, read User program status fail.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	if(! (read_data&0x80))
	{
		TWARN("Update power chip %d fail, values of register have not been restored to OTP.\n", chip->chip_inst);
		return CC_DEV_IN_FIRMWARE_PROTECT_MODE;
	}

#if 0
	//确认编程后，芯片是否确认要使用新的固件了
	if(0 != PDK_Irps5401ConfWriteLeftGet(chip->chip, &read_data))
	{
		TWARN("Update power chip %d fail, read left written times of User fail.\n", chip.chip_inst);
		return -1;	
	}
	if(read_data  == chip->conf_wirte_left - 1 )
	{
		TWARN("Update power chip %d successfully, new section number is %d\n", chip.chip_inst, IRPS5401_USER_WRITE_MAX_COUNT - read_data - 1);
		return 0;
	}
	else
	{
		TWARN("Update power chip %d fail, new section number is %d\n", chip.chip_inst, IRPS5401_USER_WRITE_MAX_COUNT - read_data - 1);
		return -1;
	}
#endif
	return CC_NORMAL;
}

static void PDK_SetIrps5401RegSectionEnable(power_chip_reg_loop_section loop_section, bool En)
{
	INT16U i;
	for(i = 0; i < sizeof(irps5401_reg_section)/sizeof(power_chip_reg_section_info_t); i++)
	{
		if(irps5401_reg_section[i].reg_section == loop_section)
		{
			irps5401_reg_section[i].loop_en = En;
		}
	}
}

/*****************************************************************************
 * Function     : PDK_UpdateIrps5401RegSectionEnableinfo
 * Description  : set irps5401_reg_section's loop_en member
 * Params       : chip:power chip update info struct
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_UpdateIrps5401RegSectionEnableinfo(power_chip_update_t *chip)
{
	INT8U read = 0,read1 = 0;
	
	//获取启用的switcher
	if(0 != PDK_Irps5401ReadByteWithPageSet(chip->chip, IRPS5401_SWITCHE_EN_REG, &read))
	{
		TWARN("Update power chip %d fail, read enable-all register fail when verifying.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	if(0 != PDK_Irps5401ReadByteWithPageSet(chip->chip, IRPS5401_SWITCHE_COMBINE_REG, &read1))
	{
		TWARN("Update power chip %d fail, read combine register fail when verifying.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	if(read & (1 << 4))PDK_SetIrps5401RegSectionEnable(POWER_REG_LOOP_LDO_SECTION, false);
	if(read & (1 << 3))PDK_SetIrps5401RegSectionEnable(POWER_REG_LOOP_D_SECTION, false);
	if(read & (1 << 2))PDK_SetIrps5401RegSectionEnable(POWER_REG_LOOP_C_SECTION, false);
	if(read & (1 << 1))PDK_SetIrps5401RegSectionEnable(POWER_REG_LOOP_B_SECTION, false);
	if(read & (1 << 0))PDK_SetIrps5401RegSectionEnable(POWER_REG_LOOP_A_SECTION, false);
	//D有特殊判断
	if(read1 & (1 << 4))PDK_SetIrps5401RegSectionEnable(POWER_REG_LOOP_D_SECTION, false);
	return 0;
	
}

static bool PDK_IfRegNeedVerified(INT16U reg_addr)
{
	INT16U i = 0;
	bool en = false;

	for(i = 0; i < sizeof(irps5401_reg_section)/sizeof(power_chip_reg_section_info_t); i++)
	{
		if((reg_addr >= irps5401_reg_section[i].start_addr) && (reg_addr <= irps5401_reg_section[i].end_addr))
		{
			if(irps5401_reg_section[i].reg_section == POWER_REG_COMMON_SECTION)
			{
				en = true;
				break;
			}
			else  if(irps5401_reg_section[i].loop_en == true)
			{
				en = true;
				break;
			}
		}
		else
		{
			continue;
		}
	}
	for(i = 0; i < sizeof(verify_ignored_reg) / sizeof(INT16U); i++ )
	{
		if(reg_addr == verify_ignored_reg[i])
		{
			en = false;
			break;
		}
	}
	return en;
}
/*****************************************************************************
 * Function     : PDK_Irps5401VerifyPrepare
 * Description  : prepare to verify irps5401 register after update user section
 * Params       : chip:power chip update info struct;verify_reg_count:point,calculate the count of register need to be verified
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401VerifyPrepare(power_chip_update_t *chip, INT16U *verify_reg_count)
{
	INT16U data = 0;
	INT8U current_image = 0;
	INT8U read = 0;
	irps5401_section_info *p_section_info = NULL;
	power_chip_data_t *p_chip_data = NULL;
	INT16U data_count = 0;
	otp_section section = POWER_CHIP_SECTION_USER;		//只能校验user分区，conf分区重新 powerup后才会更新

	if(NULL == chip)
	{
		TWARN("Update power chip fail,illegal parameter [*chip].\n");
		return CC_PARAM_OUT_OF_RANGE;
	}

	//更新各个power Switcher的启用情况
	if(0 != PDK_UpdateIrps5401RegSectionEnableinfo(chip))
	{
		TWARN("Update power chip %d fail, update switcher enable information fail.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}

	//计算需要校验的寄存器的数量
	p_chip_data = (power_chip_data_t *)chip->image_buf;
	for(p_section_info = (irps5401_section_info *)chip->section_info; p_section_info < (INT8U *)chip->section_info + sizeof(irps5401_section_info) * chip->section_count; p_section_info++)
	{
		if(p_section_info->section != section)
		{
			continue;
		}

		for(; p_chip_data < chip->image_buf + chip->imgSize; p_chip_data++)
		{
			if((p_chip_data->reg >= p_section_info->sec_start) && (p_chip_data->reg <= p_section_info->sec_end))
			{
				if(PDK_IfRegNeedVerified(p_chip_data->reg))
				data_count++;
			}
			if(p_chip_data->reg == p_section_info->sec_end)
			{
				p_chip_data++;		//直接前进到下一个地址，减少一次比对
				break;
			}
		}
	}
	*verify_reg_count = data_count;


	//获取当前需要校验的otp编号
#ifndef __PC_DBG
	current_image = IRPS5401_USER_WRITE_MAX_COUNT - chip->user_wirte_left;
#else
	current_image = IRPS5401_USER_WRITE_MAX_COUNT - chip->user_wirte_left - 1;
#endif
	//获取当前的写入情况,是否有CRC等
	data = (current_image << 8) | 0x0041;
	if(0 != PDK_Irps5401WriteWordWithPageSet(chip->chip, IRPS5401_NVM_CMD_REG, data))
	{
		TWARN("Update power chip %d fail, set NVM_COMMAND register fail when verifying.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	usleep(POWER_CHIP_PROGRAM_TIME);

	if(0 != PDK_Irps5401ReadByteWithPageSet(chip->chip, IRPS5401_NVM_CMD_REG_H, &read))
	{
		TWARN("Update power chip %d fail, read NVM_COMMAND register fail when verifying.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	if(!(read & 0x80))		//status[7] = 1:done,0;progress
	{
		TWARN("Update power chip %d, read NVM_COMMAND status = 0x%x.\n", chip->chip_inst,read);
		usleep(POWER_CHIP_PROGRAM_TIME);
	}
	if(0 != PDK_Irps5401ReadByteWithPageSet(chip->chip, IRPS5401_NVRAM_IMAGE_REG, &read))
	{
		TWARN("Update power chip %d fail, read NVRAM_IMAGE register fail when verifying.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	if(read & 0x40)
	{
		TWARN("Update power chip %d fail, there are CRC errors in user section,NVRAM_IMAGE register = 0x%x.\n", chip->chip_inst, read);
		TAUDIT(LOG_CRIT, "Update power chip %d fail, there are CRC errors in user section,NVRAM_IMAGE register = 0x%x,need to program again.\n", chip->chip_inst, read);
		return CC_ERR_FLASH_VERIFY;
	}	

	return CC_NORMAL;
}

/*****************************************************************************
 * Function     : PDK_Irps5401Verify
 * Description  : verify irps5401 register after update user section
 * Params       : chip:power chip update info struct
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401Verify(power_chip_update_t *chip)
{
	INT8U reg_value[IRPS5401_REG_END - IRPS5401_REG_START + 1];
	INT8U last_page = 0,current_page = 0;
	INT16U	reg;
	int ret = 0;
	INT16U verify_reg_count = 0, error_count = 0, current_count = 0;
	irps5401_section_info *p_section_info = NULL;
	power_chip_data_t *p_chip_data = NULL;
	otp_section section = POWER_CHIP_SECTION_USER;		//只能校验user分区，conf分区重新 powerup后才会更新

	if(NULL == chip)
	{
		TWARN("Update power chip fail,illegal parameter [*chip].\n");
		return CC_PARAM_OUT_OF_RANGE;
	}
	
	chip->progress = 0;
	chip->status = POWER_FW_UPDATE_STATUS_VERIFY;

	ret = PDK_Irps5401VerifyPrepare(chip, &verify_reg_count);
	if(ret != CC_NORMAL)return ret;
	if(0 == verify_reg_count)
	{
		TWARN("Update power chip %d fail, verify_reg_count = 0 .\n", chip->chip_inst);
		return CC_UNSPECIFIED_ERR;
	}
	chip->progress = VERIFY_PROGRESS_PREPARE;
	//读取寄存器
	memset(reg_value, 0, sizeof(reg_value));
	if(0 != PDK_Irps5401SetPage(chip->chip, 0))
	{
		TWARN("Update power chip %d fail, set page to page 0 fail.\n", chip->chip_inst);
		return CC_BUS_ERR;
	}
	last_page = 0;
	for(reg = IRPS5401_REG_START; reg <= IRPS5401_REG_END; reg++)
	{
		current_page = reg / IRPS5401_PAGE_SIZE;
		if(last_page != current_page)
		{
			PDK_Irps5401SetPage(chip->chip, current_page);
			last_page = current_page;
		}
		PDK_Irps5401ReadByteWithoutPageSet(chip->chip, reg, &reg_value[reg]);
		chip->progress = VERIFY_PROGRESS_PREPARE + (reg - IRPS5401_REG_START)  * (VERIFY_PROGRESS_REG_READ - VERIFY_PROGRESS_PREPARE) / (IRPS5401_REG_END - IRPS5401_REG_START) ;
		PRINT("Verify progress %d ,error count = %d.\n", chip->progress, error_count);
	}

	chip->progress = VERIFY_PROGRESS_REG_READ;
	PRINT("Verify progress %d ,error count = %d.\n", chip->progress, error_count);

	p_chip_data = (power_chip_data_t *)chip->image_buf;
	for(p_section_info = (irps5401_section_info *)chip->section_info; p_section_info < (INT8U *)chip->section_info + sizeof(irps5401_section_info) * chip->section_count; p_section_info++)
	{
		if(p_section_info->section != section)
		{
			continue;
		}

		for(; p_chip_data < chip->image_buf + chip->imgSize; p_chip_data++)
		{
			if((p_chip_data->reg >= p_section_info->sec_start) && (p_chip_data->reg <= p_section_info->sec_end))
			{
				if(PDK_IfRegNeedVerified(p_chip_data->reg))
				{
					if((reg_value[p_chip_data->reg] ^ p_chip_data->value) & p_chip_data->mask)
					{
						error_count++;
						PRINT("Error reg = 0x%04x, image value = 0x%02x, read value = 0x%02x, mask = 0x%02x \n", p_chip_data->reg, p_chip_data->value, reg_value[p_chip_data->reg], p_chip_data->mask);
					}
					current_count++;
				}
			}
			if(p_chip_data->reg == p_section_info->sec_end)
			{
				p_chip_data++;		//直接前进到下一个地址，减少一次比对
				break;
			}
		}
		chip->progress = VERIFY_PROGRESS_REG_READ + current_count * (VERIFY_PROGRESS_REG_COMPARE - VERIFY_PROGRESS_REG_READ) /verify_reg_count ;
		//chip->progress = current_count * 100 / verify_reg_count;
		PRINT("Verify progress %d ,error count = %d.\n", chip->progress, error_count);
	}
	chip->progress = VERIFY_PROGRESS_REG_COMPARE;
	if(error_count == 0)
	{
		chip->status = POWER_FW_UPDATE_STATUS_SUCCESS;
	}
	else
	{
		chip->status = POWER_FW_UPDATE_STATUS_FAIL;
	}
	return 0;
}


/*****************************************************************************
 * Function     : PDK_Irps5401Update
 * Description  : Update irps5401 
 * Params       : chip:power chip update info struct
 * Return       : 0: Success, -1: Failed
 * Author       : TeaFeng
 * Date         : 2024/11/21
*****************************************************************************/
static int PDK_Irps5401Update(power_chip_update_t *chip)
{
	irps5401_section_info *p_section_info = NULL;
	power_chip_data_t *p_chip_data = NULL;
	INT32U data_count = 0, written_count = 0;
	char *section_name = NULL;
	otp_section section;
	power_fw_update_stage stage;
	int (*PowerChipPrepareFunction)(power_chip_update_t *);
	int (*PowerChipPostFunction)(power_chip_update_t *);
	int ret = 0;

	if(NULL == chip)
	{
		TWARN("Update power chip fail,illegal parameter [*chip].\n");
		return CC_ERR_SETUP_FW_UPDATE;
	}

	if(chip->stage_mask & POWER_CHIP_SECTION_CONF)
	{
		section_name = "conf";
		section = POWER_CHIP_SECTION_CONF;
		stage = POWER_FW_UPDATE_STAGE_CONF;
		PowerChipPrepareFunction = PDK_IrpsUpdateConfSectionPrepare;
		PowerChipPostFunction = PDK_IrpsUpdateConfSectionPost;
	}
	else if(chip->stage_mask & POWER_CHIP_SECTION_USER)
	{
		section_name = "user";
		section = POWER_CHIP_SECTION_USER;
		stage = POWER_FW_UPDATE_STAGE_USER;
		PowerChipPrepareFunction = PDK_IrpsUpdateUserSectionPrepare;
		PowerChipPostFunction = PDK_IrpsUpdateUserSectionPost;
	}
	else
	{
		TWARN("Update power chip %d fail,section = [0x%x] is illegal.\n", chip->chip_inst,chip->stage_mask);
		return CC_ERR_SETUP_FW_UPDATE;
	}

	if(NULL == chip->image_buf || NULL == chip->section_info)
	{
		TWARN("Update power chip %d %s section fail,illegal parameter.\n", chip->chip_inst, section_name);
		return CC_ERR_SETUP_FW_UPDATE;
	}
	//检测可升级的section中是否存在当前要升级的分区，如果不存在，则退出避免浪费升级次数
	//检测固件中是否存在可升级分区的地址，并计算所需要写入的寄存器的数量，方便后续计算升级进度
	//固件文件中存在多余的、不在升级范围内的寄存器地址，因此不能直接使用固件文件中的寄存器数量当做总的写入数据量
	p_chip_data = (power_chip_data_t *)chip->image_buf;
	for(p_section_info = (irps5401_section_info *)chip->section_info; p_section_info < (INT8U *)chip->section_info + sizeof(irps5401_section_info) * chip->section_count; p_section_info++)
	{
		if(p_section_info->section != section)
		{
			continue;
		}

		for(; p_chip_data < chip->image_buf + chip->imgSize; p_chip_data++)
		{
			if((p_chip_data->reg >= p_section_info->sec_start) && (p_chip_data->reg <= p_section_info->sec_end))
			{
				data_count++;
			}
			if(p_chip_data->reg == p_section_info->sec_end)
			{
				p_chip_data++;		//直接前进到下一个地址，减少一次比对
				break;
			}
		}
	}
	if(!data_count)
	{
		TWARN("Update power chip %d %s section fail,there is no %s section data in bin file or no %s section configuration.\n", chip->chip_inst, section_name, section_name, section_name);
		return CC_FILE_MISMATCH;
	}
	PRINT("%s %s %d Dev [%d] data_count = %u \n", __FILE__, __FUNCTION__, __LINE__, chip->chip_inst, data_count);

	//进入正式升级流程
	chip->progress = 0;
	chip->status = POWER_FW_UPDATE_STATUS_ING;
	chip->stage = stage;
#ifndef __PC_DBG
	if(0 != PowerChipPrepareFunction(chip))
	{
		chip->status = POWER_FW_UPDATE_STATUS_FAIL;
		return CC_ERR_SETUP_FW_UPDATE;
	}
#endif
	p_chip_data = (power_chip_data_t *)chip->image_buf;
	for(p_section_info = (irps5401_section_info *)chip->section_info; p_section_info < (INT8U *)chip->section_info + sizeof(irps5401_section_info) * chip->section_count; p_section_info++)
	{
		if(p_section_info->section != section)
		{
			continue;
		}
		PRINT("%s %s %d Dev [%d] page = 0x%02x ,data = :\n", __FILE__, __FUNCTION__, __LINE__, chip->chip_inst, p_section_info->page);
#ifndef __PC_DBG
		//减少I2C开销，每次切换section时写一次page，写具体寄存器时不再写page寄存器
		if(0 != PDK_Irps5401SetPage(chip->chip, p_section_info->page))
		{
			chip->status = POWER_FW_UPDATE_STATUS_FAIL;
			TWARN("Update power chip %d %s section fail,set page %u fail\n", chip->chip_inst, section_name, p_section_info->page);
			return CC_ERR_FLASH_WRITE;
		}		
#endif
		for(; p_chip_data < chip->image_buf + chip->imgSize; p_chip_data++)
		{
			if((p_chip_data->reg >= p_section_info->sec_start) && (p_chip_data->reg <= p_section_info->sec_end))
			{
#ifndef __PC_DBG
				if(0 != PDK_Irps5401WriteByteWithoutPageSet(chip->chip, p_chip_data->reg, p_chip_data->value))
				{
					chip->status = POWER_FW_UPDATE_STATUS_FAIL;
					TWARN("Update power chip %d %s section fail,write reg 0x%x fail\n", chip->chip_inst, section_name, p_chip_data->reg);
					return CC_ERR_FLASH_WRITE;
				}
#endif
				PRINT("%04X %02X %02X\n",p_chip_data->reg, p_chip_data->value, p_chip_data->mask);

				written_count++;
				if(p_chip_data->reg == p_section_info->sec_end)
				{
					p_chip_data++;		//直接前进到下一个地址，减少一次比对
					break;
				}
			}
		}
		PRINT("\n\n");
		chip->progress = written_count * 100 / data_count;
	}
	PRINT("%s %s %d Dev [%d] written_count = %u \n", __FILE__, __FUNCTION__, __LINE__, chip->chip_inst, written_count);
#ifndef __PC_DBG
	ret = PowerChipPostFunction(chip);
	if(CC_NORMAL == ret)
	{
		chip->progress = 100;
		chip->status = POWER_FW_UPDATE_STATUS_SUCCESS;
		return CC_NORMAL;
	}
	else
	{
		chip->status = POWER_FW_UPDATE_STATUS_FAIL;
		return ret;
	}
#else
	chip->progress = 100;
	chip->status = POWER_FW_UPDATE_STATUS_SUCCESS;
#endif
	
	return CC_NORMAL;
}

/*****************************************************************************
 * Function     : PDK_PowerChipFwImageVerify
 * Description  : Power chip Firmware Image Verify
 * Params       : *ImgData      -- Firmware Image Data
 *                ImgSize       -- Firmware Image Data bytes length
 * Return       : IPMI Completion Code
 * Author       : TeaFeng
 * Date         : 2024/11/27
*****************************************************************************/
int PDK_PowerChipFwImageVerify(INT8U *ImgData, INT32U ImgSize )
{
    power_chip_hd_t *ImgHdr = (power_chip_hd_t *)ImgData;
    INT32U FwSize = 0;
    INT8U *DigestSign = NULL;

    if (ImgHdr->HdrCRC32 != CalculateCRC32(ImgData, sizeof(power_chip_hd_t) - 4))
    {
        TWARN("Power chip Firmware Image Header CRC32 verify failed");
        return CC_ERR_FW_IMG_HDR_CRC;
    }

    if (0 != memcmp(POWER_CHIP_FW_IMG_SIGN, ImgHdr->Signature, FW_IDENTITY_LEN))
    {
        TWARN("Power chip Firmware Image Header Signature Invalid");
        return CC_ERR_FW_IMG_SIGNATURE;
    }
	
	if (0 != memcmp(DEVMODEL_MYDEV_POWER, ImgHdr->DevModel, strlen(DEVMODEL_MYDEV_POWER)))
	{
		TWARN("Power chip Firmware Image Header Devmodel Invalid");
		return CC_ERR_FW_IMG_MODEL;
	}

    if (ImgSize != (ImgHdr->ImgOffset + ImgHdr->ImgSize + POWER_CHIP_IMG_DIGEST_SIGN_SIZE))
    {
        TWARN("Power chip Firmware Image Size Invalid [%x + %x + %x != %x]", ImgHdr->ImgOffset, ImgHdr->ImgSize, POWER_CHIP_IMG_DIGEST_SIGN_SIZE, ImgSize);
        return CC_FILE_SIZE_INVALID;
    }

    if (ImgHdr->ImgCRC32 != CalculateCRC32(&ImgData[ImgHdr->ImgOffset], ImgHdr->ImgSize))
    {
        TWARN("Power chip Firmware Image Data CRC32 verify failed");
        return CC_FILE_CHKSUM_EER;
    }

    /* Firmware Image Digest Signature Verify */
    FwSize = ImgSize - POWER_CHIP_IMG_DIGEST_SIGN_SIZE;
    DigestSign = &ImgData[FwSize];
    if (FwImageDigestSignVerify(POWER_CHIP_IMG_SIGN_PUBLIC_FILE, ImgData, FwSize, DigestSign) < 0)
    {
        TWARN("Power chip Firmware Image Digest Signature verification failed");
        return CC_ERR_HASH_SIGNED_VERIFY;
    }

    return CC_NORMAL;
}

/*****************************************************************************
 * Function     : PDK_PowerChipFwImageRead
 * Description  : Read Power chip Firmware Image file and verify
 * Params       : *file         -- Firmware image file name
 *                *pFwUpdate    -- Firmware update info
 * Return       : IPMI Completion Code
 * Author       : TeaFeng
 * Date         : 2024/11/27
*****************************************************************************/
int PDK_PowerChipFwImageRead(char *file, power_chip_update_t *pFwUpdate)
{
    struct stat fs;
    power_chip_hd_t *ImgHdr = NULL;
    INT32U size, i;
    INT8U *FwRev = NULL;
    INT8U *buf = NULL;
    int ret;

    if ((NULL == file) || (NULL == pFwUpdate))
        return CC_UNSPECIFIED_ERR;

    /* Check firmware image not exist */
    if (0 != access(file, F_OK))
        return CC_FILE_NOT_EXIST;

    if (0 != stat(file, &fs))
        return CC_ERR_FILE_READ;

    size = fs.st_size;
    if (POWER_CHIP_FW_SIZE_MAX < size)
    {
        TWARN("Power Chip Firmware Image File size %d out-of-range %d", size, POWER_CHIP_FW_SIZE_MAX);
        return CC_FILE_SIZE_INVALID;
    }
	TINFO("Power Chip Firmware Image File size %u Bytes.\n", size);
    /* molloc memory for firmware image read */
    buf = malloc(size);
    if (NULL == buf)
    {
        TWARN("No memory for Power Chip Firmware Image");
        return CC_NO_MEM;
    }

    /* Read Firmware image file */
    if (PDK_FileRead(file, 0, size, buf) < 0)
    {
        free(buf);
		buf = NULL;
        TWARN("ERROR in read Power Chip Firmware Image File");
        return CC_ERR_FILE_READ;
    }

    /* Firmware image verify */
    ret = PDK_PowerChipFwImageVerify(buf, size);
    if (CC_NORMAL != ret)
    {
        free(buf);
		buf = NULL;
        return ret;
    }

    ImgHdr = (power_chip_hd_t *)buf;
	pFwUpdate->image_buf = buf + ImgHdr->ImgOffset;
	pFwUpdate->imgSize = ImgHdr->ImgSize;
	pFwUpdate->FwRev = ImgHdr->FwRev;

	PRINT("%s %s %d Dev buf = %p,image_buf = %p.\n \n", __FILE__, __FUNCTION__, __LINE__, buf, pFwUpdate->image_buf);

	for(i=0; i < sizeof(board_power_chip_info) / sizeof(board_power_chip_info_t); i++)
	{
		if(0 == memcmp(board_power_chip_info[i].SubModel, ImgHdr->SubModel, strlen(board_power_chip_info[i].SubModel)))
		{
			pFwUpdate->chip_inst = i;
			break;
		}
		else
		{
			pFwUpdate->chip_inst = sizeof(board_power_chip_info) / sizeof(board_power_chip_info_t);
		}
	}
    return CC_NORMAL;
}


static void PDK_ExitPowerChipUpdateModeFail(power_chip_update_t *FwUpdate, char *p_fw, INT8U error_code)
{
	FwUpdate->is_under_update = 0;
	if(p_fw)free(p_fw);
	p_fw = NULL;
	FwUpdate->error_code = error_code;
	FwUpdate->status = POWER_FW_UPDATE_STATUS_FAIL;
	PDK_Irps5401MuxBlockLock(0);
}
static void PDK_ExitPowerChipUpdateMode(power_chip_update_t *FwUpdate, char *p_fw, INT8U error_code)
{
	FwUpdate->is_under_update = 0;
	if(p_fw)free(p_fw);
	p_fw = NULL;
	FwUpdate->error_code = error_code;
	PDK_Irps5401MuxBlockLock(0);
}


int PDK_PowerChipUpdate(INT8U Devinst, INT32U mask)
{
	power_chip_update_t *FwUpdate;
	int ret  = 0;
	char *p_fw = NULL;
	INT8U silcon_version = 0;

	if(Devinst > sizeof(board_power_chip_info)/sizeof(board_power_chip_info_t) || Devinst >= POWER_CHIP_COUNT_MAX)
	{
		TWARN("Input Devinst = %d is larger.\n", Devinst);
		return CC_ERR_FW_UPDATE;
	}
	
	if(!(mask&POWER_CHIP_SECTION_CONF || mask&POWER_CHIP_SECTION_USER))
	{
		TWARN("Input mask = %d is illegal.\n", mask);
		return CC_ERR_FW_UPDATE;
	}

	FwUpdate = &power_chip_update[Devinst];

	if(power_chip_update[Devinst].status == POWER_FW_UPDATE_STATUS_ING 
		|| power_chip_update[Devinst].status == POWER_FW_UPDATE_STATUS_VERIFY 
		|| power_chip_update[Devinst].is_under_update)
	{
		TWARN("Firmware is updating.\n");
		FwUpdate->error_code = CC_ERR_EXECUTING;
		FwUpdate->status = POWER_FW_UPDATE_STATUS_FAIL;
		return CC_ERR_EXECUTING;
	}
	TINFO("%s %s %d Dev [%d] enter update...\n", __FILE__, __FUNCTION__, __LINE__, Devinst);
	PDK_Irps5401MuxBlockLock(1);
	memset(FwUpdate, 0, sizeof(power_chip_update_t));
	FwUpdate->is_under_update = 1;
		
	ret = PDK_PowerChipFwImageRead(POWER_CHIP_USED_FILE, FwUpdate);
	if(CC_NORMAL != ret)
	{
		FwUpdate->image_verified_state = ret;
		TWARN("Power chip firmware update, read firmware fail.\n");
		PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw, ret);
		return ret;
	}
	FwUpdate->image_verified_state = CC_NORMAL;
	TINFO("%s %s %d Dev [%d] image size = 0x%x, fw ver = 0x%x \n", __FILE__, __FUNCTION__, __LINE__, Devinst,FwUpdate->imgSize, FwUpdate->FwRev);

	p_fw = FwUpdate->image_buf - sizeof(power_chip_hd_t);
	if(FwUpdate->chip_inst >= sizeof(board_power_chip_info) / sizeof(board_power_chip_info_t))
	{
		power_chip_hd_t *p_temp = (power_chip_hd_t *)p_fw;
		TWARN("Power chip firmware update, firmware submodel is %s, mismach board information\n", p_temp->SubModel);
		PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw, CC_FILE_MISMATCH);
		return CC_FILE_MISMATCH;
	}
	power_chip_hd_t *p_temp = (power_chip_hd_t *)p_fw;
	TINFO("%s %s %d Dev [%d] firmware submodel is %s\n",  __FILE__, __FUNCTION__, __LINE__, Devinst, p_temp->SubModel);
	if(FwUpdate->chip_inst != Devinst)
	{
		TWARN("Power chip firmware update, input devinst = %d, firmware devinst = %d\n", Devinst, FwUpdate->chip_inst);
		PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw,  CC_ERR_FW_IMG_MODEL);
		return CC_ERR_FW_IMG_MODEL;
	}

	memcpy(&FwUpdate->chip, &board_power_chip_info[FwUpdate->chip_inst].chip_info, sizeof(power_chip_info_t));
	
	ret = PDK_Irps5401SiliconVersionGet(FwUpdate->chip, &silcon_version);
	if(ret != 0)
	{
		TWARN("Power chip firmware update, get chip silicon version  fail.\n");
		PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw,  CC_ERR_FW_IMG_MODEL);
		return CC_BUS_ERR;
	}
	TINFO("Power chip firmware update, chip silicon version:0x%x\n", silcon_version);
	if(silcon_version < IRPS5401_SILICON_VERSION_MIN)
	{
		TWARN("Power chip firmware update, chip silicon [0x%x] is lower than limition [0x%x].\n", silcon_version, IRPS5401_SILICON_VERSION_MIN);
		PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw,  CC_ERR_FW_IMG_MODEL);
		return CC_FWUPDATE_NOT_SUPPORTED;
	}

	if(mask & POWER_CHIP_SECTION_CONF)
	{
		if(0 != PDK_Irps5401ConfWriteLeftGet(FwUpdate->chip, &FwUpdate->conf_wirte_left))
		{
			TWARN("Power chip %d firmware update, get conf write left count fail.\n", Devinst);
			PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw, CC_DEV_IN_FIRMWARE_PROTECT_MODE);
			return CC_DEV_IN_FIRMWARE_PROTECT_MODE;
		}
		TINFO("%s %s %d Dev [%d] FwUpdate->conf_wirte_left = %u \n", __FILE__, __FUNCTION__, __LINE__, Devinst,FwUpdate->conf_wirte_left);
		if(FwUpdate->conf_wirte_left <= POWER_CHIP_CONF_WARN_COUNT)
		{
			TWARN("Power chip %d firmware update, conf section has reached the left warning limitation %d.\n", Devinst, POWER_CHIP_CONF_WARN_COUNT);
			PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw,  CC_ERR_FW_UPDATE_CAPABILITY);
			return CC_ERR_FW_UPDATE_CAPABILITY;
		}
		if(FwUpdate->conf_wirte_left == 0)
		{
			TWARN("Power chip %d firmware update, conf section has used up all %d times update count.\n", Devinst, IRPS5401_CONF_WRITE_MAX_COUNT);
			PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw, CC_FWUPDATE_NOT_SUPPORTED);
			return CC_FWUPDATE_NOT_SUPPORTED;
		}
	}
	
	if(mask & POWER_CHIP_SECTION_USER)
	{
		if(0 != PDK_Irps5401UserWriteLeftGet(FwUpdate->chip, &FwUpdate->user_wirte_left))
		{
			TWARN("Power chip firmware update, get user write left count fail.\n", Devinst,FwUpdate->chip_inst);
			PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw, CC_ERR_FW_UPDATE_CAPABILITY);
			return CC_ERR_FW_UPDATE_CAPABILITY;
		}
		TINFO("%s %s %d Dev [%d] FwUpdate->user_wirte_left = %u \n", __FILE__, __FUNCTION__, __LINE__, Devinst, FwUpdate->user_wirte_left);
		if(FwUpdate->user_wirte_left <= POWER_CHIP_USER_WARN_COUNT)
		{
			TWARN("Power chip %d firmware update, user section has reached the left warning limitation %d.\n", Devinst, POWER_CHIP_USER_WARN_COUNT);
			PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw, CC_ERR_FW_UPDATE_CAPABILITY);
			return CC_ERR_FW_UPDATE_CAPABILITY;
		}
		if(FwUpdate->user_wirte_left == 0)
		{
			TWARN("Power chip %d firmware update, user section has used up all %d times update count.\n", Devinst, IRPS5401_USER_WRITE_MAX_COUNT);
			PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw, CC_FWUPDATE_NOT_SUPPORTED);
			return CC_FWUPDATE_NOT_SUPPORTED;
		}
	}
	

	FwUpdate->section_info = board_power_chip_info[FwUpdate->chip_inst].section_info;
	FwUpdate->section_count = board_power_chip_info[FwUpdate->chip_inst].section_count;
	if(mask & POWER_CHIP_SECTION_CONF)
	{
		FwUpdate->stage_mask = POWER_CHIP_SECTION_CONF;
		FwUpdate->progress = 0;
		FwUpdate->status = POWER_FW_UPDATE_STATUS_IDLE;
		ret = PDK_Irps5401Update(FwUpdate);
		if(0 != ret)
		{
			TWARN("Power chip %d firmware update conf section fail.\n", Devinst);
			PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw, ret);
			return ret;
		}
	}
	if(mask & POWER_CHIP_SECTION_USER)
	{
		FwUpdate->stage_mask = POWER_CHIP_SECTION_USER;
		FwUpdate->progress = 0;
		FwUpdate->status = POWER_FW_UPDATE_STATUS_IDLE;
		ret = PDK_Irps5401Update(FwUpdate);
		sleep(2);
		if(0 != ret)
		{
			TWARN("Power chip %d firmware update user section fail.\n", Devinst);
			PDK_ExitPowerChipUpdateModeFail(FwUpdate, p_fw, ret);
			return ret;
		}
	}
	TINFO("%s %s %d Dev [%d] exit update.. \n", __FILE__, __FUNCTION__, __LINE__, Devinst);	
	TINFO("%s %s %d Dev [%d] enter verify.. \n", __FILE__, __FUNCTION__, __LINE__, Devinst);	
	PDK_Irps5401Verify(FwUpdate);
	if(FwUpdate->status == POWER_FW_UPDATE_STATUS_SUCCESS)
	{
		PDK_PostRedisMsgSetFwRev(ENTITY_POWER_CHIP, Devinst, 0);
	}
	sleep(2);
	TINFO("%s %s %d Dev [%d] exit verify.. \n", __FILE__, __FUNCTION__, __LINE__, Devinst);	
	FwUpdate->progress = 0;
	FwUpdate->status = POWER_FW_UPDATE_STATUS_IDLE;
	FwUpdate->stage = POWER_FW_UPDATE_STAGE_IDLE;
	PDK_ExitPowerChipUpdateMode(FwUpdate, p_fw, 0);
	return 0;
}


void *PDK_PowerChipFwUpdateTask(void *pArg)
{
    power_chip_req_t *pFwUpdate = (power_chip_req_t *)pArg;
	char cmd[64] = {0};

    prctl(PR_SET_NAME, __FUNCTION__, 0, 0, 0);
    pthread_detach(pthread_self());

	if(NULL == pFwUpdate)return 0;

	if(access(POWER_CHIP_FILE, F_OK))
	{
		TAUDIT(LOG_WARNING,"Power chip firmware file %s does not exist.\n", POWER_CHIP_FILE);
		TWARN("Power chip firmware file %s does not exist.\n", POWER_CHIP_FILE);
		return 0;
	}

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "cp %s %s", POWER_CHIP_FILE, POWER_CHIP_USED_FILE);
	safe_system(cmd);

    sleep(1);
    TAUDIT(LOG_INFO, "Power chip %d firmware Firmware Update, update mask 0x%x", pFwUpdate->Devinst, pFwUpdate->mask);
 	PDK_PowerChipUpdate(pFwUpdate->Devinst, pFwUpdate->mask);
    return 0;
}


