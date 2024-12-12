#ifndef __PDK_POWER_CHIP_H__
#define __PDK_POWER_CHIP_H__
#include <pthread.h>
#include "Types.h"


#define POWER_CHIP_COUNT_MAX			4
#define POWER_CHIP_FW_VER_LEN			16
typedef enum{
	POWER_CHIP_SECTION_CONF = 0x01 << 0,
	POWER_CHIP_SECTION_TRIM = 0x01 << 1,
	POWER_CHIP_SECTION_USER = 0x01 << 2,
	POWER_CHIP_SECTION_INVAL = 0,
}otp_section;

typedef struct
{
	INT8U Devinst;
	INT32U mask;
}power_chip_req_t;
typedef enum
{
    POWER_FW_UPDATE_STATUS_IDLE,
    POWER_FW_UPDATE_STATUS_ING,
    POWER_FW_UPDATE_STATUS_VERIFY,
    POWER_FW_UPDATE_STATUS_SUCCESS,
    POWER_FW_UPDATE_STATUS_FAIL,
} power_fw_update_status;

typedef enum
{
    POWER_FW_UPDATE_STAGE_IDLE,
    POWER_FW_UPDATE_STAGE_CONF,
   	POWER_FW_UPDATE_STAGE_USER,
}power_fw_update_stage;

typedef struct power_chip_info{
	char *i2c_dev;
	INT8U slave_addr;
	INT8U page_reg;
	INT8U page_min;
	INT8U page_max;
	INT16U page_size;
}power_chip_info_t;


typedef struct
{
    INT8U	chip_inst;				//power chip编号
    INT8U conf_wirte_left;			//conf分区剩余可编程次数
	INT8U user_wirte_left;			//user分区剩余可编程次数
	INT8U *image_buf;				//固件地址
    uint32 imgSize;					//固件大小
    INT8U FwRev;					//固件版本
	void *section_info;				//每种电源芯片内部需要升级的otp section page的信息，如irps5401_sec
	INT32U section_count;			//section的数量
	uint32 stage_mask;				//升级掩码，确定需要升级的section
	INT8U image_verified_state;		//镜像签名校验状态
	INT8U is_under_update;			//当前是否处于升级状态
	INT8U progress;					//升级进度
	INT8U	error_code;				//升级时的错误状态
	power_fw_update_status status;	//升级状态
	power_fw_update_stage stage; 	//当前升级的section
	power_chip_info_t chip;			//待升级芯片的信息	
} power_chip_update_t;



extern power_chip_req_t power_chip_req[POWER_CHIP_COUNT_MAX];
extern pthread_t PowerChipFwUpdateThreadID[POWER_CHIP_COUNT_MAX];
extern power_chip_update_t power_chip_update[POWER_CHIP_COUNT_MAX] ;
extern void *PDK_PowerChipFwUpdateTask(void *pArg);
extern int PDK_PowerChipFWVersionGet(INT8U Devinst, INT8U *FwRevStr, INT16U *ResLen, int BMCInst);
extern int PDK_PowerChipFWVersionGetWithoutLock(INT8U Devinst, INT8U *FwRevStr, INT16U *ResLen, int BMCInst);
#endif  /* __PDK_POWER_CHIP_H__*/


