
#define HDLC_HEADER 0x7e
#define HDLC_ESCAPE 0x7d
#define FDL1_DUMP_MEM 0
#define AUTO_DISABLE_TRANSCODE 0
#define DEFAULT_NAND_ID 0x15
#define NO_CONFIRM 0

unsigned short const crc16_table[256] = {
	  0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
	  0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
	  0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
	  0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
	  0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
	  0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
	  0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
	  0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
	  0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
	  0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
	  0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
	  0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
	  0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
	  0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
	  0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
	  0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
	  0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
	  0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
	  0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
	  0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
	  0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
	  0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
	  0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
	  0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
	  0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
	  0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
	  0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
	  0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
	  0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
	  0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
	  0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
	  0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

/*

SC6531EFM.xml (SC6531E):
	FDL1 = 0x40004000
	FDL = 0x14000000

NOR_FLASH_SC6530.xml (SC6531DA):
	FDL = 0x34000000

IDs:
	BOOTLOADER = 0x80000000
	PS = 0x80000003
	NV = 0x90000001
	PHASE_CHECK = 0x90000002, 0x1000
	FLASH = 0x90000003, 0xc0000
	MMIRES = 0x90000004
	ERASE_UDISK = 0x90000005
	UDISK_IMG = 0x90000006
	DSP_CODE = 0x90000009

FDL1:
	BSL_CMD_CONNECT()
	BSL_SET_BAUDRATE(u32 baud)
	BSL_CMD_START_DATA(u32 start_addr, u32 file_size)
	BSL_CMD_MIDST_DATA(...)
	BSL_CMD_END_DATA()
	BSL_CMD_EXEC_DATA()
	unknown: bootPanic

FDL2:
	BSL_CMD_CONNECT()
	BSL_CMD_START_DATA(u32 start_addr, u32 file_size)
	BSL_CMD_MIDST_DATA(...)
	BSL_CMD_END_DATA()
	BSL_CMD_NORMAL_RESET()
	BSL_CMD_READ_FLASH(u32 addr, u32 size, u32 offset)
	BSL_REPARTITION(): nop
	BSL_ERASE_FLASH(u32 addr, u32 size)
	BSL_CMD_POWER_OFF()
	unknown: BSL_REP_INVALID_CMD, bootPanic
*/

enum {
	/* Link Control */    
	BSL_CMD_CONNECT              = 0x00,

	/* Data Download */
	BSL_CMD_START_DATA           = 0x01, /* The start flag of the data downloading */
	BSL_CMD_MIDST_DATA           = 0x02, /* The midst flag of the data downloading */
	BSL_CMD_END_DATA             = 0x03, /* The end flag of the data downloading */
	BSL_CMD_EXEC_DATA            = 0x04, /* Execute from a certain address */

 	BSL_CMD_NORMAL_RESET         = 0x05, /* Reset to normal mode */
	BSL_CMD_READ_FLASH           = 0x06, /* Read flash content */
	BSL_CMD_READ_CHIP_TYPE       = 0x07, /* Read chip type */
	BSL_CMD_READ_NVITEM          = 0x08, /* Lookup a nvitem in specified area */
	BSL_CMD_CHANGE_BAUD          = 0x09, /* Change baudrate */
	BSL_CMD_ERASE_FLASH          = 0x0A, /* Erase an area of flash */
	BSL_CMD_REPARTITION          = 0x0B, /* Repartition nand flash */
	BSL_CMD_READ_FLASH_TYPE      = 0x0C, /* Read flash type */
	BSL_CMD_READ_FLASH_INFO      = 0x0D, /* Read flash infomation */
	BSL_CMD_READ_SECTOR_SIZE     = 0x0F, /* Read Nor flash sector size */
	BSL_CMD_READ_START           = 0x10, /* Read flash start */
	BSL_CMD_READ_MIDST           = 0x11, /* Read flash midst */
	BSL_CMD_READ_END             = 0x12, /* Read flash end */

	BSL_CMD_KEEP_CHARGE          = 0x13, /* Keep charge */
	BSL_CMD_EXTTABLE             = 0x14, /* Set ExtTable */
	BSL_CMD_READ_FLASH_UID       = 0x15, /* Read flash UID */
	BSL_CMD_READ_SOFTSIM_EID     = 0x16, /* Read softSIM EID */
	BSL_CMD_POWER_OFF            = 0x17, /* Power Off */
	BSL_CMD_CHECK_ROOT           = 0x19, /* Check Root */
	BSL_CMD_READ_CHIP_UID        = 0x1A, /* Read Chip UID */
	BSL_CMD_ENABLE_WRITE_FLASH   = 0x1B, /* Enable flash */
	BSL_CMD_ENABLE_SECUREBOOT    = 0x1C, /* Enable secure boot */   
	BSL_CMD_IDENTIFY_START       = 0x1D, /* Identify start */   
	BSL_CMD_IDENTIFY_END         = 0x1E, /* Identify end */   
	BSL_CMD_READ_CU_REF          = 0x1F, /* Read CU ref */ 
	BSL_CMD_READ_REFINFO         = 0x20, /* Read Ref Info */
	BSL_CMD_DISABLE_TRANSCODE    = 0x21, /* Use the non-escape function */
	BSL_CMD_WRITE_DATETIME       = 0x22, /* Write pac file build time to miscdata */
	BSL_CMD_CUST_DUMMY           = 0x23, /* Customized Dummy */
	BSL_CMD_READ_RF_TRANSCEIVER_TYPE = 0x24, /* Read RF transceiver type */
	BSL_CMD_SET_DEBUGINFO        = 0x25,
	BSL_CMD_DDR_CHECK            = 0x26,
	BSL_CMD_SELF_REFRESH         = 0x27,
	BSL_CMD_WRITE_RAW_DATA_ENABLE = 0x28, /* Init for 0x31 and 0x33 */
	BSL_CMD_READ_NAND_BLOCK_INFO = 0x29,
	BSL_CMD_SET_FIRST_MODE       = 0x2A,
	BSL_CMD_READ_PARTITION       = 0x2D, /* Partition list */
	BSL_CMD_DLOAD_RAW_START      = 0x31, /* Raw packet */
	BSL_CMD_WRITE_FLUSH_DATA     = 0x32,
	BSL_CMD_DLOAD_RAW_START2     = 0x33, /* Whole raw file */
	BSL_CMD_READ_LOG             = 0x35,

	BSL_CMD_CHECK_BAUD           = 0x7E, /* CheckBaud command, for internal use */
	BSL_CMD_END_PROCESS          = 0x7F, /* End flash process */

	/* response from the phone */
	BSL_REP_ACK                  = 0x80, /* The operation acknowledge */     
	BSL_REP_VER                  = 0x81,
	BSL_REP_INVALID_CMD          = 0x82,
	BSL_REP_UNKNOW_CMD           = 0x83,
	BSL_REP_OPERATION_FAILED     = 0x84,

	/* Link Control */    
	BSL_REP_NOT_SUPPORT_BAUDRATE = 0x85,

	/* Data Download */ 
	BSL_REP_DOWN_NOT_START       = 0x86,
	BSL_REP_DOWN_MULTI_START     = 0x87,
	BSL_REP_DOWN_EARLY_END       = 0x88,
	BSL_REP_DOWN_DEST_ERROR      = 0x89,
	BSL_REP_DOWN_SIZE_ERROR      = 0x8A,
	BSL_REP_VERIFY_ERROR         = 0x8B,
	BSL_REP_NOT_VERIFY           = 0x8C,

	/* Phone Internal Error */
	BSL_PHONE_NOT_ENOUGH_MEMORY  = 0x8D,
	BSL_PHONE_WAIT_INPUT_TIMEOUT = 0x8E,

	/* Phone Internal return value */
	BSL_PHONE_SUCCEED            = 0x8F,
	BSL_PHONE_VALID_BAUDRATE     = 0x90,
	BSL_PHONE_REPEAT_CONTINUE    = 0x91,
	BSL_PHONE_REPEAT_BREAK       = 0x92,

	/* End of the Command can be transmited by phone */
	BSL_REP_READ_FLASH           = 0x93,
	BSL_REP_READ_CHIP_TYPE       = 0x94,
	BSL_REP_READ_NVITEM          = 0x95,

	BSL_REP_INCOMPATIBLE_PARTITION = 0x96,
	BSL_REP_SIGN_VERIFY_ERROR    = 0xA6,
	BSL_REP_READ_CHIP_UID        = 0xAB,
	BSL_REP_READ_PARTITION       = 0xBA,
	BSL_REP_READ_LOG             = 0xBB,
	BSL_REP_UNSUPPORTED_COMMAND  = 0xFE,
};
