/*
 * etx_ota_update.h
 *
 *  Created on: 26-Jul-2021
 *      Author: EmbeTronicX
 */

#ifndef INC_ETX_OTA_UPDATE_H_
#include <stdint.h>

#define INC_ETX_OTA_UPDATE_H_

#define APP_FLASH_ADDR 0x08008000U  // Application's flash address

#define PACKET_SOF 0x02  // Start of Frame
#define PACKET_EOF 0x03  // End of Frame
#define PACKET_ACK 0x00  // Acknowledge
#define PACKET_NACK 0x01 // Not Acknowledge

#define PACKET_MAX_PAYLOAD_SIZE 2048  // Maximum payload size for a OTA packet in bytes
#define PACKET_OVERHEAD 11 // 11 bytes used for a OTA packet's metadata (all fields except payload)
#define PACKET_MAX_SIZE (PACKET_MAX_PAYLOAD_SIZE + PACKET_OVERHEAD)  // Max size of OTA packet in bytes
#define APP_FW_MAX_SIZE (0x0807FFFF - 0x08008000)  // Sector 7 end - Sector 2 start

/* Enum definitions */
typedef enum ota_state {
	IDLE = 0,
	START,
	HEADER,
	DATA,
	END,
} ota_state_t;

typedef enum ota_packet_type {
    OTA_COMMAND = 0,
    OTA_HEADER,
    OTA_DATA,
    OTA_RESPONSE,
} ota_packet_type_t;

typedef enum ota_command {
    OTA_START_CMD = 0,    // OTA Start command
    OTA_END_CMD   = 1,    // OTA End command
    OTA_ABORT_CMD = 2,    // OTA Abort command
} ota_command_t;

/* Struct definitions */
typedef struct FileInfo {
    uint32_t file_size;
    uint32_t crc32;
} FileInfo;

/*
 * Packet Structure:
 * ----------------------------------------------------------------------------------------------------
 * |     u8     |     u8      |      u16      |       u16      |        u8         |  u32  |    u8    |
 * ----------------------------------------------------------------------------------------------------
 * | Start Byte | Packet Type |   Reserved    | Payload Length |      Command      | CRC32 | End Byte |
 * ----------------------------------------------------------------------------------------------------
 */
typedef struct OtaCommandPacket {
    uint8_t sof;
    uint8_t packet_type;
    uint16_t packet_num;  // "don't care" for command packet
    uint16_t payload_len;
    uint8_t cmd;
    uint32_t crc32;
    uint8_t eof;
}__attribute__((packed)) OtaCommandPacket;

/*
 * Packet Structure:
 * ----------------------------------------------------------------------------------------------------
 * |     u8     |     u8      |      u16      |       u16      | FileInfo (64 bits)|  u32  |    u8    |
 * ----------------------------------------------------------------------------------------------------
 * | Start Byte | Packet Type |   Reserved    | Payload Length | File Information  | CRC32 | End Byte |
 * ----------------------------------------------------------------------------------------------------
*/
typedef struct OtaHeaderPacket {
    uint8_t sof;
    uint8_t packet_type;
    uint16_t packet_num;  // "don't care" for header packet
    uint16_t payload_len;
    FileInfo file_info;
    uint32_t crc32;
    uint8_t eof;
}__attribute__((packed)) OtaHeaderPacket;

/*
 * Packet Structure:
 * ----------------------------------------------------------------------------------------------------
 * |     u8     |     u8      |      u16      |       u16      | u8* (Variable Len)|  u32  |    u8    |
 * ----------------------------------------------------------------------------------------------------
 * | Start Byte | Packet Type | Packet Number | Payload Length |     Payload       | CRC32 | End Byte |
 * ----------------------------------------------------------------------------------------------------
*/
typedef struct OtaDataPacket {
    uint8_t sof;
    uint8_t packet_type;
    uint16_t packet_num;
    uint16_t payload_len;
    uint8_t* payload;
    uint32_t crc32;
    uint8_t eof;
}__attribute__((packed)) OtaDataPacket;

/*
 * Packet Structure:
 * ----------------------------------------------------------------------------------------------------
 * |     u8     |     u8      |      u16      |       u16      |        u8         |  u32  |    u8    |
 * ----------------------------------------------------------------------------------------------------
 * | Start Byte | Packet Type |   Reserved    | Payload Length |      Status       | CRC32 | End Byte |
 * ----------------------------------------------------------------------------------------------------
*/
typedef struct OtaResponsePacket {
    uint8_t sof;
    uint8_t packet_type;
    uint16_t packet_num;  // "don't care" for response packet
    uint16_t payload_len;
    uint8_t status;
    uint32_t crc32;
    uint8_t eof;
}__attribute__((packed)) OtaResponsePacket;


int etx_ota_download_and_flash( void );
#endif /* INC_ETX_OTA_UPDATE_H_ */
