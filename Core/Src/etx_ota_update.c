/*
 * etx_ota_update.c
 *
 *  Created on: 26-Jul-2021
 *      Author: EmbeTronicX
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "main.h"
#include "etx_ota_update.h"

/* Buffer to hold the received data */
static uint8_t RX_BUFFER[PACKET_MAX_SIZE];

/* OTA State */
static ota_state_t ota_state = IDLE;

/* Application Firmware Total Size and CRC32 */
static FileInfo fw_image_meta_data;
/* Firmware Size that we have received */
static uint32_t ota_fw_received_size = 0;

//static uint16_t etx_receive_chunk( uint8_t *buf, uint16_t max_len );
//static ETX_OTA_EX_ etx_process_data( uint8_t *buf, uint16_t len );
//static void etx_ota_send_resp( uint8_t type );
//static HAL_StatusTypeDef write_data_to_flash_app( uint8_t *data,
//                                        uint16_t data_len, bool is_full_image );

static int sendOtaResponse(uint8_t status);
static int receiveOtaPacket(uint8_t* buf, uint16_t size);
static int processOtaPacket(uint8_t* buf, uint16_t size);
static int flashWrite(uint8_t* data, uint16_t data_len, bool first_write);

/**
  * @brief Download the application from UART and flash it.
  * @param None
  * @retval ETX_OTA_EX_
  */
int etx_ota_download_and_flash(void) {
	printf("Starting OTA download\r\n");

	ota_state = START;
	int bytes_received = 0;

	while (ota_state != IDLE) {
		memset(RX_BUFFER, 0, PACKET_MAX_SIZE);

		bytes_received = receiveOtaPacket(RX_BUFFER, PACKET_MAX_SIZE);

		if (bytes_received > 0) {
			if (processOtaPacket(RX_BUFFER, bytes_received)) {
				printf("Error! HALTING!\n");
				sendOtaResponse(PACKET_NACK);
				return -1;
			} else {
				sendOtaResponse(PACKET_ACK);
			}
		} else {
			printf("No bytes received!!");
			break;
		}
	}

	return 0;
}


static int receiveOtaPacket(uint8_t* buf, uint16_t size) {
	// Parse Ota Packet
	HAL_StatusTypeDef ret;
	uint16_t index = 0;

	// Receive the SOF, packet type, packet number, and payload length (6 bytes)
	ret = HAL_UART_Receive(&huart3, buf + index, 6, HAL_MAX_DELAY);
	if (ret != HAL_OK) {
		printf("HAL Receive failed!\n");
		return 0;
	}

	if (buf[index] != PACKET_SOF) {
		printf("Did not receive SOF!\n");
		return 0;
	}

	// skip over SOF (1 byte), packet type (1 byte), and packet number (2 bytes)
	index += 4;

	uint16_t payload_len = *((uint16_t*) &buf[index]);
	index += 2;

	// receive payload
	ret = HAL_UART_Receive(&huart3, buf + index, payload_len, HAL_MAX_DELAY);
	if (ret != HAL_OK) {
		printf("HAL Receive failed!\n");
		return 0;
	}
	index += payload_len;

	// receive CRC
	ret = HAL_UART_Receive(&huart3, buf + index, 4, HAL_MAX_DELAY);
	if (ret != HAL_OK) {
		printf("HAL Receive failed!\n");
		return 0;
	}
	index += 4;

	// receive EOF
	ret = HAL_UART_Receive(&huart3, buf + index, 1, HAL_MAX_DELAY);
	if (ret != HAL_OK) {
		printf("HAL Receive failed!\n");
		return 0;
	}

	if (buf[index] != PACKET_EOF) {
		printf("Did not receive EOF!\n");
		return 0;
	}
	index += 1;

	return index;
}

static int sendOtaResponse(uint8_t status) {
	OtaResponsePacket response_packet;

    // Build command packet to send
    memset(&response_packet, 0, sizeof(OtaResponsePacket));
    response_packet.sof         = PACKET_SOF;
    response_packet.packet_type = OTA_RESPONSE;
    response_packet.packet_num  = 0;
    response_packet.payload_len = 1;
    response_packet.status      = status;
    response_packet.crc32       = 0;  // TBD: Implement CRC32
    response_packet.eof         = PACKET_EOF;

    HAL_StatusTypeDef ret = HAL_UART_Transmit(&huart3, (uint8_t*) &response_packet, sizeof(OtaResponsePacket), HAL_MAX_DELAY);
	if (ret != HAL_OK) {
		printf("Failed to send Ota response with status: %d!\n", status);
		return -1;
	}
	return 0;
}

static int processOtaPacket(uint8_t* buf, uint16_t size) {
    OtaCommandPacket* packet = (OtaCommandPacket*) buf;

    // Check if we received a ABORT command
    if (packet->packet_type == OTA_COMMAND && packet->cmd == OTA_ABORT_CMD) {
        printf("Received OTA ABORT command!\n");
        ota_state = IDLE;
        return 0;
    }

    switch(ota_state) {
        case START:
            if (packet->packet_type == OTA_COMMAND && packet->cmd == OTA_START_CMD) {
                printf("Received OTA START command!\n");
                ota_state = HEADER;
                return 0;
            }
            printf("Error: Expected OTA start command!\n");
            break;
        case HEADER:
            OtaHeaderPacket* header_packet = (OtaHeaderPacket*) buf;
            if (header_packet->packet_type == OTA_HEADER) {
                fw_image_meta_data.file_size = header_packet->file_info.file_size;
                fw_image_meta_data.crc32 = header_packet->file_info.crc32;
                ota_state = DATA;
                printf("Received OTA header! FW Size: %ld bytes\n", fw_image_meta_data.file_size);
                return 0;
            }
            printf("Error: Expected OTA header, received packet type: %d!\n", header_packet->packet_type);
            break;
        case DATA:
            OtaDataPacket* data_packet = (OtaDataPacket*) buf;
            if (data_packet->packet_type == OTA_DATA) {
            	uint8_t* data = (uint8_t*)
            			&(data_packet->payload);
            	flashWrite(data, data_packet->payload_len, (ota_fw_received_size == 0));
                ota_fw_received_size += data_packet->payload_len;
//                printf("Received %d bytes of data!\n", data_packet->payload_len);
                if (ota_fw_received_size >= fw_image_meta_data.file_size) {
                    ota_state = END;
                }
                return 0;
            }
            printf("Error: Expected OTA data!\n");
            break;
        case END:
            if (packet->packet_type == OTA_COMMAND && packet->cmd == OTA_END_CMD) {
                printf("Received OTA END command!\n");
                // TODO: Verify full package CRC
                ota_state = IDLE;
                return 0;
            }
            printf("Error: Expected OTA end command!\n");
            break;
        default:
            break;
    }

    // TODO: Add CRC verification

    // if we didn't return early, then we have an error
    return -1;
}


static int flashWrite(uint8_t* data, uint16_t data_len, bool first_write) {
	HAL_StatusTypeDef ret = HAL_FLASH_Unlock();
	if (ret != HAL_OK) {
		printf("Failed to unlock flash!\n");
		return -1;
	}

	// Erase flash once
	if (first_write) {
		FLASH_EraseInitTypeDef EraseInitStruct;
		uint32_t sector_error;

		EraseInitStruct.TypeErase     = FLASH_TYPEERASE_SECTORS;
		EraseInitStruct.Sector        = FLASH_SECTOR_6;
		EraseInitStruct.NbSectors     = 2;                    //erase 2 sectors(6,7)
		EraseInitStruct.VoltageRange  = FLASH_VOLTAGE_RANGE_3;

		printf("Erasing flash memory sectors %ld - %ld", EraseInitStruct.Sector, EraseInitStruct.Sector + EraseInitStruct.NbSectors - 1);
		ret = HAL_FLASHEx_Erase( &EraseInitStruct, &sector_error );
		if( ret != HAL_OK ) {
			printf("Failed to erase flash!\n");
			return -1;  // TODO: return HAL_FLASH_GetError()
		}
		printf("Erased flash successfully!\n");
	}

	// Write to flash
	for (int i = 0; i < data_len; i++) {
		ret = HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, APP_FLASH_ADDR + ota_fw_received_size, data[i]);
		if (ret != HAL_OK) {
			printf("Flash program failed! only %d bytes written to flash!\n", i);
			return -1;
		}
	}

    ret = HAL_FLASH_Lock();
    if( ret != HAL_OK ) {
    	printf("Failed to lock flash!\n");
    	return -1;
    }

    return 0;
}

