#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "main.h"
#include "ota_update.h"

/* Buffer to hold the received data */
static uint8_t RX_BUFFER[PACKET_MAX_SIZE];
/* OTA State */
static ota_state_t ota_state = IDLE;
/* Application Firmware Total Size and CRC32 */
static FileInfo fw_image_meta_data;
/* Firmware Size that we have received */
static uint32_t ota_fw_received_size = 0;
/* Hardware CRC Handle */
extern CRC_HandleTypeDef hcrc;

static int sendOtaResponse(uint8_t status);
static int receiveOtaPacket(uint8_t* buf, uint16_t size);
static int processOtaPacket(uint8_t* buf, uint16_t size);
static int flashWrite(uint8_t* data, uint16_t data_len, bool first_write);

static const uint32_t crc_table[0x100] = {
  0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005, 0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
  0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC, 0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8, 0x6ED82B7F, 0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD,
  0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039, 0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0xBE2B5B58, 0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033, 0xA4AD16EA, 0xA06C0B5D,
  0xD4326D90, 0xD0F37027, 0xDDB056FE, 0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95, 0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4, 0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D,
  0x34867077, 0x30476DC0, 0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5, 0x2AC12072, 0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16, 0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA,
  0x7897AB07, 0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02, 0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1, 0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
  0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B, 0xBB60ADFC, 0xB6238B25, 0xB2E29692, 0x8AAD2B2F, 0x8E6C3698, 0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A,
  0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E, 0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2, 0xC6BCF05F, 0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34, 0xDC3ABDED, 0xD8FBA05A,
  0x690CE0EE, 0x6DCDFD59, 0x608EDB80, 0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB, 0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53,
  0x251D3B9E, 0x21DC2629, 0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B, 0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF, 0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623,
  0xF12F560E, 0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65, 0xEBA91BBC, 0xEF68060B, 0xD727BBB6, 0xD3E6A601, 0xDEA580D8, 0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
  0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2, 0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B, 0x9B3660C6, 0x9FF77D71, 0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74, 0x857130C3,
  0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640, 0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21, 0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24,
  0x119B4BE9, 0x155A565E, 0x18197087, 0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC, 0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654,
  0xC5A92679, 0xC1683BCE, 0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB, 0xDBEE767C, 0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18, 0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4,
  0x89B8FD09, 0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662, 0x933EB0BB, 0x97FFAD0C, 0xAFB010B1, 0xAB710D06, 0xA6322BDF, 0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4,
};

uint32_t CalcCRC(uint8_t* pData, uint32_t DataLength) {
    uint32_t Checksum = 0xFFFFFFFF;
    for (unsigned int i=0; i < DataLength; i++) {
        uint8_t top = (uint8_t)(Checksum >> 24);
        top ^= pData[i];
        Checksum = (Checksum << 8) ^ crc_table[top];
    }
    return Checksum;
}


/**
  * @brief Download the application from UART and flash it.
  * @param None
  * @retval ETX_OTA_EX_
  */
int runOtaUpdate() {
	sendOtaResponse(PACKET_ACK);  // Send Ack to signal that we are ready to start OTA

	ota_state = START;
	int bytes_received = 0;

	while (ota_state != IDLE) {
		memset(RX_BUFFER, 0, PACKET_MAX_SIZE);

		bytes_received = receiveOtaPacket(RX_BUFFER, PACKET_MAX_SIZE);
		if (bytes_received > 0) {
			if (processOtaPacket(RX_BUFFER, bytes_received)) {
				sendOtaResponse(PACKET_NACK);
				return -1;
			} else {
				sendOtaResponse(PACKET_ACK);
			}
		} else {
			// Error
			sendOtaResponse(PACKET_NACK);
		}
	}

	return 0;
}


static int receiveOtaPacket(uint8_t* buf, uint16_t size) {
	// Parse Ota Packet
	HAL_StatusTypeDef ret;
	uint16_t index = 0;
	uint32_t computed_crc = 0;
	uint32_t received_crc = 0;
	memset(buf, 0, PACKET_MAX_SIZE);

	// Receive the SOF, packet type, packet number, and payload length (6 bytes)
	ret = HAL_UART_Receive(&huart5, buf + index, 6, HAL_MAX_DELAY);
	if (ret != HAL_OK) {
		return 0;
	}

	if (buf[index] != PACKET_SOF) {
//		printf("Did not receive SOF!\n");
		return 0;
	}
	index += 6;

	// Get payload length (bytes 4 and 5)
	uint16_t payload_len = *((uint16_t*) &buf[4]);
	// receive payload
	ret = HAL_UART_Receive(&huart5, buf + index, payload_len, HAL_MAX_DELAY);
	if (ret != HAL_OK) {
//		printf("HAL Receive failed!\n");
		return 0;
	}
	index += payload_len;

	// receive crc
	ret = HAL_UART_Receive(&huart5, buf + index, 4, HAL_MAX_DELAY);
	if (ret != HAL_OK) {
//		printf("HAL Receive failed!\n");
		return 0;
	}
	received_crc = *((uint32_t*) &buf[index]);
	index += 4;

    // Compute CRC (excluding received CRC and EOF)
    computed_crc = CalcCRC((uint8_t*) &buf[6], payload_len);

	// receive EOF
	ret = HAL_UART_Receive(&huart5, buf + index, 1, HAL_MAX_DELAY);
	if (ret != HAL_OK) {
//		printf("HAL Receive failed!\n");
		return 0;
	}
	if (buf[index] != PACKET_EOF) {
//		printf("Did not receive EOF!\n");
		return 0;
	}
	index++;

	// Compute CRC on the fields from SOF to payload (exclude crc (4 bytes) and end byte (1 byte))
	if (computed_crc != received_crc) {
		return 0;
	}

	return index;
}

static int sendOtaResponse(uint8_t status) {
	OtaResponsePacket response_packet;
//    size_t crc_size = sizeof(OtaResponsePacket) - sizeof(response_packet.crc32) - sizeof(response_packet.eof);
//    size_t crc_buffer_size = (crc_size + sizeof(uint32_t) - 1) / sizeof(uint32_t); // Ceiling division
//    uint32_t crc_buffer[crc_buffer_size];

    // Build command packet to send
    memset(&response_packet, 0, sizeof(OtaResponsePacket));
    response_packet.sof         = PACKET_SOF;
    response_packet.packet_type = OTA_RESPONSE;
    response_packet.packet_num  = 0;
    response_packet.payload_len = 1;
    response_packet.status      = status;
//    memcpy(crc_buffer, &response_packet, crc_size);
    response_packet.crc32		= CalcCRC((uint8_t*) &response_packet.status, response_packet.payload_len);
    response_packet.eof         = PACKET_EOF;

    HAL_StatusTypeDef ret = HAL_UART_Transmit(&huart5, (uint8_t*) &response_packet, sizeof(OtaResponsePacket), HAL_MAX_DELAY);
	if (ret != HAL_OK) {
//		printf("Failed to send Ota response with status: %d!\n", status);
		return -1;
	}
	return 0;
}

static int processOtaPacket(uint8_t* buf, uint16_t size) {
    OtaCommandPacket* packet = (OtaCommandPacket*) buf;

    // Check if we received a ABORT command
    if (packet->packet_type == OTA_COMMAND && packet->cmd == OTA_ABORT_CMD) {
//        printf("Received OTA ABORT command!\n");
        ota_state = IDLE;
        return 0;
    }

    switch(ota_state) {
        case START:
            if (packet->packet_type == OTA_COMMAND && packet->cmd == OTA_START_CMD) {
//                printf("Received OTA START command!\n");
                ota_state = HEADER;
                return 0;
            }
//            printf("Error: Expected OTA start command!\n");
            break;

        case HEADER:
            OtaHeaderPacket* header_packet = (OtaHeaderPacket*) buf;
            if (header_packet->packet_type == OTA_HEADER) {
                fw_image_meta_data.file_size = header_packet->file_info.file_size;
                fw_image_meta_data.crc32 = header_packet->file_info.crc32;
                ota_state = DATA;
//                printf("Received OTA header! FW Size: %ld bytes\n", fw_image_meta_data.file_size);
                return 0;
            }
//            printf("Error: Expected OTA header, received packet type: %d!\n", header_packet->packet_type);
            break;

        case DATA:
            OtaDataPacket* data_packet = (OtaDataPacket*) buf;
            if (data_packet->packet_type == OTA_DATA) {
            	uint8_t* data = (uint8_t*) &(data_packet->payload);
            	flashWrite(data, data_packet->payload_len, (ota_fw_received_size == 0));
                ota_fw_received_size += data_packet->payload_len;
                if (ota_fw_received_size >= fw_image_meta_data.file_size) {
                    ota_state = END;
                }
                return 0;
            }
//            printf("Error: Expected OTA data!\n");
            break;

        case END:
            if (packet->packet_type == OTA_COMMAND && packet->cmd == OTA_END_CMD) {
//                printf("Received OTA END command!\n");
                // Verify full package CRC
                uint32_t computed_crc = CalcCRC((uint8_t*) APP_FLASH_ADDR, fw_image_meta_data.file_size);
                if (computed_crc != fw_image_meta_data.crc32) {
                	return -1;
                }

                ota_state = IDLE;
                return 0;
            }
//            printf("Error: Expected OTA end command!\n");
            break;

        default:
            break;
    }

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
		EraseInitStruct.Sector        = FLASH_SECTOR_3;
		EraseInitStruct.NbSectors     = 5;                    //erase 5 sectors (3, 4, 5, 6, 7)
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
		ret = HAL_FLASH_Program(FLASH_TYPEPROGRAM_BYTE, APP_FLASH_ADDR + ota_fw_received_size + i, data[i]);
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

