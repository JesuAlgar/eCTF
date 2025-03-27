/**
 * @file    decoder.c
 * @brief   Secure Decoder Implementation for eCTF
 */

 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 #include <wolfssl/wolfcrypt/aes.h>
 #include <wolfssl/wolfcrypt/hmac.h>
 #include <wolfssl/wolfcrypt/random.h>
 
 #include "mxc_device.h"
 #include "status_led.h"
 #include "board.h"
 #include "mxc_delay.h"
 #include "simple_flash.h"
 #include "host_messaging.h"
 #include "simple_uart.h"
 
 /* Comment out include for testing */
 /* #include "secrets.h" */
 
 /* Temporary definitions for testing - These would normally come from secrets.h */
 static const uint8_t MASTER_KEY[32] = {
     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
 };
 
 static const uint8_t MAC_KEY[32] = {
     0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
     0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
 };
 
 static const uint8_t CHANNEL_KEY_1[32] = {
     0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
     0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60
 };
 
 static const uint8_t CHANNEL_KEY_2[32] = {
     0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
     0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80
 };
 
 static const uint8_t CHANNEL_KEY_3[32] = {
     0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
     0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0
 };
 
 static const uint8_t CHANNEL_KEY_4[32] = {
     0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
     0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0
 };
 
 static const uint8_t CHANNEL_KEY_5[32] = {
     0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
     0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0
 };
 
 static const uint8_t CHANNEL_KEY_6[32] = {
     0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
     0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00
 };
 
 static const uint8_t CHANNEL_KEY_7[32] = {
     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
 };
 
 static const uint8_t CHANNEL_KEY_8[32] = {
     0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
     0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
 };
 
 /* Definitions for types and constants */
 #define MAX_CHANNEL_COUNT 8
 #define EMERGENCY_CHANNEL 0
 #define FRAME_SIZE 64
 #define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
 #define FLASH_FIRST_BOOT 0xDEADBEEF
 #define HMAC_SIZE 32
 #define NONCE_SIZE 20
 #define KEY_SIZE 32
 
 #define timestamp_t uint64_t
 #define channel_id_t uint32_t
 #define decoder_id_t uint32_t
 #define encoder_id_t uint32_t
 #define pkt_len_t uint16_t
 
 /* Calculate the flash address for channel info */
 #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
 
 /* Define the decoder ID - This should come from actual hardware or configuration */
 #define THIS_DECODER_ID 0x87654321
 
 /* Helper function to create debug strings */
 static char debug_buffer[256];
 
 #pragma pack(push, 1)
 typedef struct {
     channel_id_t channel;
     timestamp_t timestamp;
     encoder_id_t encoder_id;
     uint8_t encrypted_frame[FRAME_SIZE + 16]; // +16 for timestamp and seq_num
     uint8_t mac[HMAC_SIZE];
     uint64_t seq_num;
 } secure_frame_packet_t;
 
 typedef struct {
     channel_id_t channel;
     decoder_id_t decoder_id;
     timestamp_t start_timestamp;
     timestamp_t end_timestamp;
     encoder_id_t encoder_id;
     uint8_t hmac[HMAC_SIZE];
 } secure_subscription_update_packet_t;
 
 typedef struct {
     uint8_t master_key[KEY_SIZE];
     uint8_t channel_keys[MAX_CHANNEL_COUNT][KEY_SIZE];
     uint8_t mac_key[KEY_SIZE];
 } secure_secrets_t;
 
 typedef struct {
     bool active;
     channel_id_t id;
     timestamp_t start_timestamp;
     timestamp_t end_timestamp;
     uint64_t last_seq_num;
 } secure_channel_status_t;
 
 typedef struct {
     uint32_t first_boot;
     decoder_id_t decoder_id;
     secure_channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
     secure_secrets_t secrets;
 } secure_flash_entry_t;
 #pragma pack(pop)
 
 /* Definiciones para listar canales */
 #pragma pack(push, 1)
 typedef struct {
     channel_id_t channel;
     timestamp_t start;
     timestamp_t end;
 } channel_info_t;
 
 typedef struct {
     uint32_t n_channels;
     channel_info_t channel_info[MAX_CHANNEL_COUNT];
 } list_response_t;
 #pragma pack(pop)
 
 secure_flash_entry_t decoder_status;
 WC_RNG rng;
 
 int verify_subscription_hmac(secure_subscription_update_packet_t *update) {
     Hmac hmac;
     uint8_t computed_hmac[HMAC_SIZE];
     
     wc_HmacInit(&hmac, NULL, INVALID_DEVID);
     wc_HmacSetKey(&hmac, SHA256, decoder_status.secrets.mac_key, KEY_SIZE);
     
     // Update HMAC with all fields except the HMAC itself
     wc_HmacUpdate(&hmac, (uint8_t*)&update->channel, sizeof(channel_id_t));
     wc_HmacUpdate(&hmac, (uint8_t*)&update->decoder_id, sizeof(decoder_id_t));
     wc_HmacUpdate(&hmac, (uint8_t*)&update->encoder_id, sizeof(encoder_id_t));
     wc_HmacUpdate(&hmac, (uint8_t*)&update->start_timestamp, sizeof(timestamp_t));
     wc_HmacUpdate(&hmac, (uint8_t*)&update->end_timestamp, sizeof(timestamp_t));
     
     wc_HmacFinal(&hmac, computed_hmac);
     
     return (memcmp(computed_hmac, update->hmac, HMAC_SIZE) == 0);
 }
 
 int is_subscribed(channel_id_t channel, timestamp_t timestamp) {
     if (channel == EMERGENCY_CHANNEL) return 1;
     
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == channel && 
             decoder_status.subscribed_channels[i].active &&
             timestamp >= decoder_status.subscribed_channels[i].start_timestamp &&
             timestamp <= decoder_status.subscribed_channels[i].end_timestamp) {
             return 1;
         }
     }
     return 0;
 }
 
 int update_subscription(pkt_len_t pkt_len, secure_subscription_update_packet_t *update) {
     if (pkt_len < sizeof(secure_subscription_update_packet_t)) {
         STATUS_LED_RED();
         print_error("Invalid subscription packet size\n");
         return -1;
     }
     
     if (update->channel == EMERGENCY_CHANNEL) {
         STATUS_LED_RED();
         print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
         return -1;
     }
     
     // Verify that the decoder ID in the subscription matches this decoder
     if (update->decoder_id != decoder_status.decoder_id) {
         STATUS_LED_RED();
         print_error("Subscription decoder ID mismatch\n");
         return -1;
     }
     
     if (!verify_subscription_hmac(update)) {
         STATUS_LED_RED();
         print_error("Subscription HMAC verification failed\n");
         return -1;
     }
     
     // Find an empty slot or the existing channel entry
     int slot = -1;
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (!decoder_status.subscribed_channels[i].active || 
             decoder_status.subscribed_channels[i].id == update->channel) {
             slot = i;
             break;
         }
     }
     
     if (slot == -1) {
         STATUS_LED_RED();
         print_error("No free subscription slots available\n");
         return -1;
     }
     
     // Update subscription
     decoder_status.subscribed_channels[slot].active = true;
     decoder_status.subscribed_channels[slot].id = update->channel;
     decoder_status.subscribed_channels[slot].start_timestamp = update->start_timestamp;
     decoder_status.subscribed_channels[slot].end_timestamp = update->end_timestamp;
     decoder_status.subscribed_channels[slot].last_seq_num = 0;
     
     // Save to flash
     flash_simple_erase_page(FLASH_STATUS_ADDR);
     flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(secure_flash_entry_t));
     
     write_packet(SUBSCRIBE_MSG, NULL, 0);
     return 0;
 }
 
 // Reemplazando la función AesCtrEncrypt que no está disponible
 void custom_aes_ctr_encrypt(Aes* aes, uint8_t* out, const uint8_t* in, size_t len) {
     uint8_t counter[16] = {0};
     uint8_t encBuf[16];
     size_t i, j;
     
     // Extraer el IV inicial 
     uint8_t iv[16];
     wc_AesGetIV(aes, iv);
     
     // Inicializar contador con IV
     memcpy(counter, iv, 16);
     
     for (i = 0; i < len; i += 16) {
         // Cifrar el contador
         wc_AesEncryptDirect(aes, encBuf, counter);
         
         // XOR con el texto plano para obtener el texto cifrado
         for (j = 0; j < 16 && (i + j) < len; j++) {
             out[i + j] = in[i + j] ^ encBuf[j];
         }
         
         // Incrementar el contador
         for (j = 15; j >= 0; j--) {
             if (++counter[j]) break;
         }
     }
 }
 
 int decode(pkt_len_t pkt_len, secure_frame_packet_t *new_frame) {
     Hmac hmac;
     Aes aes;
     uint8_t computed_mac[HMAC_SIZE];
     uint8_t decrypted_frame[FRAME_SIZE + 16]; // +16 for TS and seq_num
     uint8_t nonce[16]; // AES-CTR uses 16 byte nonce/IV
     uint8_t *channel_key;
     
     if (pkt_len < sizeof(secure_frame_packet_t)) {
         STATUS_LED_RED();
         print_error("Invalid frame packet size\n");
         return -1;
     }
     
     // Verify channel subscription and timestamp
     if (!is_subscribed(new_frame->channel, new_frame->timestamp)) {
         STATUS_LED_RED();
         print_error("Unsubscribed channel or invalid timestamp\n");
         return -1;
     }
     
     // Verify MAC - following the approach from PDF section 1.3
     wc_HmacInit(&hmac, NULL, INVALID_DEVID);
     wc_HmacSetKey(&hmac, SHA256, decoder_status.secrets.mac_key, KEY_SIZE);
     
     // Update HMAC with all the fields except the MAC itself
     wc_HmacUpdate(&hmac, (uint8_t*)&new_frame->channel, sizeof(channel_id_t));
     wc_HmacUpdate(&hmac, (uint8_t*)&new_frame->timestamp, sizeof(timestamp_t));
     wc_HmacUpdate(&hmac, new_frame->encrypted_frame, sizeof(new_frame->encrypted_frame));
     wc_HmacUpdate(&hmac, (uint8_t*)&new_frame->seq_num, sizeof(uint64_t));
     wc_HmacUpdate(&hmac, (uint8_t*)&new_frame->encoder_id, sizeof(encoder_id_t));
     
     wc_HmacFinal(&hmac, computed_mac);
     
     if (memcmp(computed_mac, new_frame->mac, HMAC_SIZE) != 0) {
         STATUS_LED_RED();
         print_error("Frame MAC verification failed\n");
         return -1;
     }
     
     // Check sequence number to prevent replay
     int channel_index = -1;
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == new_frame->channel && 
             decoder_status.subscribed_channels[i].active) {
             channel_index = i;
             
             if (new_frame->seq_num <= decoder_status.subscribed_channels[i].last_seq_num) {
                 STATUS_LED_RED();
                 print_error("Replay attack detected\n");
                 return -1;
             }
             decoder_status.subscribed_channels[i].last_seq_num = new_frame->seq_num;
             break;
         }
     }
     
     if (channel_index == -1 && new_frame->channel != EMERGENCY_CHANNEL) {
         STATUS_LED_RED();
         print_error("Channel not found in subscriptions\n");
         return -1;
     }
     
     // Select channel key (emergency or specific channel)
     if (new_frame->channel == EMERGENCY_CHANNEL) {
         channel_key = decoder_status.secrets.master_key;
     } else {
         channel_key = decoder_status.secrets.channel_keys[new_frame->channel - 1];
     }
     
     // Prepare nonce for AES-CTR decryption
     // Combining channel, timestamp and seq number as per PDF section 1.3
     memset(nonce, 0, sizeof(nonce));
     memcpy(nonce, &new_frame->channel, sizeof(channel_id_t));
     memcpy(nonce + sizeof(channel_id_t), &new_frame->timestamp, sizeof(timestamp_t));
     memcpy(nonce + sizeof(channel_id_t) + sizeof(timestamp_t), &new_frame->seq_num, 4); // Using part of seq_num
     
     // Decrypt frame using AES-CTR (custom implementation)
     wc_AesInit(&aes, NULL, INVALID_DEVID);
     wc_AesSetKey(&aes, channel_key, KEY_SIZE, nonce, AES_ENCRYPTION);
     
     // Usar nuestra implementación personalizada de AES-CTR ya que wc_AesCtrEncrypt no está disponible
     custom_aes_ctr_encrypt(&aes, decrypted_frame, new_frame->encrypted_frame, sizeof(new_frame->encrypted_frame));
     wc_AesFree(&aes);
     
     // Extract only the frame portion (without TS and seq_num)
     uint8_t frame_only[FRAME_SIZE];
     memcpy(frame_only, decrypted_frame, FRAME_SIZE);
     
     // Write decrypted frame
     write_packet(DECODE_MSG, frame_only, FRAME_SIZE);
     return 0;
 }
 
 int list_channels() {
     list_response_t resp;
     pkt_len_t len;
   
     resp.n_channels = 0;
   
     for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].active) {
             resp.channel_info[resp.n_channels].channel = decoder_status.subscribed_channels[i].id;
             resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
             resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
             resp.n_channels++;
         }
     }
   
     len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);
   
     // Success message
     write_packet(LIST_MSG, &resp, len);
     return 0;
 }
 
 void init() {
     int ret;
     
     // Initialize WolfSSL RNG
     wc_InitRng(&rng);
     
     flash_simple_init();
     
     flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(secure_flash_entry_t));
     if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
         // First time initialization
         decoder_status.first_boot = FLASH_FIRST_BOOT;
         decoder_status.decoder_id = THIS_DECODER_ID; // Set the decoder ID
         
         // Initialize channel statuses
         memset(decoder_status.subscribed_channels, 0, sizeof(decoder_status.subscribed_channels));
         
         // Load keys from the temporary keys defined at the top of this file
         memcpy(decoder_status.secrets.master_key, MASTER_KEY, KEY_SIZE);
         memcpy(decoder_status.secrets.mac_key, MAC_KEY, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[0], CHANNEL_KEY_1, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[1], CHANNEL_KEY_2, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[2], CHANNEL_KEY_3, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[3], CHANNEL_KEY_4, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[4], CHANNEL_KEY_5, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[5], CHANNEL_KEY_6, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[6], CHANNEL_KEY_7, KEY_SIZE);
         memcpy(decoder_status.secrets.channel_keys[7], CHANNEL_KEY_8, KEY_SIZE);
         
         flash_simple_erase_page(FLASH_STATUS_ADDR);
         flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(secure_flash_entry_t));
     }
     
     ret = uart_init();
     if (ret < 0) {
         STATUS_LED_ERROR();
         while (1);
     }
 }
 
 int main(void) {
     uint8_t uart_buf[sizeof(secure_frame_packet_t) > sizeof(secure_subscription_update_packet_t) ? 
                       sizeof(secure_frame_packet_t) : sizeof(secure_subscription_update_packet_t)];
     msg_type_t cmd;
     int result;
     uint16_t pkt_len;
     
     init();
     
     // Imprimir mensaje de inicio simple sin formato
     print_debug("Secure Decoder Booted!");
     
     // Para formatear el ID, crear una cadena formateada primero
     sprintf(debug_buffer, "Decoder ID: 0x%08X", decoder_status.decoder_id);
     print_debug(debug_buffer);
     
     while (1) {
         print_debug("Ready");
         STATUS_LED_GREEN();
         
         result = read_packet(&cmd, uart_buf, &pkt_len);
         if (result < 0) {
             STATUS_LED_ERROR();
             print_error("Failed to receive cmd from host\n");
             continue;
         }
         
         switch (cmd) {
             case LIST_MSG:
                 STATUS_LED_CYAN();
                 list_channels();
                 break;
             case DECODE_MSG:
                 STATUS_LED_PURPLE();
                 decode(pkt_len, (secure_frame_packet_t *)uart_buf);
                 break;
             case SUBSCRIBE_MSG:
                 STATUS_LED_YELLOW();
                 update_subscription(pkt_len, (secure_subscription_update_packet_t *)uart_buf);
                 break;
             default:
                 STATUS_LED_ERROR();
                 print_error("Invalid Command\n");
                 break;
         }
     }
 }