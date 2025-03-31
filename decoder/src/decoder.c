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
 
 /* Incluir el header generado con las claves */
 #include "secrets.h"
 
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
 #define pkt_len_t uint16_t
 
 /* Calculate the flash address for channel info */
 #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
 
 #pragma pack(push, 1)
 typedef struct {
     channel_id_t channel;
     timestamp_t timestamp;
     uint8_t encrypted_frame[FRAME_SIZE];
     uint8_t mac[HMAC_SIZE];
     uint64_t seq_num;
 } secure_frame_packet_t;
 
 typedef struct {
     channel_id_t channel;
     decoder_id_t decoder_id;
     timestamp_t start_timestamp;
     timestamp_t end_timestamp;
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
     wc_HmacUpdate(&hmac, (uint8_t*)update, sizeof(secure_subscription_update_packet_t) - HMAC_SIZE);
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
     if (update->channel == EMERGENCY_CHANNEL) {
         STATUS_LED_RED();
         print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
         return -1;
     }
     
     if (!verify_subscription_hmac(update)) {
         STATUS_LED_RED();
         print_error("Subscription HMAC verification failed\n");
         return -1;
     }
     
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == update->channel || 
             !decoder_status.subscribed_channels[i].active) {
             decoder_status.subscribed_channels[i].active = true;
             decoder_status.subscribed_channels[i].id = update->channel;
             decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
             decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
             decoder_status.subscribed_channels[i].last_seq_num = 0;
             break;
         }
     }
     
     flash_simple_erase_page(FLASH_STATUS_ADDR);
     flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(secure_flash_entry_t));
     
     write_packet(SUBSCRIBE_MSG, NULL, 0);
     return 0;
 }
 
 int decode(pkt_len_t pkt_len, secure_frame_packet_t *new_frame) {
     Hmac hmac;
     Aes aes;
     uint8_t computed_mac[HMAC_SIZE];
     uint8_t decrypted_frame[FRAME_SIZE];
     uint8_t nonce[NONCE_SIZE];
     uint8_t *channel_key;
     
     // Verify channel subscription and timestamp
     if (!is_subscribed(new_frame->channel, new_frame->timestamp)) {
         STATUS_LED_RED();
         print_error("Unsubscribed channel or invalid timestamp\n");
         return -1;
     }
     
     // Verify MAC
     wc_HmacInit(&hmac, NULL, INVALID_DEVID);
     wc_HmacSetKey(&hmac, SHA256, decoder_status.secrets.mac_key, KEY_SIZE);
     wc_HmacUpdate(&hmac, (uint8_t*)new_frame, sizeof(secure_frame_packet_t) - HMAC_SIZE);
     wc_HmacFinal(&hmac, computed_mac);
     
     if (memcmp(computed_mac, new_frame->mac, HMAC_SIZE) != 0) {
         STATUS_LED_RED();
         print_error("Frame MAC verification failed\n");
         return -1;
     }
     
     // Check sequence number to prevent replay
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == new_frame->channel) {
             if (new_frame->seq_num <= decoder_status.subscribed_channels[i].last_seq_num) {
                 STATUS_LED_RED();
                 print_error("Replay attack detected\n");
                 return -1;
             }
             decoder_status.subscribed_channels[i].last_seq_num = new_frame->seq_num;
             break;
         }
     }
     
     // Select channel key (emergency or specific channel)
     channel_key = (new_frame->channel == EMERGENCY_CHANNEL) ? 
          decoder_status.secrets.master_key : 
          decoder_status.secrets.channel_keys[new_frame->channel - 1];
     
     // Prepare nonce
     memcpy(nonce, &new_frame->channel, sizeof(channel_id_t));
     memcpy(nonce + sizeof(channel_id_t), &new_frame->timestamp, sizeof(timestamp_t));
     memcpy(nonce + sizeof(channel_id_t) + sizeof(timestamp_t), &new_frame->seq_num, sizeof(uint64_t));
     
     // Decrypt frame
     wc_AesInit(&aes, NULL, INVALID_DEVID);
     wc_AesSetKey(&aes, channel_key, KEY_SIZE, nonce, AES_ENCRYPTION);
     wc_AesCtrEncrypt(&aes, decrypted_frame, new_frame->encrypted_frame, FRAME_SIZE);
     wc_AesFree(&aes);
     
     // Write decrypted frame
     write_packet(DECODE_MSG, decrypted_frame, FRAME_SIZE);
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
         decoder_status.first_boot = FLASH_FIRST_BOOT;
         
         // Initialize channel statuses
         memset(decoder_status.subscribed_channels, 0, sizeof(decoder_status.subscribed_channels));
         
         // Zero out secrets
         memset(&decoder_status.secrets, 0, sizeof(secure_secrets_t));
         
         /* En este ejemplo se copia directamente la master key y claves desde el header.
            En un sistema real se debe decodificar la cadena Base64 para obtener los bytes. */
         memcpy(decoder_status.secrets.master_key, MASTER_KEY_BASE64, KEY_SIZE);
         memcpy(decoder_status.secrets.mac_key, MAC_KEY_BASE64, KEY_SIZE);
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
     uint8_t uart_buf[sizeof(secure_frame_packet_t)];
     msg_type_t cmd;
     int result;
     uint16_t pkt_len;
     
     init();
     
     print_debug("Secure Decoder Booted!\n");
     
     while (1) {
         print_debug("Ready\n");
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
 