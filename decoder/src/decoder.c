/**
 * @file    decoder.c
 * @brief   Secure Decoder Implementation for eCTF.
 *
 * Este decoder valida el código de suscripción (C_SUBS) y, si es válido,
 * procede a descifrar el frame recibido.
 *
 * El proceso se basa en:
 *   - Verificar la integridad del bloque de suscripción usando AES-CMAC con K_master.
 *   - Extraer y validar los parámetros de suscripción: decoder_id, start, end, channel, encoder_id.
 *   - Derivar una clave dinámica a partir de g_channel_key y [#SEQ, CH_ID] y descifrar el frame en AES-CTR.
 *
 * Basado en lo descrito en main.pdf :contentReference[oaicite:0]{index=0}&#8203;:contentReference[oaicite:1]{index=1} y en el firmware original :contentReference[oaicite:2]{index=2}&#8203;:contentReference[oaicite:3]{index=3}.
 */

 #include <wolfssl/options.h>
 #include <wolfssl/wolfcrypt/aes.h>
 
 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 #include <stdlib.h>
 #include <stdbool.h>
 
 /* eCTF includes */
 #include "mxc_device.h"
 #include "status_led.h"
 #include "board.h"
 #include "mxc_delay.h"
 #include "simple_flash.h"
 #include "host_messaging.h"
 #include "simple_uart.h"
 
 /* ------------------- CONSTANTES --------------------- */
 #define HEADER_SIZE      20
 /* C_SUBS: 36 bytes de payload + 16 bytes de MAC = 52 bytes */
 #define SUBS_PAYLOAD_SIZE 36
 #define SUBS_MAC_SIZE    16
 #define SUBS_TOTAL_SIZE  (SUBS_PAYLOAD_SIZE + SUBS_MAC_SIZE)  // 52
 
 /* Frame: 8 bytes + 16 bytes trailer = 24 bytes */
 #define FRAME_SIZE       8
 #define TRAILER_SIZE     16
 #define CIPHER_SIZE      (FRAME_SIZE + TRAILER_SIZE) // 24
 
 /* Paquete total: 20 + 52 + 24 = 96 bytes */
 #define PACKET_MIN_SIZE  (HEADER_SIZE + SUBS_TOTAL_SIZE + CIPHER_SIZE)
 
 /* Configuración de suscripciones en flash */
 #define MAX_CHANNEL_COUNT 8
 #define EMERGENCY_CHANNEL 0
 #define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFFULL
 #define FLASH_FIRST_BOOT 0xDEADBEEF
 #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
 
 /* Estructuras de host messaging */
 #pragma pack(push, 1)
 typedef struct {
     uint32_t channel;
     uint64_t timestamp;
     uint8_t  data[FRAME_SIZE]; // 8 bytes de frame
 } frame_packet_t;
 
 /* Estructura del header */
 typedef struct {
     uint32_t seq;
     uint32_t channel;
     uint32_t encoder_id;
     uint64_t ts;
 } header_t;
 
 /* Estructura del payload de suscripción (36 bytes):
  * Contiene 5 enteros de 4 bytes y un campo de 16 bytes.
  * Orden: decoder_id, start_timestamp, end_timestamp, channel, encoder_id, partial_key
  */
 typedef struct {
     uint32_t decoder_id;
     uint32_t start;
     uint32_t end;
     uint32_t channel;
     uint32_t encoder_id;
     uint8_t  partial_key[16];
 } subscription_payload_t;
 
 /* Estructura de la lista de canales para LIST_MSG */
 typedef struct {
     uint32_t channel;
     uint64_t start;
     uint64_t end;
 } channel_info_t;
 
 typedef struct {
     uint32_t n_channels;
     channel_info_t channel_info[MAX_CHANNEL_COUNT];
 } list_response_t;
 #pragma pack(pop)
 
 /* Estructuras para flash */
 typedef struct {
     bool active;
     uint32_t id;           
     uint64_t start_timestamp;
     uint64_t end_timestamp;
 } channel_status_t;
 
 typedef struct {
     uint32_t first_boot; 
     channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
 } flash_entry_t;
 
 static flash_entry_t decoder_status;
 
 /* -------------- PROTOTIPOS --------------- */
 int is_subscribed(uint32_t channel);
 int decode(uint16_t pkt_len, uint8_t *encrypted_buf); 
 void init(void);
 
 void boot_flag(void);
 int list_channels(void);
 int update_subscription(uint16_t pkt_len, void *update_packet); // no modificado para SUBSCRIBE CMD
 
 /* -------------- Claves globales --------------- */
 static uint8_t g_channel_key[32];  // Clave específica por canal (por ejemplo, 32 bytes)
 static uint8_t G_K_MASTER[16];     // Master key (K_master)
 
 /* -------------- Función de carga de claves --------------- */
 int load_secure_keys(void) {
     /* Aquí se debería parsear "secure_decoder.json" para cargar channel_keys, etc.
        Por brevedad, se usan valores mock. */
     memset(G_K_MASTER, 0xAB, 16);
     memset(g_channel_key, 0xCD, 32);
     return 0;
 }
 
 /* -------------- Funciones de CMAC y AES --------------- */
 static void leftshift_onebit(const uint8_t* in, uint8_t* out)
 {
     uint8_t overflow = 0;
     for (int i = 15; i >= 0; i--) {
         out[i] = (in[i] << 1) | overflow;
         overflow = (in[i] & 0x80) ? 1 : 0;
     }
 }
 
 static int aes_ecb_encrypt_block(const uint8_t* key, int keyLen,
                                  const uint8_t* in, uint8_t* out)
 {
     Aes aes;
     int ret = wc_AesSetKey(&aes, key, keyLen, NULL, AES_ENCRYPTION);
     if (ret != 0) return ret;
     wc_AesEncryptDirect(&aes, out, in);
     return 0;
 }
 
 static int aes_cmac(const uint8_t* key, int keyLen,
                     const uint8_t* msg, size_t msg_len,
                     uint8_t mac[16])
 {
     uint8_t zero_block[16] = {0};
     uint8_t L[16];
     if (aes_ecb_encrypt_block(key, keyLen, zero_block, L) != 0)
         return -1;
 
     uint8_t K1[16], K2[16];
     leftshift_onebit(L, K1);
     if (L[0] & 0x80) {
         K1[15] ^= 0x87;
     }
     leftshift_onebit(K1, K2);
     if (K1[0] & 0x80) {
         K2[15] ^= 0x87;
     }
 
     size_t n = (msg_len + 15) / 16;
     bool complete = ((msg_len % 16) == 0 && msg_len != 0);
     if (n == 0) {
         n = 1;
         complete = false;
     }
 
     uint8_t M_last[16];
     memset(M_last, 0, 16);
     if (complete) {
         memcpy(M_last, msg + (n - 1) * 16, 16);
         for (int i = 0; i < 16; i++) {
             M_last[i] ^= K1[i];
         }
     } else {
         size_t rem = msg_len % 16;
         uint8_t temp[16];
         memset(temp, 0, 16);
         if (rem > 0) {
             memcpy(temp, msg + (n - 1) * 16, rem);
         }
         temp[rem] = 0x80;
         for (int i = 0; i < 16; i++) {
             M_last[i] = temp[i] ^ K2[i];
         }
     }
 
     Aes aes;
     if (wc_AesSetKey(&aes, key, keyLen, NULL, AES_ENCRYPTION) != 0) {
         return -1;
     }
 
     uint8_t X[16];
     memset(X, 0, 16);
     uint8_t block[16];
 
     for (size_t i = 0; i < n - 1; i++) {
         for (int j = 0; j < 16; j++) {
             block[j] = X[j] ^ msg[i * 16 + j];
         }
         wc_AesEncryptDirect(&aes, X, block);
     }
     for (int j = 0; j < 16; j++) {
         block[j] = X[j] ^ M_last[j];
     }
     wc_AesEncryptDirect(&aes, X, block);
 
     memcpy(mac, X, 16);
     return 0;
 }
 
 /* -------------- AES-CTR --------------- */
 static void aes_ctr_xcrypt(const uint8_t* key, int keyLen,
                            const uint8_t* nonce,
                            uint8_t* buffer, size_t length)
 {
     Aes aes;
     if (wc_AesSetKey(&aes, key, keyLen, NULL, AES_ENCRYPTION) != 0) {
         return;
     }
     uint8_t counter[16];
     memcpy(counter, nonce, 16);
 
     size_t blocks = length / 16;
     size_t rem = length % 16;
     uint8_t keystream[16];
 
     for (size_t i = 0; i < blocks; i++) {
         wc_AesEncryptDirect(&aes, keystream, counter);
         for (int j = 0; j < 16; j++) {
             buffer[i * 16 + j] ^= keystream[j];
         }
         for (int c = 15; c >= 0; c--) {
             counter[c]++;
             if (counter[c] != 0) break;
         }
     }
     if (rem > 0) {
         wc_AesEncryptDirect(&aes, keystream, counter);
         for (size_t j = 0; j < rem; j++) {
             buffer[blocks*16 + j] ^= keystream[j];
         }
     }
 }
 
 /* -------------- Helper: store64_be --------------- */
 static void store64_be(uint64_t val, uint8_t out[8])
 {
     out[0] = (val >> 56) & 0xff;
     out[1] = (val >> 48) & 0xff;
     out[2] = (val >> 40) & 0xff;
     out[3] = (val >> 32) & 0xff;
     out[4] = (val >> 24) & 0xff;
     out[5] = (val >> 16) & 0xff;
     out[6] = (val >>  8) & 0xff;
     out[7] = (val >>  0) & 0xff;
 }
 
 /**********************************************************
  ****************** secure_process_packet *****************
  **********************************************************/
 /**
  * @brief Procesa un paquete de 96 bytes:
  *   - Extrae header, bloque de suscripción y ciphertext.
  *   - Valida el bloque de suscripción usando AES-CMAC con K_master.
  *   - Parsea y valida los parámetros de suscripción.
  *   - Deriva una clave dinámica y descifra el frame con AES-CTR.
  *
  * @param packet   Paquete recibido.
  * @param packet_len  Longitud del paquete.
  * @param frame_out  Salida: puntero al frame descifrado (8 bytes).
  * @param frame_len_out Salida: longitud del frame (8 bytes).
  * @return 0 si OK, -1 si error.
  */
 static int secure_process_packet(const uint8_t* packet, size_t packet_len,
                                  uint8_t** frame_out, size_t* frame_len_out)
 {
     if (packet_len < PACKET_MIN_SIZE) {
         fprintf(stderr, "[decoder] ERROR: Paquete demasiado corto\n");
         return -1;
     }
 
     /* 1. Extraer header */
     header_t hdr;
     memcpy(&hdr, packet, HEADER_SIZE);
     printf("[decoder] Header: seq=%u, channel=%u, encoder_id=%u, ts=%llu\n",
            hdr.seq, hdr.channel, hdr.encoder_id, (unsigned long long)hdr.ts);
     fflush(stdout);
 
     /* 2. Extraer bloque de suscripción */
     const uint8_t* subs_block = packet + HEADER_SIZE;
     const uint8_t* subs_mac   = subs_block + SUBS_PAYLOAD_SIZE;
 
     uint8_t computed_mac[16];
     /* Verificar integridad del bloque de suscripción usando K_master */
     if (aes_cmac(G_K_MASTER, 16, subs_block, SUBS_PAYLOAD_SIZE, computed_mac) != 0) {
         fprintf(stderr, "[decoder] ERROR: Falló cálculo de MAC de suscripción\n");
         return -1;
     }
     if (memcmp(computed_mac, subs_mac, 16) != 0) {
         fprintf(stderr, "[decoder] ERROR: MAC de suscripción inválido\n");
         return -1;
     }
     printf("[decoder] MAC de suscripción válido\n");
     fflush(stdout);
 
     /* 3. Parsear payload de suscripción */
     subscription_payload_t sub_payload;
     memcpy(&sub_payload, subs_block, SUBS_PAYLOAD_SIZE);
 
     /* Validar parámetros de suscripción:
        - El decoder_id debe ser 1 (valor asignado a este dispositivo)
        - El canal y encoder_id deben coincidir con los del header
        - El timestamp debe estar entre start y end
     */
     if (sub_payload.decoder_id != 1) {
         fprintf(stderr, "[decoder] ERROR: decoder_id de suscripción (%u) no coincide con el esperado (1)\n",
                 sub_payload.decoder_id);
         return -1;
     }
     if (sub_payload.channel != hdr.channel) {
         fprintf(stderr, "[decoder] ERROR: Canal de suscripción (%u) no coincide con el header (%u)\n",
                 sub_payload.channel, hdr.channel);
         return -1;
     }
     if (sub_payload.encoder_id != hdr.encoder_id) {
         fprintf(stderr, "[decoder] ERROR: encoder_id de suscripción (%u) no coincide con el header (%u)\n",
                 sub_payload.encoder_id, hdr.encoder_id);
         return -1;
     }
     if (hdr.ts < sub_payload.start || hdr.ts > sub_payload.end) {
         fprintf(stderr, "[decoder] ERROR: ts (%llu) fuera del rango de suscripción (%u - %u)\n",
                 (unsigned long long)hdr.ts, sub_payload.start, sub_payload.end);
         return -1;
     }
     printf("[decoder] Parámetros de suscripción válidos\n");
     fflush(stdout);
 
     /* 4. Derivar clave dinámica para descifrar el frame.
        Se usa g_channel_key y se calcula dynamic_key = AES-CMAC(g_channel_key, [seq, channel] en LE)
     */
     uint8_t dynamic_key[16];
     uint8_t seq_channel[8];
     memcpy(seq_channel, &hdr.seq, 4);
     memcpy(seq_channel+4, &hdr.channel, 4);
     if (aes_cmac(g_channel_key, 16, seq_channel, 8, dynamic_key) != 0) {
         fprintf(stderr, "[decoder] ERROR: Falló derivación de dynamic_key\n");
         return -1;
     }
     printf("[decoder] Clave dinámica derivada\n");
     fflush(stdout);
 
     /* 5. Descifrar frame (24 bytes: 8 bytes de frame + 16 bytes de trailer) */
     size_t offset = HEADER_SIZE + SUBS_TOTAL_SIZE;
     uint8_t* ciphertext = (uint8_t*)malloc(CIPHER_SIZE);
     if (!ciphertext) return -1;
     memcpy(ciphertext, packet + offset, CIPHER_SIZE);
 
     /* Nonce para AES-CTR: 8 ceros + secuencia en big-endian (8 bytes) */
     uint8_t nonce[16] = {0};
     store64_be(hdr.seq, nonce+8);
     aes_ctr_xcrypt(dynamic_key, 16, nonce, ciphertext, CIPHER_SIZE);
 
     /* Extraer el frame: se asume que son los primeros 8 bytes */
     *frame_out = (uint8_t*)malloc(FRAME_SIZE);
     if (!*frame_out) {
         free(ciphertext);
         return -1;
     }
     memcpy(*frame_out, ciphertext, FRAME_SIZE);
     *frame_len_out = FRAME_SIZE;
     free(ciphertext);
 
     printf("[decoder] Frame descifrado exitosamente\n");
     fflush(stdout);
     return 0;
 }
 
 /* -------------- decode() -------------- */
 int decode(uint16_t pkt_len, uint8_t *encrypted_buf)
 {
     uint8_t *frame_plain = NULL;
     size_t frame_len = 0;
 
     if (secure_process_packet(encrypted_buf, pkt_len, &frame_plain, &frame_len) < 0) {
         STATUS_LED_RED();
         print_error("Decodificación falló\n");
         return -1;
     }
 
     /* Enviar el frame descifrado al host */
     write_packet(DECODE_MSG, frame_plain, (uint16_t)frame_len);
     free(frame_plain);
     return 0;
 }
 
 /* -------------- is_subscribed() -------------- */
 /* (Función auxiliar para comandos LIST y actualización en flash) */
 int is_subscribed(uint32_t channel) {
     if (channel == EMERGENCY_CHANNEL) {
         return 1;
     }
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == channel &&
             decoder_status.subscribed_channels[i].active) {
             return 1;
         }
     }
     return 0;
 }
 
 /* -------------- boot_flag() -------------- */
 void boot_flag(void) {
     print_debug("Boot Reference Flag: NOT_REAL_FLAG\n");
 }
 
 /* -------------- list_channels() -------------- */
 int list_channels() {
     list_response_t resp;
     uint16_t len;
     resp.n_channels = 0;
 
     for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].active) {
             resp.channel_info[resp.n_channels].channel =
                 decoder_status.subscribed_channels[i].id;
             resp.channel_info[resp.n_channels].start =
                 decoder_status.subscribed_channels[i].start_timestamp;
             resp.channel_info[resp.n_channels].end =
                 decoder_status.subscribed_channels[i].end_timestamp;
             resp.n_channels++;
         }
     }
     len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);
     write_packet(LIST_MSG, &resp, len);
     return 0;
 }
 
 /* -------------- update_subscription() -------------- */
 /* Esta función procesa comandos de actualización de suscripción (no relacionados al paquete recibido) */
 int update_subscription(uint16_t pkt_len, void *update_packet) {
     /* Se asume que el formato del paquete de actualización es compatible con el firmware original */
     subscription_update_packet_t *update = (subscription_update_packet_t*)update_packet;
 
     if (update->channel == EMERGENCY_CHANNEL) {
         STATUS_LED_RED();
         print_error("Cannot subscribe to emergency channel\n");
         return -1;
     }
     int i;
     for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (!decoder_status.subscribed_channels[i].active ||
             decoder_status.subscribed_channels[i].id == update->channel)
         {
             decoder_status.subscribed_channels[i].active = true;
             decoder_status.subscribed_channels[i].id = update->channel;
             decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
             decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
             break;
         }
     }
     if (i == MAX_CHANNEL_COUNT) {
         STATUS_LED_RED();
         print_error("Max subscriptions reached\n");
         return -1;
     }
     flash_simple_erase_page(FLASH_STATUS_ADDR);
     flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
     write_packet(SUBSCRIBE_MSG, NULL, 0);
     return 0;
 }
 
 /* -------------- init() -------------- */
 void init(void) {
     flash_simple_init();
     flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
 
     if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
         print_debug("First boot. Setting flash...\n");
         decoder_status.first_boot = FLASH_FIRST_BOOT;
         for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
             decoder_status.subscribed_channels[i].active = false;
             decoder_status.subscribed_channels[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
             decoder_status.subscribed_channels[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
         }
         flash_simple_erase_page(FLASH_STATUS_ADDR);
         flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(decoder_status));
     }
 
     if (uart_init() < 0) {
         STATUS_LED_ERROR();
         while (1) {}
     }
 
     if (load_secure_keys() != 0) {
         STATUS_LED_ERROR();
         print_error("Load secure keys error\n");
         while (1) {}
     }
 }
 
 /* -------------- MAIN -------------- */
 int main(void) {
     init();
     print_debug("Decoder Booted!\n");
 
     uint8_t uart_buf[1024];
     msg_type_t cmd;
     int result;
     uint16_t pkt_len;
 
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
                 boot_flag();
                 list_channels();
                 break;
             case DECODE_MSG:
                 STATUS_LED_PURPLE();
                 decode(pkt_len, uart_buf);
                 break;
             case SUBSCRIBE_MSG:
                 STATUS_LED_YELLOW();
                 update_subscription(pkt_len, (void*)uart_buf);
                 break;
             default:
                 STATUS_LED_ERROR();
                 print_error("Invalid Command\n");
                 break;
         }
     }
     return 0;
 }
 