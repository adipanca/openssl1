// /* Extras for OQS extension */

// /* Encodes two messages (classical and PQC) into one hybrid message:
//    classical_msg || pq_msg
//    hybrid_msg is allocated in this function.
//    Follows format specified in https://tools.ietf.org/html/draft-ietf-tls-hybrid-design-01#section-3.2
//  */
// static int OQS_encode_hybrid_message(const unsigned char* classical_msg,
//                                      const uint16_t classical_msg_len,
//                                      const unsigned char* pq_msg,
//                                      const uint16_t pq_msg_len,
//                                      unsigned char** hybrid_msg,
//                                      uint16_t* hybrid_msg_len) {
//   *hybrid_msg_len = classical_msg_len + pq_msg_len;
//   *hybrid_msg = OPENSSL_malloc(*hybrid_msg_len);
//   if (*hybrid_msg == NULL) {
//     return 0;
//   }

//   memcpy(*hybrid_msg, classical_msg, classical_msg_len);
//   memcpy(*hybrid_msg + classical_msg_len, pq_msg, pq_msg_len);

//   return 1;
// }

// /* Decodes hybrid message returning the classical and PQC messages:
//    classical_msg || pq_msg
//    classical_msg and pq_msg are allocated in this function.
//    Follows format specified in https://tools.ietf.org/html/draft-ietf-tls-hybrid-design-01#section-3.2
//  */
// static int OQS_decode_hybrid_message(const unsigned char* hybrid_msg,
//                                      const unsigned int group_id,
//                                      const int is_server,
//                                      unsigned char** classical_msg,
//                                      uint16_t* classical_msg_len,
//                                      unsigned char** pq_msg,
//                                      uint16_t* pq_msg_len) {

//   int ec_curve_id = OQS_KEM_CLASSICAL_CURVEID(group_id);
//   unsigned int pq_kem_id = OQS_KEM_NID(group_id);

//   switch (ec_curve_id) {
//       case 29: /* X25519 */
//           *classical_msg_len = 32;
//           break;
//       // case 30: /* X448 (opsional, kalau kamu pakai) */
//       //     *classical_msg_len = 56;
//       //     break;
//       case 23: /* P-256 */
//           *classical_msg_len = 65;
//           break;
//       case 24: /* P-384 */
//           *classical_msg_len = 97;
//           break;
//       case 25: /* P-521 */
//           *classical_msg_len = 133;
//           break;
//       default:
//           return 0;
//   }
//   *classical_msg = OPENSSL_malloc(*classical_msg_len);
//   if (*classical_msg == NULL) {
//     return 0;
//   }
//   memcpy(*classical_msg, hybrid_msg, *classical_msg_len);

//   OQS_KEM* oqs_kem = OQS_KEM_new(OQS_ALG_NAME(pq_kem_id));
//   if (oqs_kem == NULL) {
//       return 0;
//   }
//   if (is_server) {
//       *pq_msg_len = oqs_kem->length_public_key;
//   } else {
//       *pq_msg_len = oqs_kem->length_ciphertext;
//   }

//   *pq_msg = OPENSSL_malloc(*pq_msg_len);
//   if (*pq_msg == NULL) {
//     return 0;
//   }
//   memcpy(*pq_msg, hybrid_msg + *classical_msg_len, *pq_msg_len);

//   return 1;
// }


#ifndef HYB_ORDER_CLASSICAL_THEN_PQC
#define HYB_ORDER_CLASSICAL_THEN_PQC 0
#endif

static int OQS_encode_hybrid_message(const unsigned char* classical_msg,
                                     const uint16_t classical_msg_len,
                                     const unsigned char* pq_msg,
                                     const uint16_t pq_msg_len,
                                     unsigned char** hybrid_msg,
                                     uint16_t* hybrid_msg_len) {
  *hybrid_msg_len = classical_msg_len + pq_msg_len;
  *hybrid_msg = OPENSSL_malloc(*hybrid_msg_len);
  if (*hybrid_msg == NULL) return 0;

#if HYB_ORDER_CLASSICAL_THEN_PQC
  memcpy(*hybrid_msg, classical_msg, classical_msg_len);
  memcpy(*hybrid_msg + classical_msg_len, pq_msg, pq_msg_len);
#else
  memcpy(*hybrid_msg, pq_msg, pq_msg_len);
  memcpy(*hybrid_msg + pq_msg_len, classical_msg, classical_msg_len);
#endif

  return 1;
}


static int OQS_decode_hybrid_message(const unsigned char* hybrid_msg,
                                     const unsigned int group_id,
                                     const int is_server,
                                     unsigned char** classical_msg,
                                     uint16_t* classical_msg_len,
                                     unsigned char** pq_msg,
                                     uint16_t* pq_msg_len) {

  int ec_curve_id = OQS_KEM_CLASSICAL_CURVEID(group_id);
  unsigned int pq_kem_id = OQS_KEM_NID(group_id);

  switch (ec_curve_id) {
      case 29: *classical_msg_len = 32; break;   // X25519
      case 23: *classical_msg_len = 65; break;   // P-256
      case 24: *classical_msg_len = 97; break;   // P-384
      case 25: *classical_msg_len = 133; break;  // P-521
      default: return 0;
  }

  OQS_KEM* oqs_kem = OQS_KEM_new(OQS_ALG_NAME(pq_kem_id));
  if (oqs_kem == NULL) return 0;

  if (is_server)
      *pq_msg_len = oqs_kem->length_public_key;
  else
      *pq_msg_len = oqs_kem->length_ciphertext;

  *classical_msg = OPENSSL_malloc(*classical_msg_len);
  *pq_msg = OPENSSL_malloc(*pq_msg_len);
  if (*classical_msg == NULL || *pq_msg == NULL) return 0;

#if HYB_ORDER_CLASSICAL_THEN_PQC
  memcpy(*classical_msg, hybrid_msg, *classical_msg_len);
  memcpy(*pq_msg, hybrid_msg + *classical_msg_len, *pq_msg_len);
#else
  memcpy(*pq_msg, hybrid_msg, *pq_msg_len);
  memcpy(*classical_msg, hybrid_msg + *pq_msg_len, *classical_msg_len);
#endif

  return 1;
}
