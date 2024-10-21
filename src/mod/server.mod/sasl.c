/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sasl.c -- part of server.mod
 *
 * Written by Michael Ortmann
 *
 * Copyright (C) 2019 - 2024 Eggheads Development Team
 */

#undef answer /* before resolv.h because it could collide with src/mod/module.h
               * (dietlibc) */
#include <resolv.h> /* base64 encode b64_ntop() and base64 decode b64_pton() */

/* RFC 5802 - printable ASCII characters excluding ','
 * printable = %x21-2B / %x2D-7E
 */
#define CHARSET_SCRAM "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e"

#define CLIENT_KEY "Client Key"
#define SERVER_KEY "Server Key"

/* Available sasl mechanisms */
enum {
  SASL_MECHANISM_PLAIN,
  SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE,
  SASL_MECHANISM_EXTERNAL,
  SASL_MECHANISM_SCRAM_SHA_256,
  SASL_MECHANISM_SCRAM_SHA_512,
  /* TODO: https://github.com/atheme/atheme/blob/master/modules/saslserv/ecdh-x25519-challenge.c */
  /* SASL_MECHANISM_ECDH_X25519_CHALLENGE, */
  SASL_MECHANISM_NUM
};

#define SASL_PASSWORD_MAX  120
#define SASL_ECDSA_KEY_MAX 120

static int sasl_timeout_time = 0;
static int sasl_continue = 1;
static char sasl_username[NICKMAX + 1];
static int sasl_mechanism = 0;
static char sasl_password[SASL_PASSWORD_MAX + 1];
static char sasl_ecdsa_key[SASL_ECDSA_KEY_MAX + 1];
static int sasl_timeout = 15;
int sasl = 0;

/* Available sasl mechanisms. */
static char const *SASL_MECHANISMS[SASL_MECHANISM_NUM] = {
  [SASL_MECHANISM_PLAIN]                    = "PLAIN",
  [SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE] = "ECDSA-NIST256P-CHALLENGE",
  [SASL_MECHANISM_EXTERNAL]                 = "EXTERNAL",
  [SASL_MECHANISM_SCRAM_SHA_256]            = "SCRAM-SHA-256",
  [SASL_MECHANISM_SCRAM_SHA_512]            = "SCRAM-SHA-512",
  /* [SASL_MECHANISM_ECDH_X25519_CHALLENGE]    = "ECDH-X25519-CHALLENGE", */
};

/* scram state */
#ifdef TLS
#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
const EVP_MD *digest;
char salted_password[EVP_MAX_MD_SIZE];
static int step = 0;
char nonce[21]; /* atheme defines acceptable client nonce len min 8 max 512 chars
                 * nonce 128 bit = math.ceil(128 / math.log(93, 2)) = 20 chars
                 * 3 major irc clients and postgres use 18, looks like ripping is still a thing ;)
                 */
char client_first_message[1024];
int digest_len, auth_message_len;
char auth_message[3069];
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
#endif /* TLS */

static void sasl_error(const char *msg)
{
  putlog(LOG_SERV, "*", "SASL: %s", msg);
  dprintf(DP_MODE, "CAP END\n");
  sasl_timeout_time = 0;
  if (!sasl_continue) {
    putlog(LOG_DEBUG, "*", "SASL: Aborting connection and retrying");
    nuke_server("sasl");
  }
}

static void sasl_secondly()
{
  if (!--sasl_timeout_time)
    sasl_error("timeout");
}

/* Got 901: RPL_LOGGEDOUT, users account name is unset (whether by SASL or
 * otherwise)
 */
static int got901(char *from, char *msg)
{
  newsplit(&msg); /* nick */
  newsplit(&msg); /* nick!ident@host */
  fixcolon(msg);
  putlog(LOG_SERV, "*", "%s: %s", from, msg);
  return 0;
}

/* Got 902: ERR_NICKLOCKED, authentication fails b/c nick is unavailable
 * Got 904: ERR_SASLFAIL, invalid credentials (or something not covered)
 * Got 905: ERR_SASLTOOLONG, AUTHENTICATE command was too long (>400 bytes)
 * Got 906: ERR_SASL_ABORTED, sent AUTHENTICATE command with * as parameter
 * For easy grepping, this covers got902 got904 got905 got906
 */
static int gotsasl90X(char *from, char *msg)
{
  newsplit(&msg); /* nick */
  fixcolon(msg);
  sasl_error(msg);
  return 0;
}

/* Got 903: RPL_SASLSUCCESS, authentication successful */
static int got903(char *from, char *msg)
{
  newsplit(&msg); /* nick */
  fixcolon(msg);
  putlog(LOG_SERV, "*", "SASL: %s", msg);
  dprintf(DP_MODE, "CAP END\n");
  sasl_timeout_time = 0;
  return 0;
}

/* Got 907: ERR_SASLALREADY, already authenticated */
static int got907(char *from, char *msg)
{
  putlog(LOG_SERV, "*", "SASL: Already authenticated");
  return 0;
}

/* Got 908: RPL_SASLMECHS, available mechanisms by network */
static int got908(char *from, char *msg)
{
  char s[128];

  newsplit(&msg); /* nick */
  fixcolon(msg);
  putlog(LOG_SERV, "*", "SASL: Available mechanisms: %s", msg);
  del_capability("sasl");
  snprintf(s, sizeof s, "sasl=%s", msg);
  add_capabilities(s);
  return 0;
}

static int sasl_plain(char *client_msg_plain)
{
  /* Don't use snprintf() due to \0 inside */
  char *s = client_msg_plain;
  s = stpcpy(s, sasl_username) + 1;
  s = stpcpy(s, sasl_username) + 1;
  s = stpcpy(s, sasl_password);
  return s - client_msg_plain;
}

#ifdef TLS
static int sasl_ecdsa_nist256p_challange_step_0(char *client_msg_plain)
{
  /* Don't use snprintf() due to \0 inside */
  char *s = client_msg_plain;
  s = stpcpy(s, sasl_username) + 1;
  s = stpcpy(s, sasl_username);
  return s - client_msg_plain;
}

static int sasl_ecdsa_nist256p_challange_step_1(
  char *restrict client_msg_plain, char *restrict server_msg_plain,
  int server_msg_plain_len)
{
  FILE *fp;
  char error_msg[256]; /* snprintf() truncation should be tolerable */
  EVP_PKEY *pkey;

  if (!(fp = fopen(sasl_ecdsa_key, "r"))) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE error: could not open "
             "file sasl_ecdsa_key %s: %s\n", sasl_ecdsa_key, strerror(errno));
    sasl_error(error_msg);
    return -1;
  }
  if (!(pkey = PEM_read_PrivateKey(fp, NULL, 0, NULL))) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE: "
             "PEM_read_PrivateKey(): SSL error = %s\n",
             ERR_error_string(ERR_get_error(), 0));
    sasl_error(error_msg);
    fclose(fp);
    return -1;
  }
  fclose(fp);
#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
  EVP_PKEY_CTX *ctx;
  size_t siglen;

  /* The EVP interface to digital signatures should almost always be used in
   * preference to the low level interfaces.
   */
  if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL))) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE: EVP_PKEY_CTX_new(): "
             "SSL error = %s\n", ERR_error_string(ERR_get_error(), 0));
    sasl_error(error_msg);
    return -1;
  }
  EVP_PKEY_free(pkey);
  if (EVP_PKEY_sign_init(ctx) <= 0) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE: EVP_PKEY_sign_init():"
             "SSL error = %s\n", ERR_error_string(ERR_get_error(), 0));
    sasl_error(error_msg);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE: "
             "EVP_PKEY_CTX_set_signature_md(): SSL error = %s\n",
             ERR_error_string(ERR_get_error(), 0));
    sasl_error(error_msg);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  /* EVP_PKEY_sign() must be used instead of EVP_DigestSign*() and EVP_Sign*(),
   * because EVP_PKEY_sign() does not hash the data to be signed.
   * EVP_PKEY_sign() is for signing digests, EVP_DigestSign*() and EVP_Sign*()
   * are for signing messages.
   */
  if (EVP_PKEY_sign(ctx, NULL, &siglen, (unsigned char *) server_msg_plain, server_msg_plain_len) <= 0) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE: EVP_PKEY_sign(): SSL "
             "error = %s\n", ERR_error_string(ERR_get_error(), 0));
    sasl_error(error_msg);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  if (EVP_PKEY_sign(ctx, (unsigned char *) client_msg_plain, &siglen, (unsigned char *) server_msg_plain, server_msg_plain_len) <= 0) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE: EVP_PKEY_sign(): SSL "
             "error = %s\n", ERR_error_string(ERR_get_error(), 0));
    sasl_error(error_msg);
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }
  EVP_PKEY_CTX_free(ctx);
#else
  EC_KEY *eckey;
  int ret;
  unsigned int siglen;

  eckey = EVP_PKEY_get1_EC_KEY(pkey);
  EVP_PKEY_free(pkey);
  if (!eckey) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE: "
             "EVP_PKEY_get1_EC_KEY(): SSL error = %s\n",
             ERR_error_string(ERR_get_error(), 0));
    sasl_error(error_msg);
    return -1;
  }
  ret = ECDSA_sign(0, (const unsigned char *) server_msg_plain,
                   server_msg_plain_len,
                   (unsigned char *) client_msg_plain, &siglen, eckey);
  EC_KEY_free(eckey);
  if (!ret) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE: ECDSA_sign() SSL "
             "error = %s\n", ERR_error_string(ERR_get_error(), 0));
    sasl_error(error_msg);
    return -1;
  } 
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
  return siglen;
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
static int sasl_scram_step_0(char *client_msg_plain, int client_msg_plain_len)
{
  /* TODO: after sasl scram merged make_rand_str_from_chars() should be made
   * return unbiased uniformed randoms
   */
  make_rand_str_from_chars(nonce, (sizeof nonce) - 1, CHARSET_SCRAM);
  return snprintf(client_msg_plain, client_msg_plain_len, "n,,n=%s,r=%s",
                  sasl_username, nonce);
}

static int sasl_scram_step_1(char *restrict client_msg_plain,
                             int client_msg_plain_len,
                             char *restrict server_msg_plain)
{
  char server_first_message[1024];
  char *word, *brkb, *server_nonce = 0, *salt_b64 = 0, *i = 0;
  char error_msg[128]; /* snprintf() truncation should be tolerable */
  int salt_plain_len, iter, j;
  char salt_plain[64]; /* atheme: Valid values are 8 to 64 (inclusive) */
  char client_key[EVP_MAX_MD_SIZE];
  unsigned int client_key_len, stored_key_len;
  unsigned char stored_key[EVP_MAX_MD_SIZE];
  char client_final_message_without_proof[1024];
  unsigned char client_signature[EVP_MAX_MD_SIZE];
  unsigned char client_proof[EVP_MAX_MD_SIZE];
  char client_proof_b64[1024];

  strlcpy(server_first_message, server_msg_plain, sizeof server_first_message);
  for (word = strtok_r(server_msg_plain,  ",", &brkb);
       word;
       word = strtok_r(NULL, ",", &brkb)) {
    switch (*word) {
      case 'r':
        if (
#if OPENSSL_VERSION_NUMBER >= 0x1010008fL /* 1.1.0h */
            CRYPTO_memcmp
#else
            memcmp
#endif
            (word + 2, nonce, (sizeof nonce) - 1)) {
          sasl_error("AUTHENTICATE error: server nonce != client nonce");
          return -1;
        }
        server_nonce = word + 2;
        break;
      case 's':
        salt_b64 = word + 2;
        break;
      case 'i':
        i = word + 2;
        break;
      case 'e':
        snprintf(error_msg, sizeof error_msg, "AUTHENTICATE error: server error: %s", word + 2);
	sasl_error(error_msg);
        return -1;
      default:
        putlog(LOG_SERV, "*", "SASL: AUTHENTICATE warning: SCRAM Attribute ignored: %s", word);
    }
  }
  if (!server_nonce) {
    sasl_error("AUTHENTICATE error: server nonce missing from SCRAM challenge");
    return -1;
  }
  if (!salt_b64) {
    sasl_error("AUTHENTICATE error: salt missing from SCRAM challenge");
    return -1;
  }
  if (!i) {
    sasl_error("AUTHENTICATE error: iteration count missing from SCRAM challenge");
    return -1;
  }
  /* TODO: normalize(password)
   * Eggdrop doesnt have support for utf8 normalization yet
   * tcl also doesnt have it in core yet, only in tcllib
   * We could use glib or something
   */

  if ((salt_plain_len = b64_pton(salt_b64, (unsigned char*) salt_plain, sizeof salt_plain)) == -1) {
    sasl_error("AUTHENTICATE error: could not base64 decode salt");
    return -1;
  }
  errno = 0;
  iter = strtol(i, NULL, 10);
  if (errno) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE error: strtol(%s): %s", i, strerror(errno));
    sasl_error(error_msg);
    return -1;
  }

  printf("DEBUG: server_nonce: >>>%s<<<\n", server_nonce);
  printf("DEBUG: salt_b64: >>>%s<<<\n", salt_b64);
  printf("DEBUG: iter: %i\n", iter);
  printf("DEBUG: salt_plain_len: %i\n", salt_plain_len);

  if (sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_256)
    digest = EVP_sha256();
  else
    digest = EVP_sha512();
  digest_len = EVP_MD_size(digest);
  /* TODO: print time spent for pbkdf2 func */
  if (!PKCS5_PBKDF2_HMAC(sasl_password, strlen(sasl_password),
                         (const unsigned char *) salt_plain, salt_plain_len,
                         iter, digest, digest_len,
                         (unsigned char *) salted_password)) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE error: "
             "PKCS5_PBKDF2_HMAC(): %s", ERR_error_string(ERR_get_error(),
	     NULL));
    sasl_error(error_msg);
    return -1;
  }

  printf("DEBUG: salted_password ready\n");

  /* ClientKey       := HMAC(SaltedPassword, "Client Key") */

  if (!HMAC(digest, salted_password, digest_len, (unsigned char *) CLIENT_KEY,
            strlen(CLIENT_KEY), (unsigned char *) client_key,
	    &client_key_len)) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE error: HMAC(): %s",
             ERR_error_string(ERR_get_error(), NULL));
    sasl_error(error_msg);
    return -1;
  }

  printf("DEBUG: client_key ready\n");

  /* StoredKey       := H(ClientKey) */

  if (!EVP_Digest(client_key, client_key_len, stored_key, &stored_key_len, digest, NULL)) {
    snprintf(error_msg, sizeof error_msg,
             "AUTHENTICATE error: EVP_Digest(): %s",
             ERR_error_string(ERR_get_error(), NULL));
    sasl_error(error_msg);
    return -1;
  }

  printf("DEBUG: stored_key ready\n");

  /* AuthMessage     := client-first-message-bare + "," +
   *                    server-first-message + "," +
   *                    client-final-message-without-proof
   */

  snprintf(client_final_message_without_proof,
           sizeof client_final_message_without_proof, "c=biws,r=%s",
           server_nonce);

  printf("DEBUG: client_final_message_without_proof = >>>%s<<<\n", client_final_message_without_proof);

  auth_message_len = snprintf(auth_message, sizeof auth_message, "%s,%s,%s",
                              client_first_message + 3, server_first_message,
                              client_final_message_without_proof);

  printf("DEBUG: auth_message ready: >>>%s<<<\n", auth_message);

  /* ClientSignature := HMAC(StoredKey, AuthMessage) */

  printf("DEBUG: digestlen: %i auth_message_len: %i\n", digest_len, auth_message_len);

  if (!HMAC(digest, stored_key, digest_len, (unsigned char *) auth_message,
            auth_message_len, client_signature, NULL)) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE error: HMAC(): %s",
             ERR_error_string(ERR_get_error(), NULL));
    sasl_error(error_msg);
    return -1;
  }

  printf("DEBUG: client_signature ready\n");

  /* ClientProof     := ClientKey XOR ClientSignature */

  printf("DEBUG: client_key_len: %i\n", client_key_len);

  for (j = 0; j < client_key_len; j++)
    client_proof[j] = client_key[j] ^ client_signature[j];

  printf("DEBUG: client_proof ready\n");

  if (b64_ntop(client_proof, client_key_len, client_proof_b64, sizeof client_proof_b64) == -1) {
    sasl_error("AUTHENTICATE error: could not base64 encode");
    return -1;
  }

  printf("DEBUG: base64-encoded client_proof ready\n");

  printf("DEBUG: client_final_message_without_proof = >>>%s<<<\n", client_final_message_without_proof);

  return snprintf(client_msg_plain, client_msg_plain_len, "%s,p=%s",
                  client_final_message_without_proof, client_proof_b64);
}

static void sasl_scram_step_2(char *restrict client_msg_plain,
                             int client_msg_plain_len,
                             char *restrict server_msg_plain)
{
  char server_key[EVP_MAX_MD_SIZE];
  unsigned int server_key_len;
  char error_msg[128]; /* snprintf() truncation should be tolerable */
  unsigned char server_signature[EVP_MAX_MD_SIZE];
  char server_signature_b64[128];
  int server_signature_b64_len;

  /* ServerKey       := HMAC(SaltedPassword, "Server Key") */

  if (!HMAC(digest, salted_password, digest_len, (unsigned char *) SERVER_KEY,
            strlen(SERVER_KEY), (unsigned char *) server_key,
            &server_key_len)) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE error: HMAC(): %s",
             ERR_error_string(ERR_get_error(), NULL));
    sasl_error(error_msg);
    return;
  }

  printf("DEBUG: server_key ready\n");

  /* ServerSignature := HMAC(ServerKey, AuthMessage) */

  printf("DEBUG: digestlen: %i auth_message_len: %i\n", digest_len, auth_message_len);

  if (!HMAC(digest, server_key, digest_len, (unsigned char *) auth_message,
            auth_message_len, server_signature, NULL)) {
    snprintf(error_msg, sizeof error_msg, "AUTHENTICATE error: HMAC(): %s",
             ERR_error_string(ERR_get_error(), NULL));
    sasl_error(error_msg);
    return;
  }

  printf("DEBUG: server_signature ready\n");

  if ((server_signature_b64_len = b64_ntop(server_signature, digest_len, server_signature_b64, sizeof server_signature_b64)) == -1) {
    sasl_error("AUTHENTICATE error: could not base64 encode");
    return;
  }

  printf("DEBUG: base64-encoded server_signature ready\n");

  printf("DEBUG: server_signature_b64 = >>>%s<<<\n", server_signature_b64);

  printf("DEBUG: server_signature_b64_len = %i\n", server_signature_b64_len);

  if (
#if OPENSSL_VERSION_NUMBER >= 0x1010008fL /* 1.1.0h */
      CRYPTO_memcmp
#else
      memcmp
#endif
      (server_msg_plain + 2, server_signature_b64, server_signature_b64_len)) {
    sasl_error("invalid server signature");
    return;
  }

  putlog(LOG_SERV, "*", "SASL: authentication of server successful");
  dprintf(DP_MODE, "AUTHENTICATE +\n");
  sasl_timeout_time = 0;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
#endif /* TLS */

/* TODO:
 *   modularize
 *     aim is final version <= 70 lines
 *   state machine, at least for scram
 *   guard sasl auth with timeout
 *   sasl-password should be sasl-password-file so we read the pass from file
 *     and keep it only in memory while we need it,
 *   we could also enable/disable all sasl raw bindings to minimize attack
 *   surface
 *   in the end, fuzzing would be nice, coze we do a lot of parsing here
 *   server_iter and rusage should be displayed for the function calling
 *   pbkdf2(server_iter)
 *   cache the client_key (assuming the Salt and hash iteration-count is stable)
 *   support authenticate split by 400 byte, like:
 *     https://github.com/ircv3/ircv3-specifications/commit/838ef397385065bbc5c29d934bbb407e5b5a5ce5
 *     400-byte chunk, see: https://ircv3.net/specs/extensions/sasl-3.1.html
 *     base64 padding
 *     The response is encoded in Base64 (RFC 4648), then split to
 *       400-byte chunks, and each chunk is sent as a separate AUTHENTICATE
 *       command.
 */
static int gotauthenticate(char *from, char *msg)
{
  char client_msg_plain[1024];
  int client_msg_plain_len;
#ifdef TLS
  char server_msg_plain[1024];
  char error_msg[1050]; /* snprintf() truncation should be tolerable */
  int server_msg_plain_len;
#endif
  #ifndef MAX
  #define MAX(a,b) (((a)>(b))?(a):(b))
  #endif
  char client_msg_b64[((MAX((sizeof client_msg_plain), 400) + 2) / 3) << 2] = "";


  putlog(LOG_DEBUG, "*", "SASL: got AUTHENTICATE %s", msg);
  fixcolon(msg); /* Because Inspircd does its own thing */
#ifdef TLS
  if (*msg == '+') {
#endif
    if (!*sasl_username) { /* TODO: mind. fuer EXTERNAL muessen wir das nicht machen */
      putlog(LOG_SERV, "*", "SASL: sasl-username not set, setting it to "
             "username %s", botname);
      strlcpy(sasl_username, botuser, sizeof sasl_username);
    }
#ifdef TLS
    switch (sasl_mechanism) {
      case SASL_MECHANISM_PLAIN:
#endif
        client_msg_plain_len = sasl_plain(client_msg_plain);
#ifdef TLS
        break;
      case SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE:
        client_msg_plain_len = sasl_ecdsa_nist256p_challange_step_0(client_msg_plain);
        break;
      case SASL_MECHANISM_EXTERNAL:
        putlog(LOG_DEBUG, "*", "SASL: put AUTHENTICATE Response +");
        dprintf(DP_MODE, "AUTHENTICATE +\n");
        return 0;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
      case SASL_MECHANISM_SCRAM_SHA_256:
      case SASL_MECHANISM_SCRAM_SHA_512:
        client_msg_plain_len = sasl_scram_step_0(client_msg_plain, sizeof client_msg_plain);
        strlcpy(client_first_message, client_msg_plain,
                sizeof client_first_message); /* TODO: do this here or in sasl_scram_step_0() ? */
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
    }
  } else {
    if ((server_msg_plain_len = b64_pton(msg, (unsigned char*) server_msg_plain, sizeof server_msg_plain)) == -1) {
      sasl_error("AUTHENTICATE: could not base64 decode line from server");
      return 0;
    }
    if (server_msg_plain_len < 2) {
      sasl_error("AUTHENTICATE: server message too short");
      return 0;
    }
    if (*server_msg_plain == 'e') {
      snprintf(error_msg, sizeof error_msg, "AUTHENTICATE: server error: %s", server_msg_plain + 2);
      sasl_error(error_msg);
      return 0;
    }
    if (sasl_mechanism == SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE) {
      if ((client_msg_plain_len = sasl_ecdsa_nist256p_challange_step_1(client_msg_plain, server_msg_plain, server_msg_plain_len)) < 0)
        return 0;
    }
#if OPENSSL_VERSION_NUMBER >= 0x10000000L /* 1.0.0 */
    else
      if (step == 0) {
        if ((client_msg_plain_len = sasl_scram_step_1(client_msg_plain, sizeof client_msg_plain, server_msg_plain)) < 0)
          return 0;
        step++;
      } else {
        sasl_scram_step_2(client_msg_plain, sizeof client_msg_plain, server_msg_plain);
        return 0;
      }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10000000L */
  }
#endif /* TLS */
  if (b64_ntop((unsigned char *) client_msg_plain, client_msg_plain_len, client_msg_b64, sizeof client_msg_b64) == -1) {
    sasl_error("AUTHENTICATE: could not base64 encode");
    return 0;
  }
  putlog(LOG_DEBUG, "*", "SASL: put AUTHENTICATE Response %s", client_msg_b64);
  dprintf(DP_MODE, "AUTHENTICATE %s\n", client_msg_b64);
  return 0;
}

static char *traced_sasl_mechanism(ClientData cdata, Tcl_Interp *irp,
                                   EGG_CONST char *name1,
                                   EGG_CONST char *name2, int flags)
{
  if ((sasl_mechanism < 0) || (sasl_mechanism >= SASL_MECHANISM_NUM))
    return "sasl-mechanism is not set to an allowed value, please check it and"
           " try again";
#ifdef TLS
#ifndef HAVE_EVP_PKEY_GET1_EC_KEY
  if (sasl_mechanism == SASL_MECHANISM_ECDSA_NIST256P_CHALLENGE)
    return "SASL NIST256P functionality missing from your TLS libs, please "
           "choose a different SASL method";
#endif /* HAVE_EVP_PKEY_GET1_EC_KEY */
#if OPENSSL_VERSION_NUMBER < 0x10000000L /* 1.0.0 */
  if ((sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_256) ||
      (sasl_mechanism == SASL_MECHANISM_SCRAM_SHA_512))
    return "SASL SCRAM functionality needs openssl version 1.0.0 or higher, "
           "please choose a different SASL method";
#endif /* OPENSSL_VERSION_NUMBER < 0x10000000L */
#else /* TLS */
  if (sasl_mechanism != SASL_MECHANISM_PLAIN)
    return "The selected SASL authentication method requires TLS libraries "
           "which are not installed on this machine. Please choose the PLAIN "
           "method.";
#endif /* TLS */
  return NULL;
}

static cmd_t sasl_raw[] = {
  {"901",          "",   (IntFunc) got901,          NULL},
  {"902",          "",   (IntFunc) gotsasl90X,      NULL},
  {"903",          "",   (IntFunc) got903,          NULL},
  {"904",          "",   (IntFunc) gotsasl90X,      NULL},
  {"905",          "",   (IntFunc) gotsasl90X,      NULL},
  {"906",          "",   (IntFunc) gotsasl90X,      NULL},
  {"907",          "",   (IntFunc) got907,          NULL},
  {"908",          "",   (IntFunc) got908,          NULL},
  {"AUTHENTICATE", "",   (IntFunc) gotauthenticate, NULL},
  {NULL,           NULL, NULL,                      NULL}
};

static tcl_ints sasl_tcl_ints[] = {
  {"sasl",           &sasl,           0},
  {"sasl-mechanism", &sasl_mechanism, 0},
  {"sasl-continue",  &sasl_continue,  0},
  {"sasl-timeout",   &sasl_timeout,   0},
  {NULL,             NULL,            0}
};

static tcl_strings sasl_tcl_strings[] = {
  {"sasl-username",  sasl_username,  NICKMAX,            0},
  {"sasl-password",  sasl_password,  SASL_PASSWORD_MAX,  0},
  {"sasl-ecdsa-key", sasl_ecdsa_key, SASL_ECDSA_KEY_MAX, 0},
  {NULL,             NULL,           0,                  0}
};

static void sasl_close()
{
  rem_builtins(H_raw, sasl_raw);
  rem_tcl_ints(sasl_tcl_ints);
  rem_tcl_strings(sasl_tcl_strings);
  Tcl_UntraceVar(interp, "sasl-mechanism", TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
                 traced_sasl_mechanism, NULL);
}

static void sasl_start()
{
  Tcl_TraceVar(interp, "sasl-mechanism", TCL_TRACE_WRITES | TCL_TRACE_UNSETS,
               traced_sasl_mechanism, NULL);
  add_builtins(H_raw, sasl_raw);
  add_tcl_ints(sasl_tcl_ints);
  add_tcl_strings(sasl_tcl_strings);
}

/* There are two forms of the AUTHENTICATE command: initial client message and
 * later messages. The initial client message specifies the SASL mechanism to
 * be used.
*/
/* TODO: aktuell versucht eggdrop EXTERNAL ueber non-ssl verbindung, das kann
 * doch nicht funktionieren, oder? also sollte eggdrop da eine warnung loggen
 * und es gar nicht erst versuchen.
 */
int sasl_authenticate_initial(const struct cap_values *cap_value_list)
{
  char error_msg[128];
  putlog(LOG_DEBUG, "*", "SASL: Starting authentication process");
  if (!is_cap_value(cap_value_list, SASL_MECHANISMS[sasl_mechanism])) {
    snprintf(error_msg, sizeof error_msg,
             "authentication mechanism %s not supported by server",
             SASL_MECHANISMS[sasl_mechanism]); /* TODO: report server supported mechanisms */
    sasl_error(error_msg);
    return 1;
  }
  putlog(LOG_DEBUG, "*", "SASL: AUTHENTICATE %s", SASL_MECHANISMS[sasl_mechanism]);
  dprintf(DP_MODE, "AUTHENTICATE %s\n", SASL_MECHANISMS[sasl_mechanism]);
  sasl_timeout_time = sasl_timeout;
  return 0;
}
