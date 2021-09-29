/*
 * Copyright © 2021, Radu-Alexandru Mantu <andru.mantu@gmail.com>
 *
 * This file is part of app-fw.
 *
 * app-fw is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * app-fw is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with app-fw. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>         /* [u]int*_t */
#include <gpgme.h>          /* gpgme */
#include <termios.h>        /* tcgetattr, tcsetattr */
#include <locale.h>         /* setlocale, LC_CTYPE */
#include <unistd.h>         /* write */
#include <string.h>         /* memmove */
#include <openssl/sha.h>    /* SHA256_DIGEST_LENGTH */

#include "gpg_helpers.h"
#include "util.h"

/******************************************************************************
 ************************** INTERNAL DATA STRUCTURES **************************
 ******************************************************************************/

static gpgme_ctx_t ctx;         /* gpgme context    */
static gpgme_key_t key;         /* gpgme key object */

/******************************************************************************
 ********************************* PUBLIC API *********************************
 ******************************************************************************/

int32_t gpg_init(char *_ep, char *_kh, char *_kfp, uint8_t _pem);
int32_t gpg_fini(void);
int32_t gpg_packet_signature(void *sgn, void *buff, size_t len);

/******************************************************************************
 ************************** INTERNAL HELPER FUNCTIONS *************************
 ******************************************************************************/

/******************************************************************************
 ************************** PUBLIC API IMPLEMENTATION *************************
 ******************************************************************************/

/* gpg_init - initialize gpgme
 *  @_ep  : gpg engine path (probably /usr/bin/gpg)
 *  @_kh  : keystore home (can be NULL -> gpgme uses default)
 *  @_kfp : shortform key fingerprint (lsb 4 bytes hexstring)
 *  @_pem : pinentry mode (1 = default-ncurses, 0 = loopback)
 *
 *  @return : 0 if everything went well
 */
int32_t gpg_init(char *_ep, char *_kh, char *_kfp, uint8_t _pem)
{
    const char             *version;    /* gpgme version               */
    const char             *algo;       /* gpgme algorithm             */
    gpgme_error_t          err;         /* gpgme error                 */
    ssize_t                ans;         /* answer                      */
    
    /* initialize gpgme (also gets version) */
    version = gpgme_check_version(NULL);
    RET(!version, -1, "could not initialize gpgme");
    INFO("using gpgme v%s", version);

    /* initialize locale */
    err = gpgme_set_locale(NULL, LC_CTYPE, setlocale(LC_CTYPE, NULL));
    RET(err != GPG_ERR_NO_ERROR, -1,
        "gpgme locale failed to initialize (%s | %s)",
        gpgme_strsource(err), gpgme_strerror(err));
    INFO("set gpgme locale to current locale");

    /* check that SHA256 is a known algo to gpgme */
    algo = gpgme_hash_algo_name(GPGME_MD_SHA256);
    RET(!algo, -1, "gpgme does not know of SHA256");
    INFO("gpgme can use SHA256");

    /* create new gpgme context */
    err = gpgme_new(&ctx);
    RET(err != GPG_ERR_NO_ERROR, -1,
        "unable to create gpgme context (%s | %s)",
        gpgme_strsource(err), gpgme_strerror(err));
    INFO("created new gpgme context");

    /* set crypto engine backend */
    err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OPENPGP, _ep, _kh);
    RET(err != GPG_ERR_NO_ERROR, -1,
        "unable to set crypto engine protocol (%s | %s)",
        gpgme_strsource(err), gpgme_strerror(err));
    INFO("initialized OpenPGP backend as \"%s\" with home in \"%s\"", _ep, _kh);

    /* set pinentry mode                                     *
     * NOTE: for now, we don't implement loopback mode       *
     *       make sure you increase gpg-agent cache validity */
    RET(_pem == 0, -1, "loopback pinentry mode is not supported");

    err = gpgme_set_pinentry_mode(ctx, _pem ? GPGME_PINENTRY_MODE_DEFAULT
                                            : GPGME_PINENTRY_MODE_LOOPBACK);
    RET(err != GPG_ERR_NO_ERROR, -1,
        "unable to set pinentry mode (%s | %s)",
        gpgme_strsource(err), gpgme_strerror(err));
    INFO("set gpg pinentry mode");

    /* TODO: if loopback pinentry mode, add callback registration here */

    /* set key listing mode to local */
    err = gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_LOCAL);
    RET(err != GPG_ERR_NO_ERROR, -1,
        "unable to set key listing mode (%s | %s)",
        gpgme_strsource(err), gpgme_strerror(err));
    INFO("gpgme key listing mode set to local");

    /* retrive private key with given id & check validity */
    err = gpgme_get_key(ctx, _kfp, &key, 1);
    RET(err != GPG_ERR_NO_ERROR, -1,
        "unable to retrieve key with given fingerprint (%s | %s)",
        gpgme_strsource(err), gpgme_strerror(err));
    INFO("selected gpg key %s belonging to %s <%s>",
         key->subkeys->keyid,
         key->uids ? key->uids->name  : "(null)",
         key->uids ? key->uids->email : "(null)");

    RET(key->revoked,   -1, "retrieved key was revoked");
    RET(key->expired,   -1, "retrieved key has expired");
    RET(key->disabled,  -1, "retrieved key was disabled");
    RET(key->invalid,   -1, "retrieved key is invalid");
    RET(!key->can_sign, -1, "retrieved key can not sign");

    /* clear any previous signer from context                       *
     * NOTE: since the context is new, this should not be necessary */
    gpgme_signers_clear(ctx);
    INFO("cleared all signers from gpgme context");

    /* add retrieved key as signer */
    err = gpgme_signers_add(ctx, key);
    RET(err != GPG_ERR_NO_ERROR, -1,
        "unable to add retrieved key as signer to gpgme context (%s | %s)",
        gpgme_strsource(err), gpgme_strerror(err));
    INFO("add retrieved key as signer to gpgme context");

    return 0;
}

/* gpg_fini - deinitialize gpgme
 *  @return : 0 if everything went well
 */
int32_t gpg_fini(void)
{
    /* destroy gpgme context */
    gpgme_release(ctx);
    INFO("destroyed gpgme context");

    return 0;
}


/* gpg_packet_signature - computes the packet signaure
 *  @sgn  : buffer allocated for the signature
 *  @buff : buffer containing the packet
 *  @len  : basically ip.total_length
 *
 *  @return : 0 if everything went well
 *
 * NOTE: the received packet must already have space allocated in the
 *       options section
 * NOTE: this generated a _very_ dumb signature
 *       this is only for testing
 */
int32_t gpg_packet_signature(void *sgn, void *buff, size_t len)
{
    static uint8_t      masked_pkt[0xffff]; /* masked packet buffer    */
    gpgme_data_t        gpg_data;           /* input data (the packet) */
    gpgme_data_t        gpg_sgn;            /* output signature        */
    gpgme_sign_result_t gpg_sgnres;         /* signature result        */
    gpgme_error_t       err;                /* gpgme error             */
    int32_t             retval;             /* return value            */
    ssize_t             ans;                /* answer                  */
    

    /* assume abnormal termination until signing successfully concluded */
    retval = -1;

    /* create copy of packet for masking fields                          *
     * NOTE: more efficient to create backup of l3,4 headers and restore *
     *       them after masking fields and computing signature           */
    memmove(masked_pkt, buff, len);

    /* TODO: mask mutable fields */

    /* import packet buffer into gpgme data object */
    err = gpgme_data_new_from_mem(&gpg_data, (const char *) masked_pkt, len, 0);
    RET(err != GPG_ERR_NO_ERROR, -1, 
        "unable to import packet buffer into gpgme data object (%s | %s)",
        gpgme_strsource(err), gpgme_strerror(err));

    /* allocate space in a gpgme data object for the signature */
    err = gpgme_data_new(&gpg_sgn);
    GOTO(err != GPG_ERR_NO_ERROR, clean_gpg_data_obj,
        "unable to allocate space for signature data",
        gpgme_strsource(err), gpgme_strerror(err)); 

    /* compute signature of masked packet buffer */
    err = gpgme_op_sign(ctx, gpg_data, gpg_sgn, GPGME_SIG_MODE_DETACH);
    GOTO(err != GPG_ERR_NO_ERROR, clean_gpg_sgn_obj,
        "unable to sign plaintext data (%s | %s)",
        gpgme_strsource(err), gpgme_strerror(err));

    /* get result of previous (successful) signature and check compliance *
     * NOTE: we only have ONE signature; don't overcomplicate it          */
    gpg_sgnres = gpgme_op_sign_result(ctx);
    GOTO(!gpg_sgnres || gpg_sgnres->signatures->next, clean_gpg_sgn_obj,
        "unexpected number of created signatures");
    GOTO(gpg_sgnres->invalid_signers, clean_gpg_sgn_obj,
        "invalid signer encountered");
    GOTO(!gpg_sgnres->signatures, clean_gpg_sgn_obj,
        "no signatures created");
    GOTO(gpg_sgnres->signatures->type != GPGME_SIG_MODE_DETACH, clean_gpg_sgn_obj,
        "signature type mismatch (actual=%d)",
        gpg_sgnres->signatures->type);
    GOTO(gpg_sgnres->signatures->hash_algo != GPGME_MD_SHA256, clean_gpg_sgn_obj,
        "hash algorithm differs from SHA256 (actual=%s)",
        gpgme_hash_algo_name(gpg_sgnres->signatures->hash_algo));
    /* TODO: add singer fingerprint match check */

    /* copy signature from gpgme object to native buffer *
     * NOTE: must rewind cursor first                    */
    gpgme_data_seek(gpg_sgn, 0, SEEK_SET);
    ans = gpgme_data_read(gpg_sgn, sgn, SHA256_DIGEST_LENGTH);
    GOTO(ans == -1, clean_gpg_sgn_obj,
        "error getting signature from gpgme data object (%s)",
        strerror(errno));
    GOTO(ans != SHA256_DIGEST_LENGTH, clean_gpg_sgn_obj,
        "got %ld/%ld bytes of signature", ans, SHA256_DIGEST_LENGTH);

    /* signing process ended successfully */
    retval = 0;

    /* cleanup */
clean_gpg_sgn_obj:
    gpgme_data_release(gpg_sgn);

clean_gpg_data_obj:
    gpgme_data_release(gpg_data);

    return retval;
}

