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
 * Foobar is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with app-fw. If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>     /* [u]int*_t */
#include <gpgme.h>      /* gpgme */
#include <termios.h>    /* tcgetattr, tcsetattr */
#include <locale.h>     /* setlocale, LC_CTYPE */
#include <unistd.h>     /* write */

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

