/*
 * rlm_pap_pbkdf2.c
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2001  Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <ctype.h>

#ifndef WITH_OPENSSL_SHA1
#include <openssl/hmac.h> 
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#endif

#define PW_PBKDF2_PASSWORD 3001

#define PAP_PBKDF2_MAX_ALGO_LEN 20
#define PAP_PBKDF2_MAX_ITERATIONS_LEN 20
#define PAP_PBKDF2_SHA256_LEN 32

#define PAP_PBKDF2_ALGO_INVALID -1
#define PAP_PBKDF2_ALGO_SHA256 0

static const FR_NAME_NUMBER enc_algos[] = {
	{ "pbkdf2_sha256", PAP_PBKDF2_ALGO_SHA256 },
	{ NULL, PAP_PBKDF2_ALGO_INVALID }
};

#ifndef WITH_OPENSSL_SHA1

static int hash_pbkdf2_shd256(const char *password, const char *salt, size_t salt_len, int it, char *result_base64)
{
	unsigned char enc_buf[PAP_PBKDF2_SHA256_LEN];
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	/*Encrypt*/
	int res = PKCS5_PBKDF2_HMAC(
		password, strlen(password), (const unsigned char*)salt, salt_len,
		it, EVP_sha256(), PAP_PBKDF2_SHA256_LEN, enc_buf);
	
	if (res) {
		b64 = BIO_new(BIO_f_base64());
		bmem = BIO_new(BIO_s_mem());
		b64 = BIO_push(b64, bmem);
		BIO_write(b64, enc_buf, PAP_PBKDF2_SHA256_LEN);
		BIO_flush(b64);
		BIO_get_mem_ptr(b64, &bptr);
		memcpy(result_base64, bptr->data, bptr->length - 1);
		BIO_free_all(b64);
	}

	return res;
}

static int pbkdf2_check_password(REQUEST *request, VALUE_PAIR *user_password_vp, VALUE_PAIR *pbkdf2_password_vp)
{
	const char * ch;
	const char * algo = NULL;
	size_t algo_len = 0;
	const char * iterations = NULL;
	size_t iterations_len = 0;
	const char * salt = NULL;
	size_t salt_len = 0;
	const char * hashed_pass = NULL;
	size_t hashed_pass_len = 0;
	char algo_buf[PAP_PBKDF2_MAX_ALGO_LEN];
	int algo_type;
	char it_buf[PAP_PBKDF2_MAX_ITERATIONS_LEN];
	int it;
	char user_hashed_pass[MAX_STRING_LEN];

	memset(algo_buf, 0, sizeof(algo_buf));
	memset(it_buf, 0, sizeof(it_buf));
	memset(user_hashed_pass, 0, sizeof(user_hashed_pass));

	/* quiet the compiler */
	request = request;
	user_password_vp = user_password_vp;

	for (ch = pbkdf2_password_vp->vp_strvalue; *ch; ch++) {
		if (*ch == '$') {
			if (!algo) {
				algo = pbkdf2_password_vp->vp_strvalue;
				algo_len = ch - algo;
			} else if (!iterations) {
				iterations = algo + algo_len + 1;
				iterations_len = ch - iterations;
			} else if (!salt) {
				salt = iterations + iterations_len + 1;
				salt_len = ch - salt;
			}
		}
	}

	if (!algo || !iterations || !salt || 
		(algo_len > PAP_PBKDF2_MAX_ALGO_LEN) ||
		(iterations_len > PAP_PBKDF2_MAX_ITERATIONS_LEN)) {
		radlog(L_ERR, "[pap_pbkdf2] Bad PBKDF2-Password attribute: \"%s\"",
			pbkdf2_password_vp->vp_strvalue);
		return 0;
	}

	hashed_pass = salt + salt_len + 1;
	hashed_pass_len = ch - hashed_pass;

	if (!hashed_pass_len) {
		radlog(L_ERR, "[pap_pbkdf2] Bad PBKDF2-Password attribute: \"%s\"",
			pbkdf2_password_vp->vp_strvalue);
		return 0;
	}

	radlog(L_INFO, "[pap_pbkdf2] Found PBKDF2-Password: "
		           "algo: %.*s, it: %.*s, salt: %.*s, hashed_pass: %.*s",
			algo_len, algo, iterations_len, iterations, 
			salt_len, salt, hashed_pass_len, hashed_pass);

	memcpy(it_buf, iterations, iterations_len);
	it = atoi(it_buf);
	if (it == 0) {
		radlog(L_ERR, "[pap_pbkdf2] iterations has invalid value!");
		return 0;
	}

	memcpy(algo_buf, algo, algo_len);
	algo_type = fr_str2int(enc_algos, algo_buf, PAP_PBKDF2_ALGO_INVALID);
	switch (algo_type) {
	case PAP_PBKDF2_ALGO_SHA256:
		if (!hash_pbkdf2_shd256(user_password_vp->vp_strvalue, salt, salt_len, it, user_hashed_pass)) {
			radlog(L_ERR, "[pap_pbkdf2] hash_pbkdf2_shd256 failed!");
			return 0;
		}
		break;
	default:
		radlog(L_ERR, "[pap_pbkdf2] Unknown algo: \"%.*s\"", algo_len, algo);
	}

	radlog(L_INFO, "[pap_pbkdf2] Encrypted User-Password: %s", user_hashed_pass);
	if (!strncmp(user_hashed_pass, hashed_pass, hashed_pass_len))
		return 1;
	radlog(L_ERR, "[pap_pbkdf2] Password check failed");
	return 0;
}

#endif

static int pap_pbkdf2_authorize(void *instance, REQUEST *request)
{
	/* quiet the compiler */
	instance = instance;

	radlog(L_INFO, "[pap_pbkdf] authorize");

	if (!pairfind(request->config_items, PW_PBKDF2_PASSWORD)) {
		return RLM_MODULE_NOOP;
	}

	if (pairfind(request->config_items, PW_AUTHTYPE) != NULL) {
		RDEBUG2("[pap_pbkdf] WARNING: Auth-Type already set.  Not setting to PAP_PBKDF2");
		return RLM_MODULE_NOOP;
	}

	RDEBUG("[pap_pbkdf] Setting 'Auth-Type := PAP_PBKDF2'");
	pairadd(&request->config_items,
		pairmake("Auth-Type", "PAP_PBKDF2", T_OP_EQ));

	return RLM_MODULE_OK;
}

static int pap_pbkdf2_authenticate(void *instance, REQUEST *request)
{
	VALUE_PAIR *pbkdf2_password;

	/* quiet the compiler */
	instance = instance;

	radlog(L_INFO, "[pap_pbkdf2] authenticate");

	if (!request->username) {
		radlog(L_ERR, "[pap_pbkdf2] ERROR: You set 'Auth-Type = PAP_PBKDF2' "
			          "for a request that does not contain a User-Name attribute!");
		return RLM_MODULE_INVALID;
	}

	if (!request->password ||
	    (request->password->attribute != PW_USER_PASSWORD)) {
		radlog(L_ERR, "[pap_pbkdf2] ERROR: You set 'Auth-Type = PAP_PBKDF2'"
			          "for a request that does not contain a User-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	The user MUST supply a non-zero-length password.
	 */
	if (request->password->length == 0) {
		radlog(L_ERR, "[pap_pbkdf2] ERROR: You set 'Auth-Type = PAP_PBKDF2'"
			          "for a request that contains zero length User-Password attribute!");
		return RLM_MODULE_INVALID;
	}

	radlog(L_INFO, "[pap_pbkdf2] login attempt with password \"%s\"",
		request->password->vp_strvalue);

	pbkdf2_password = pairfind(request->config_items, PW_PBKDF2_PASSWORD);
	if (!pbkdf2_password) {
		radlog(L_ERR, "[pap_pbkdf2] ERROR: You set 'Auth-Type = PAP_PBKDF2'"
			          "for a config without PBKDF2-Password attribute!");
	}

#ifndef WITH_OPENSSL_SHA1

	if (!pbkdf2_check_password(request, request->password, pbkdf2_password))
		return RLM_MODULE_INVALID;

#else

	radlog(L_ERR, "[pap_pbkdf2] ERROR: You have to build radius "
		          "with WITH_OPENSSL_SHA1 to use this module!");

#endif

	return RLM_MODULE_OK;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_pap_pbkdf2 = {
	RLM_MODULE_INIT,
	"PAP_PBKDF2",
	RLM_TYPE_THREAD_UNSAFE,   	/* type */
	NULL,		/* instantiation */
	NULL,			/* detach */
	{
		pap_pbkdf2_authenticate,	/* authentication */
		pap_pbkdf2_authorize,		/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};