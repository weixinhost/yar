/*
  +----------------------------------------------------------------------+
  | Yar - Light, concurrent RPC framework                                |
  +----------------------------------------------------------------------+
  | Copyright (c) 2012-2013 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:  Xinchen Hui   <laruence@php.net>                            |
  |          Zhenyu  Zhang <zhangzhenyu@php.net>                         |
  +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/php_lcg.h" /* for php_combined_lcg’ */
#include "ext/standard/php_rand.h" /* for php_mt_rand */

#include "php_yar.h"
#include "yar_exception.h"
#include "yar_response.h"
#include "yar_request.h"
#include "yar_packager.h"

#include "aes.h"

yar_request_t *php_yar_request_instance(zend_string *method, zval *params, zval *options) /* {{{ */ {
	yar_request_t *request = ecalloc(1, sizeof(yar_request_t));

	if (!BG(mt_rand_is_seeded)) {
		php_mt_srand(GENERATE_SEED());
	}

	request->id = (long)php_mt_rand();

	request->method = zend_string_copy(method);
	if (params) {
		ZVAL_COPY(&request->parameters, params);
	}
	if (options) {
		ZVAL_COPY(&request->options, options);
	}

	return request;
}
/* }}} */

yar_request_t * php_yar_request_unpack(zval *body) /* {{{ */ {
	yar_request_t *req;
	zval *pzval;
	HashTable *ht;

	req = (yar_request_t *)ecalloc(sizeof(yar_request_t), 1);

	if (IS_ARRAY != Z_TYPE_P(body)) {
		return req;
	}

	ht = Z_ARRVAL_P(body);
	if ((pzval = zend_hash_str_find(ht, "i", sizeof("i") - 1)) != NULL) {
		req->id = zval_get_long(pzval);
	}

	if ((pzval = zend_hash_str_find(ht, "m", sizeof("m") - 1)) != NULL) {
		req->method = zval_get_string(pzval);
	}

	if ((pzval = zend_hash_str_find(ht, "p", sizeof("p") - 1)) != NULL) {
		if (IS_ARRAY != Z_TYPE_P(pzval)) {
			convert_to_array(pzval);
		}
		ZVAL_COPY(&req->parameters, pzval);
	}

	return req;
} /* }}} */


void wxhost_aes_encode(uint8_t *key, uint8_t *in, int in_length, uint8_t **out)
{

	int buffer_size = in_length + in_length % 16;


	uint8_t *result = calloc(sizeof(uint8_t), buffer_size);

	int i = 0;

	for(; i <= in_length; i += 16){

        AES128_ECB_encrypt(in +  i , key, result + i);
	}

	*out = result;
}

zend_string *php_yar_request_pack(yar_request_t *request, char **msg) /* {{{ */ {
	zval zreq;
	zend_string *payload;
	char *packager_name = NULL;

	/* @TODO: this is ugly, which needs options stash in request */
	if (IS_ARRAY == Z_TYPE(request->options)) {
		zval *pzval;
		if ((pzval = zend_hash_index_find(Z_ARRVAL(request->options), YAR_OPT_PACKAGER)) && IS_STRING == Z_TYPE_P(pzval)) {
			packager_name = Z_STRVAL_P(pzval);
		}
	}

	array_init(&zreq);

	add_assoc_long_ex(&zreq, ZEND_STRL("i"), request->id);
	add_assoc_str_ex(&zreq, ZEND_STRL("m"), zend_string_copy(request->method));

	if (IS_ARRAY == Z_TYPE(request->parameters)) {
		Z_TRY_ADDREF(request->parameters);
		add_assoc_zval_ex(&zreq, ZEND_STRL("p"), &request->parameters);
	} else {
		zval tmp;
		array_init(&tmp);
		add_assoc_zval_ex(&zreq, ZEND_STRL("p"), &tmp);
	}

	if (!(payload = php_yar_packager_pack(packager_name, &zreq, msg))) {
		zval_ptr_dtor(&zreq);
		return NULL;
	}

	zval_ptr_dtor(&zreq);

	FILE* fstream;
	fstream=fopen("/tmp/log3","at+");


	uint8_t *key = "d83ks93urk0987e4";
	uint8_t *in  = ZSTR_VAL(payload);
	int in_length = ZSTR_LEN(payload);

	uint8_t *out;

	wxhost_aes_encode(key, in, in_length, &out);

	fwrite(out, 1, strlen(out), fstream);
	

	//uint8_t *oo;
	//AES128_ECB_decrypt(buffer, key, oo);



  //fwrite(ZSTR_VAL(payload), 1, ZSTR_LEN(payload), fstream);

	
	fclose(fstream);

	return payload;
}
/* }}} */




void php_yar_request_destroy(yar_request_t *request) /* {{{ */ {
	if (request->method) {
		zend_string_release(request->method);
	}

	zval_ptr_dtor(&request->parameters);

	zval_ptr_dtor(&request->options);

	efree(request);
}
/* }}} */

int php_yar_request_valid(yar_request_t *req, yar_response_t *response, char **msg) /* {{{ */ {
	response->id = req->id;

	if (!req->method) {
		spprintf(msg, 0, "%s", "need specifical request method");
		return 0;
	}

	if (Z_ISUNDEF(req->parameters)) {
		spprintf(msg, 0, "%s", "need specifical request parameters");
		return 0;
	}

	return 1;
} /* }}} */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
