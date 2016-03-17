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
  | Author:  Misko Lee   <imiskolee@gmail.com>                           |
  |                                 |
  +----------------------------------------------------------------------+
*/

#ifndef PHP_YAR_ENCRYPT_H
#define PHP_YAR_ENCRYPT_H

#include "php.h"

typedef struct {
    unsigned int body_len;
    unsigned int real_len;
    unsigned char *body;
} yar_encrypt_body_t;

void get_encrypt_key(char *key,int key_len,unsigned char *store);
yar_encrypt_body_t* yar_encrypt_body_encrypt(char *key,int key_len,char *body,int body_len);
yar_encrypt_body_decrypt(char *key,char *key_len,char *body,int body_len,char *store);
yar_encrypt_body_t* yar_encrypt_body_parse(char *body,int body_len);
void yar_encrypt_body_render(yar_encrypt_body_t *encrypt,char *body,int body_len);
#endif
