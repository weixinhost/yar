#include "php.h"
#include "ext/standard/md5.h"
#include "aes.h"
#include "yar_encrypt.h"

// store is a 128 bit
void get_encrypt_key(char *key,int key_len,unsigned char *store){

    PHP_MD5_CTX md5_ctx;
    PHP_MD5Init(&md5_ctx);
    PHP_MD5Update(&md5_ctx,(const void *)key,(size_t)key_len);
    PHP_MD5Final(store,&md5_ctx);

}

yar_encrypt_body_t* yar_encrypt_body_encrypt(char *key,int key_len,char *body,int body_len){

    char encrypt_key[16] = {0};
    get_encrypt_key(key,key_len,encrypt_key);

    int encrypt_body_len = 0;
    int step = 16;
    yar_encrypt_body_t *encrypt_body = emalloc(sizeof(yar_encrypt_body_t));
    encrypt_body->body_len = body_len + (step - (body_len % step));
    encrypt_body->body = emalloc(encrypt_body->body_len);
    memset(encrypt_body->body,0,encrypt_body->body_len);

    void *cursor = body;
    int  encrypted = 0;

    while(1){
       if(body_len - encrypted < 1){
         break;
       }

       unsigned char block[16] = {0};
       memset(block,0,16);

       if (encrypted + step > body_len) {
            memcpy(block,cursor,body_len - encrypted);
       }else {
            memcpy(block,cursor,step);
       }

       AES128_ECB_encrypt(block,encrypt_key,(char *)encrypt_body->body + encrypted);
       encrypted += step;
       cursor += step;
    }

    encrypt_body->real_len = body_len;
    return encrypt_body;

}

yar_encrypt_body_decrypt(char *key,char *key_len,char *body,int body_len,char *store){

     char encrypt_key[16] = {0};
     get_encrypt_key(key,key_len,encrypt_key);

     int decrypt_body_len = 0;
     int step = 16;

     void *cursor = body;
     int  encrypted = 0;
     cursor = body;

     while(1){
        if(body_len - encrypted < 1){
            break;
        }
        unsigned char block[16] = {0};
        memset(block,0,16);
        if (encrypted + step > body_len) {
            memcpy(block,body+encrypted,step - (body_len - encrypted));
        }else {
            memcpy(block,body+encrypted,step);
        }
         AES128_ECB_decrypt(block,encrypt_key,store+encrypted);
         encrypted += step;
     }
}