#ifndef _SRC_C_STD_EXT_H_
#define _SRC_C_STD_EXT_H_

#include <stddef.h>
#include <stdint.h>

int ext_strncmp(const char *first, const char *last, size_t count);
char *ext_strpbrk(const char *s1, const char *s2);
char *ext_strcat(char *dest, const char *src);
char *ext_strncpy(char *strDest, const char *strSrc, int num);
char *ext_strtok(char *str, const char *delimit);
char *ext_strncat(char *dest, const char *str, int n);

uint8_t hex_to_uint8(const char *d);
uint32_t str_to_uint32(const char *d);

#endif  // _SRC_C_STD_EXT_H_