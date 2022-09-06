#include "c_std_ext.h"

#include <string.h>

int ext_strncmp(const char *s1, const char *s2, size_t len) {
  // assert(s1 != NULL && s2 != NULL);
  while (len--) {
    if (*s1 == 0 || *s1 != *s2) return *s1 - *s2;

    s1++;
    s2++;
  }
  return 0;
}

char *ext_strpbrk(const char *s1, const char *s2) {
  const char *s;
  for (; *s1; s1++) {
    for (s = s2; *s; s++) {
      if (*s == *s1) return (char *)s1;
    }
  }
  return NULL;
}

char *ext_strcat(char *dest, const char *src) {
  // assert(dest != NULL && src != NULL);
  char *temp = dest;
  while (*temp != '\0') temp++;
  while ((*temp++ = *src++) != '\0')
    ;

  return dest;
}

char *ext_strncpy(char *strDest, const char *strSrc, int num) {
  // assert((strDest != NULL) && (strSrc != NULL));
  char *strDestcopy = strDest;
  while ((num--) && (*strDest++ = *strSrc++) != '\0')
    ;
  if (num > 0) {
    while (--num) {
      *strDest++ = '\0';
    }
  }
  return strDestcopy;
}

char *ext_strtok(char *str, const char *delimit) {
  static char *tmp = NULL;
  char *ret = NULL;
  if (delimit == NULL) return str;
  if (str != NULL) tmp = str;
  if (tmp == NULL) return NULL;
  ret = tmp;
  char *p = strstr(tmp, delimit);
  if (p != NULL) {
    tmp = p + strlen(delimit);
    int i;
    for (i = 0; i < strlen(delimit); i++) {
      *(p + i) = '\0';
    }
  } else {
    tmp = NULL;
  }
  return ret;
}

char *ext_strncat(char *dest, const char *str, int n) {
  // assert((dest != NULL) && (str != NULL));
  char *cp = dest;
  while (*cp != '\0') ++cp;

  while (n && (*cp++ = *str++) != '\0') {
    --n;
  }

  return dest;
}

uint8_t char_hex_to_uint8(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 0xa;
  }

  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 0xa;
  }

  return 0;
}

uint8_t hex_to_uint8(const char *d) {
  return (char_hex_to_uint8(d[0]) << 4) + char_hex_to_uint8(d[1]);
}

uint8_t char_to_uint8(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }

  return 0xf;
}

uint32_t str_to_uint32(const char *d) {
  size_t i = 0;

  uint32_t ret = 0, r = 0;
  for (i = 0; d[i] != 0; d++) {
    r = (uint32_t)char_to_uint8(d[i]);
    if (r == 0xf) {
      break;
    }
    ret = ret * 10 + r;
  }
  return ret;
}