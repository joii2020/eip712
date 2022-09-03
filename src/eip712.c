#include "eip712.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eip712/sim_include/keepkey/board/confirm_sm.h"
#include "eip712/sim_include/keepkey/firmware/eip712.h"
#include "eip712/sim_include/keepkey/firmware/tiny-json.h"

// eip712tool specific defines
//#define DISPLAY_INTERMEDIATES 1     // define this to display intermediate
// hash results
#define BUFSIZE 4000
#define PRIMETYPE_BUFSIZE 80
#define DOMAIN_BUFSIZE 300
#define MESSAGE_BUFSIZE 2000
#define TYPES_BUFSIZE \
  2000  // This will be used as the types,values concatenated string
// Example
// DEBUG_DISPLAY_VAL("sig", "sig %s", 65, resp->signature.bytes[ctr]);

int parseJsonName(char *name, char *jsonMsg, char *parsedJson,
                  unsigned maxParsedSize) {
  char *secStart, *brack, *brackTest, *typeEnd;
  unsigned brackLevel, parsedSize;

  if (NULL == (secStart = strstr(jsonMsg, name))) {
    printf("%s not found!\n", name);
    return 0;
  }

  if (0 != strncmp(name, "\"primaryType\"", strlen(name))) {
    brackLevel = 1;
    brack = strstr(secStart, "{");
    while (brackLevel > 0) {
      brackTest = strpbrk(brack + 1, "{}");
      if ('{' == *brackTest) {
        brackLevel++;
      } else if ('}' == *brackTest) {
        brackLevel--;
      } else if (0 == brackTest) {
        printf("can't parse %s value!\n", name);
        return 0;
      }
      brack = brackTest;
    }

    parsedSize = brack - secStart + 1;
    if (parsedSize + 2 > maxParsedSize) {
      printf("parsed size is %u, larger than max allowed %u\n", parsedSize,
             maxParsedSize);
      return 0;
    }

    // json parser wants to see string json string enclosed in braces, i.e., "{
    // ... }"
    strcat(parsedJson, "{\0");
    strncpy(&parsedJson[strlen(parsedJson)], secStart, parsedSize);
    strcat(parsedJson, "}\0");

  } else {
    // primary type parsing is different
    typeEnd = strpbrk(secStart, ",\n");
    if (typeEnd == NULL) {
      printf("parsed size of primaryType is NULL!\n");
      return 0;
    }
    if (PRIMETYPE_BUFSIZE < (parsedSize = typeEnd - secStart)) {
      printf(
          "primaryType parsed size is %u, greater than max size allowed %u\n",
          parsedSize, PRIMETYPE_BUFSIZE);
      return 0;
    }
    // json parser wants to see string json string enclosed in braces, i.e., "{
    // ... }"

    strcat(parsedJson, "{\0");
    strncpy(&parsedJson[strlen(parsedJson)], secStart, parsedSize);
    if (parsedJson[parsedSize] == ',') {
      parsedJson[parsedSize - 1] = 0;
    }
    strcat(parsedJson, "}\0");
  }
  return 1;
}

int test_eip712() {
  const char *test_data_path = "/Volumes/workspack/code/eip712_c/tools/nodejs_test/data/data_dotbit.json";

  json_t const *json;
  json_t const *jsonT;
  json_t const *jsonV;
  json_t const *jsonPT;

  static char jsonStr[BUFSIZE] = {'\0'};
  static char typesJsonStr[TYPES_BUFSIZE] = {'\0'};
  static char primaryTypeJsonStr[PRIMETYPE_BUFSIZE] = {'\0'};
  static char domainJsonStr[DOMAIN_BUFSIZE] = {'\0'};
  static char messageJsonStr[MESSAGE_BUFSIZE] = {'\0'};
  int chr, ctr;
  FILE *f;

  // get file from cmd line or open default
  if (NULL == (f = fopen(test_data_path, "r"))) {
    printf(
        "USAGE: ./sim712.exe <filename>\n  Where <filename> is a properly "
        "formatted EIP-712 message.\n");
    return 0;
  }

  // read in the json file
  ctr = 0;
  chr = fgetc(f);
  while (chr != EOF && ctr < BUFSIZE - 1) {
    jsonStr[ctr++] = chr;
    chr = fgetc(f);
  }

  // parse out the 4 sections
  parseJsonName("\"types\"", jsonStr, typesJsonStr, TYPES_BUFSIZE);
  // printf("%s\n\n", typesJsonStr);
  parseJsonName("\"domain\"", jsonStr, domainJsonStr, DOMAIN_BUFSIZE);
  // printf("%s\n\n", domainJsonStr);
  parseJsonName("\"message\"", jsonStr, messageJsonStr, MESSAGE_BUFSIZE);
  // printf("%s\n\n", messageJsonStr);
  parseJsonName("\"primaryType\"", jsonStr, primaryTypeJsonStr,
                MESSAGE_BUFSIZE);
  // printf("%s\n\n", primaryTypeJsonStr);

  json_t mem[JSON_OBJ_POOL_SIZE];
  json = json_create(jsonStr, mem, sizeof mem / sizeof *mem);
  if (!json) {
    printf("Error json create json, errno = %d.", errno);
    return EXIT_FAILURE;
  }

  // encode domain separator

  json_t memTypes[JSON_OBJ_POOL_SIZE];
  json_t memVals[JSON_OBJ_POOL_SIZE];
  json_t memPType[4];
  jsonT =
      json_create(typesJsonStr, memTypes, sizeof memTypes / sizeof *memTypes);
  jsonV = json_create(domainJsonStr, memVals, sizeof memVals / sizeof *memVals);
  if (!jsonT) {
    printf("Error json create jsonT, errno = %d.", errno);
    return EXIT_FAILURE;
  }
  if (!jsonV) {
    printf("Error json create jsonV, errno = %d.", errno);
    return EXIT_FAILURE;
  }

  uint8_t domainSeparator[32];
  encode(jsonT, jsonV, "EIP712Domain", domainSeparator);
  DEBUG_DISPLAY_VAL("domainSeparator", "hash    ", 65, domainSeparator[ctr]);

  jsonV =
      json_create(messageJsonStr, memVals, sizeof memVals / sizeof *memVals);
  jsonPT = json_create(primaryTypeJsonStr, memPType,
                       sizeof memPType / sizeof *memPType);
  if (!jsonV) {
    printf("Error json create second jsonV, errno = %d.", errno);
    return EXIT_FAILURE;
  }
  if (!jsonPT) {
    printf("Error json create jsonPT, errno = %d.", errno);
    return EXIT_FAILURE;
  }

  uint8_t msgHash[32];
  const char *primeType =
      json_getValue(json_getProperty(jsonPT, "primaryType"));

  if (0 == strncmp(primeType, "EIP712Domain", strlen(primeType))) {
    printf("primary type is EIP712Domain, message hash is NULL\n");
  } else if (2 == encode(jsonT, jsonV, primeType, msgHash)) {
    printf("message hash is NULL\n");
  } else {
    DEBUG_DISPLAY_VAL("message", "hash    ", 65, msgHash[ctr]);
  }

  return 0;
}