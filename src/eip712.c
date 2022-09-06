#include "eip712.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c_std_ext.h"
#include "eip712/sim_include/keepkey/board/confirm_sm.h"
#include "eip712/sim_include/keepkey/firmware/eip712_tools.h"
#include "eip712/sim_include/keepkey/firmware/tiny-json.h"
#include "eip712/sim_include/trezor/crypto/sha3.h"

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

  if (0 != ext_strncmp(name, "\"primaryType\"", strlen(name))) {
    brackLevel = 1;
    brack = strstr(secStart, "{");
    while (brackLevel > 0) {
      brackTest = ext_strpbrk(brack + 1, "{}");
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
    ext_strcat(parsedJson, "{\0");
    ext_strncpy(&parsedJson[strlen(parsedJson)], secStart, parsedSize);
    ext_strcat(parsedJson, "}\0");

  } else {
    // primary type parsing is different
    typeEnd = ext_strpbrk(secStart, ",\n");
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

    ext_strcat(parsedJson, "{\0");
    ext_strncpy(&parsedJson[strlen(parsedJson)], secStart, parsedSize);
    if (parsedJson[parsedSize] == ',') {
      parsedJson[parsedSize - 1] = 0;
    }
    ext_strcat(parsedJson, "}\0");
  }
  return 1;
}

e_item *gen_eip712_data_types(e_mem *mem, e_item *root) {
  e_item *d_types = gen_item_struct(mem, root, "types", NULL);

  e_item *domain = gen_item_array(mem, d_types, "EIP712Domain");

  e_item *it = NULL;

  it = gen_item_struct(mem, domain, NULL, NULL);
  gen_item_string(mem, it, "name", "chainId");
  gen_item_string(mem, it, "type", "uint256");

  it = gen_item_struct(mem, domain, NULL, NULL);
  gen_item_string(mem, it, "name", "name");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, domain, NULL, NULL);
  gen_item_string(mem, it, "name", "verifyingContract");
  gen_item_string(mem, it, "type", "address");

  it = gen_item_struct(mem, domain, NULL, NULL);
  gen_item_string(mem, it, "name", "version");
  gen_item_string(mem, it, "type", "string");

  e_item *action = gen_item_array(mem, d_types, "Action");
  it = gen_item_struct(mem, action, NULL, NULL);
  gen_item_string(mem, it, "name", "action");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, action, NULL, NULL);
  gen_item_string(mem, it, "name", "params");
  gen_item_string(mem, it, "type", "string");

  e_item *cell = gen_item_array(mem, d_types, "Cell");
  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "capacity");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "lock");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "type");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "data");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, cell, NULL, NULL);
  gen_item_string(mem, it, "name", "extraData");
  gen_item_string(mem, it, "type", "string");

  e_item *tran = gen_item_array(mem, d_types, "Transaction");
  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "DAS_MESSAGE");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "inputsCapacity");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "outputsCapacity");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "fee");
  gen_item_string(mem, it, "type", "string");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "action");
  gen_item_string(mem, it, "type", "Action");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "inputs");
  gen_item_string(mem, it, "type", "Cell[]");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "outputs");
  gen_item_string(mem, it, "type", "Cell[]");

  it = gen_item_struct(mem, tran, NULL, NULL);
  gen_item_string(mem, it, "name", "digest");
  gen_item_string(mem, it, "type", "bytes32");

  return d_types;
}

e_item *gen_eip712_data_domain(e_mem *mem, e_item *root) {
  e_item *d_domain = gen_item_struct(mem, root, "domain", NULL);

  gen_item_string(mem, d_domain, "chainId", "1");
  gen_item_string(mem, d_domain, "name", "da.systems");
  gen_item_string(mem, d_domain, "verifyingContract",
                  "0x0000000000000000000000000000000020210722");
  gen_item_string(mem, d_domain, "version", "1");

  return d_domain;
}

e_item *gen_eip712_data_message(e_mem *mem, e_item *root) {
  e_item *d_message = gen_item_struct(mem, root, "message", NULL);

  gen_item_string(
      mem, d_message, "DAS_MESSAGE",
      "TRANSFER FROM 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39280335 "
      "CKB) TO 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39270335 CKB)");
  gen_item_string(mem, d_message, "inputsCapacity", "551.39280335 CKB");
  gen_item_string(mem, d_message, "outputsCapacity", "551.39270335 CKB");
  gen_item_string(mem, d_message, "fee", "0.0001 CKB");
  gen_item_string(
      mem, d_message, "digest",
      "0xa71c9bf1cb1686b35a6c2ee4593202bc13279aae96e6ea274d919444f1e3749f");

  e_item *action = gen_item_struct(mem, d_message, "action", NULL);
  gen_item_string(mem, action, "action", "withdraw_from_wallet");
  gen_item_string(mem, action, "params", "0x00");

  gen_item_array(mem, d_message, "inputs");
  gen_item_array(mem, d_message, "outputs");

  return d_message;
}

e_item *gen_eip712_data(e_mem *mem) {
  e_item *root = gen_item_struct(mem, NULL, "", NULL);

  gen_eip712_data_types(mem, root);
  gen_item_string(mem, root, "primaryType", "Transaction");
  gen_eip712_data_domain(mem, root);
  gen_eip712_data_message(mem, root);

  return root;
}

int test_eip712_2() {
  uint8_t buffer[1024 * 8];
  e_mem mem = gen_mem(buffer, sizeof(buffer));

  e_item *root = gen_eip712_data(&mem);

  output_item(root);

  uint8_t ret_hash[32] = {0};
  return encode_2(root, ret_hash);
}

int test_eip712() {
  // clang-format off
  static char json_data[] = "{\"types\":{\"EIP712Domain\":[{\"name\":\"chainId\",\"type\":\"uint256\"},{\"name\":\"name\",\"type\":\"string\"},{\"name\":\"verifyingContract\",\"type\":\"address\"},{\"name\":\"version\",\"type\":\"string\"}],\"Action\":[{\"name\":\"action\",\"type\":\"string\"},{\"name\":\"params\",\"type\":\"string\"}],\"Cell\":[{\"name\":\"capacity\",\"type\":\"string\"},{\"name\":\"lock\",\"type\":\"string\"},{\"name\":\"type\",\"type\":\"string\"},{\"name\":\"data\",\"type\":\"string\"},{\"name\":\"extraData\",\"type\":\"string\"}],\"Transaction\":[{\"name\":\"DAS_MESSAGE\",\"type\":\"string\"},{\"name\":\"inputsCapacity\",\"type\":\"string\"},{\"name\":\"outputsCapacity\",\"type\":\"string\"},{\"name\":\"fee\",\"type\":\"string\"},{\"name\":\"action\",\"type\":\"Action\"},{\"name\":\"inputs\",\"type\":\"Cell[]\"},{\"name\":\"outputs\",\"type\":\"Cell[]\"},{\"name\":\"digest\",\"type\":\"bytes32\"}]},\"primaryType\":\"Transaction\",\"domain\":{\"chainId\":\"1\",\"name\":\"da.systems\",\"verifyingContract\":\"0x0000000000000000000000000000000020210722\",\"version\":\"1\"},\"message\":{\"DAS_MESSAGE\":\"TRANSFER FROM 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39280335 CKB) TO 0x9176acd39a3a9ae99dcb3922757f8af4f94cdf3c(551.39270335 CKB)\",\"inputsCapacity\":\"551.39280335 CKB\",\"outputsCapacity\":\"551.39270335 CKB\",\"fee\":\"0.0001 CKB\",\"digest\":\"0xa71c9bf1cb1686b35a6c2ee4593202bc13279aae96e6ea274d919444f1e3749f\",\"action\":{\"action\":\"withdraw_from_wallet\",\"params\":\"0x00\"},\"inputs\":[],\"outputs\":[]}}";
  // clang-format on

  json_t const *json;
  json_t const *jsonT;
  json_t const *jsonV;
  json_t const *jsonPT;

  static char jsonStr[BUFSIZE] = {'\0'};
  static char typesJsonStr[TYPES_BUFSIZE] = {'\0'};
  static char primaryTypeJsonStr[PRIMETYPE_BUFSIZE] = {'\0'};
  static char domainJsonStr[DOMAIN_BUFSIZE] = {'\0'};
  static char messageJsonStr[MESSAGE_BUFSIZE] = {'\0'};

  memcpy(jsonStr, json_data, sizeof(json_data));

  // parse out the 4 sections
  parseJsonName("\"types\"", jsonStr, typesJsonStr, TYPES_BUFSIZE);
  parseJsonName("\"domain\"", jsonStr, domainJsonStr, DOMAIN_BUFSIZE);
  parseJsonName("\"message\"", jsonStr, messageJsonStr, MESSAGE_BUFSIZE);
  parseJsonName("\"primaryType\"", jsonStr, primaryTypeJsonStr,
                MESSAGE_BUFSIZE);

  json_t mem[JSON_OBJ_POOL_SIZE];
  json = json_create(jsonStr, mem, sizeof mem / sizeof *mem);
  if (!json) {
    printf("Error json create json, errno = %d.", errno);
    return 1;
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
    return 1;
  }
  if (!jsonV) {
    printf("Error json create jsonV, errno = %d.", errno);
    return 1;
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
    return 1;
  }
  if (!jsonPT) {
    printf("Error json create jsonPT, errno = %d.", errno);
    return 1;
  }

  uint8_t msgHash[32];
  const char *primeType =
      json_getValue(json_getProperty(jsonPT, "primaryType"));

  if (0 == ext_strncmp(primeType, "EIP712Domain", strlen(primeType))) {
    printf("primary type is EIP712Domain, message hash is NULL\n");
  } else if (2 == encode(jsonT, jsonV, primeType, msgHash)) {
    printf("message hash is NULL\n");
  } else {
    DEBUG_DISPLAY_VAL("message", "hash    ", 65, msgHash[ctr]);
  }

  uint8_t buf[2 + 32 + 32] = {0};
  buf[0] = 0x19;
  buf[1] = 0x01;

  memcpy(buf + 2, domainSeparator, 32);
  memcpy(buf + 2 + 32, msgHash, 32);

  uint8_t befor_sign[32] = {0};
  keccak_256(buf, sizeof(buf), befor_sign);
  DEBUG_DISPLAY_VAL("before sign", "hash    ", 65, befor_sign[ctr]);

  return 0;
}