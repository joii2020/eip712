
/*
 * Copyright (c) 2022 markrypto  (cryptoakorn@gmail.com)
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
    Produces hashes based on the metamask v4 rules. This is different from the
   EIP-712 spec in how arrays of structs are hashed but is compatable with
   metamask. See https://github.com/MetaMask/eth-sig-util/pull/107

    eip712 data rules:
    Parser wants to see C strings, not javascript strings:
        requires all complete json message strings to be enclosed by braces,
   i.e., { ... } Cannot have entire json string quoted, i.e., "{ ... }" will not
   work. Remove all quote escape chars, e.g., {"types":  not  {\"types\": int
   values must be hex. Negative sign indicates negative value, e.g., -5, -8a67
        Note: Do not prefix ints or uints with 0x
    All hex and byte strings must be big-endian
    Byte strings and address should be prefixed by 0x
*/

#include "eip712/sim_include/keepkey/firmware/eip712_tools.h"

// #include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c_std_ext.h"
#include "eip712/sim_include/keepkey/board/confirm_sm.h"
#include "eip712/sim_include/keepkey/firmware/ethereum_tokens.h"
#include "eip712/sim_include/keepkey/firmware/tiny-json.h"
#include "eip712/sim_include/trezor/crypto/memzero.h"
#include "eip712/sim_include/trezor/crypto/sha3.h"

unsigned long
    end;  // This is at the end of the data + bss, used for recursion guard
static const char *udefList[MAX_USERDEF_TYPES] = {0};
static dm confirmProp;

static const char *nameForValue;

int memcheck() {
  // char buf[33] = {0};
  void *stackBottom;  // this is the bottom of the stack, it is shrinking toward
                      // static mem at variable "end".
  // snprintf(buf, 64, "RAM available %u", (unsigned)&stackBottom -
  // (unsigned)&end); DEBUG_DISPLAY(buf);
  if (STACK_SIZE_GUARD > ((unsigned long)&stackBottom - (unsigned long)&end)) {
    return RECURSION_ERROR;
  } else {
    return SUCCESS;
  }
}

int encodableType(const char *typeStr) {
  int ctr;

  if (0 == ext_strncmp(typeStr, "address", sizeof("address") - 1)) {
    return ADDRESS;
  }
  if (0 == ext_strncmp(typeStr, "string", sizeof("string") - 1)) {
    return STRING;
  }
  if (0 == ext_strncmp(typeStr, "int", sizeof("int") - 1)) {
    // This could be 'int8', 'int16', ..., 'int256'
    return INT;
  }
  if (0 == ext_strncmp(typeStr, "uint", sizeof("uint") - 1)) {
    // This could be 'uint8', 'uint16', ..., 'uint256'
    return UINT;
  }
  if (0 == ext_strncmp(typeStr, "bytes", sizeof("bytes") - 1)) {
    // This could be 'bytes', 'bytes1', ..., 'bytes32'
    if (0 == strcmp(typeStr, "bytes")) {
      return BYTES;
    } else {
      // parse out the length val
      uint8_t byteTypeSize = (uint8_t)str_to_uint32((typeStr + 5));
      if (byteTypeSize > 32) {
        return NOT_ENCODABLE;
      } else {
        return BYTES_N;
      }
    }
  }
  if (0 == strcmp(typeStr, "bool")) {
    return BOOL;
  }

  // See if type already defined. If so, skip, otherwise add it to list
  for (ctr = 0; ctr < MAX_USERDEF_TYPES; ctr++) {
    char typeNoArrTok[MAX_TYPESTRING] = {0};

    ext_strncpy(typeNoArrTok, typeStr, sizeof(typeNoArrTok) - 1);
    ext_strtok(typeNoArrTok, "[");  // eliminate the array tokens if there

    if (udefList[ctr] != 0) {
      if (0 == ext_strncmp(udefList[ctr], typeNoArrTok,
                           strlen(udefList[ctr]) - strlen(typeNoArrTok))) {
        return PREV_USERDEF;
      } else {
      }

    } else {
      udefList[ctr] = typeStr;
      return UDEF_TYPE;
    }
  }
  if (ctr == MAX_USERDEF_TYPES) {
    return TOO_MANY_UDEFS;
  }

  return NOT_ENCODABLE;  // not encodable
}

/*
    Entry:
            eip712Types points to eip712 json type structure to parse
            typeS points to the type to parse from jType
            typeStr points to caller allocated, zeroized string buffer of size
   STRBUFSIZE+1 Exit: typeStr points to hashable type string returns error list
   status

    NOTE: reentrant!
*/
int parseType(const json_t *eip712Types, const char *typeS, char *typeStr) {
  json_t const *tarray, *pairs;
  const json_t *jType;
  char append[STRBUFSIZE + 1] = {0};
  int encTest;
  const char *typeType = NULL;
  int errRet = SUCCESS;
  const json_t *obTest;
  const char *nameTest;
  const char *pVal;

  if (NULL == (jType = json_getProperty(eip712Types, typeS))) {
    errRet = JSON_TYPE_S_ERR;
    return errRet;
  }

  if (NULL == (nameTest = json_getName(jType))) {
    errRet = JSON_TYPE_S_NAMEERR;
    return errRet;
  }

  ext_strncat(typeStr, nameTest, STRBUFSIZE - strlen((const char *)typeStr));
  ext_strncat(typeStr, "(", STRBUFSIZE - strlen((const char *)typeStr));

  tarray = json_getChild(jType);
  while (tarray != 0) {
    if (NULL == (pairs = json_getChild(tarray))) {
      errRet = JSON_NO_PAIRS;
      return errRet;
    }
    // should be type JSON_TEXT
    if (pairs->type != JSON_TEXT) {
      errRet = JSON_PAIRS_NOTEXT;
      return errRet;
    } else {
      if (NULL == (obTest = json_getSibling(pairs))) {
        errRet = JSON_NO_PAIRS_SIB;
        return errRet;
      }
      typeType = json_getValue(obTest);
      encTest = encodableType(typeType);
      if (encTest == UDEF_TYPE) {
        // This is a user-defined type, parse it and append later
        if (']' == typeType[strlen(typeType) - 1]) {
          // array of structs. To parse name, remove array tokens.
          char typeNoArrTok[MAX_TYPESTRING] = {0};
          ext_strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok) - 1);
          if (strlen(typeNoArrTok) < strlen(typeType)) {
            return UDEF_NAME_ERROR;
          }

          ext_strtok(typeNoArrTok, "[");
          if (SUCCESS != (errRet = memcheck())) {
            return errRet;
          }
          if (SUCCESS !=
              (errRet = parseType(eip712Types, typeNoArrTok, append))) {
            return errRet;
          }
        } else {
          if (SUCCESS != (errRet = memcheck())) {
            return errRet;
          }
          if (SUCCESS != (errRet = parseType(eip712Types, typeType, append))) {
            return errRet;
          }
        }
      } else if (encTest == TOO_MANY_UDEFS) {
        return UDEFS_OVERFLOW;
      } else if (encTest == NOT_ENCODABLE) {
        return TYPE_NOT_ENCODABLE;
      }

      if (NULL == (pVal = json_getValue(pairs))) {
        errRet = JSON_NOPAIRVAL;
        return errRet;
      }
      ext_strncat(typeStr, typeType, STRBUFSIZE - strlen((const char *)typeStr));
      ext_strncat(typeStr, " ", STRBUFSIZE - strlen((const char *)typeStr));
      ext_strncat(typeStr, pVal, STRBUFSIZE - strlen((const char *)typeStr));
      ext_strncat(typeStr, ",", STRBUFSIZE - strlen((const char *)typeStr));
    }
    tarray = json_getSibling(tarray);
  }
  // typeStr ends with a ',' unless there are no parameters to the type.
  if (typeStr[strlen(typeStr) - 1] == ',') {
    // replace last comma with a paren
    typeStr[strlen(typeStr) - 1] = ')';
  } else {
    // append paren, there are no parameters
    ext_strncat(typeStr, ")", STRBUFSIZE - 1);
  }
  if (strlen(append) > 0) {
    ext_strncat(typeStr, append, STRBUFSIZE - strlen((const char *)append));
  }

  return SUCCESS;
}

int encAddress(const char *string, uint8_t *encoded) {
  unsigned ctr;
  char byteStrBuf[3] = {0};

  if (string == NULL) {
    return ADDR_STRING_NULL;
  }
  if (ADDRESS_SIZE < strlen(string)) {
    return ADDR_STRING_VFLOW;
  }

  for (ctr = 0; ctr < 12; ctr++) {
    encoded[ctr] = '\0';
  }
  for (ctr = 12; ctr < 32; ctr++) {
    ext_strncpy(byteStrBuf, &string[2 * ((ctr - 12)) + 2], 2);
    encoded[ctr] = hex_to_uint8(byteStrBuf);
  }
  return SUCCESS;
}

int encString(const char *string, uint8_t *encoded) {
  struct SHA3_CTX strCtx;

  sha3_256_Init(&strCtx);
  sha3_Update(&strCtx, (const unsigned char *)string, (size_t)strlen(string));
  keccak_Final(&strCtx, encoded);
  return SUCCESS;
}

int encodeBytes(const char *string, uint8_t *encoded) {
  struct SHA3_CTX byteCtx;
  const char *valStrPtr = string + 2;
  uint8_t valByte[1];
  char byteStrBuf[3] = {0};

  sha3_256_Init(&byteCtx);
  while (*valStrPtr != '\0') {
    ext_strncpy(byteStrBuf, valStrPtr, 2);
    valByte[0] = hex_to_uint8(byteStrBuf);
    sha3_Update(&byteCtx, (const unsigned char *)valByte,
                (size_t)sizeof(uint8_t));
    valStrPtr += 2;
  }
  keccak_Final(&byteCtx, encoded);
  return SUCCESS;
}

int encodeBytesN(const char *typeT, const char *string, uint8_t *encoded) {
  char byteStrBuf[3] = {0};
  unsigned ctr;

  if (MAX_ENCBYTEN_SIZE < strlen(string)) {
    return BYTESN_STRING_ERROR;
  }

  // parse out the length val
  uint8_t byteTypeSize = (uint8_t)(str_to_uint32((typeT + 5)));
  if (32 < byteTypeSize) {
    return BYTESN_SIZE_ERROR;
  }
  for (ctr = 0; ctr < 32; ctr++) {
    // zero padding
    encoded[ctr] = 0;
  }
  unsigned zeroFillLen = 32 - ((strlen(string) - 2 /* skip '0x' */) / 2);
  // bytesN are zero padded on the right
  for (ctr = zeroFillLen; ctr < 32; ctr++) {
    ext_strncpy(byteStrBuf, &string[2 + 2 * (ctr - zeroFillLen)], 2);
    encoded[ctr - zeroFillLen] = hex_to_uint8(byteStrBuf);
  }
  return SUCCESS;
}

int confirmName(const char *name, bool valAvailable) {
  if (valAvailable) {
    nameForValue = name;
  }
  return SUCCESS;
}

int confirmValue(const char *value) { return SUCCESS; }

int dsConfirm(const char *value) {
  static const char *name = NULL, *version = NULL, *chainId = NULL,
                    *verifyingContract = NULL;

  if (0 == ext_strncmp(nameForValue, "name", sizeof("name"))) {
    name = value;
  }
  if (0 == ext_strncmp(nameForValue, "version", sizeof("version"))) {
    version = value;
  }
  if (0 == ext_strncmp(nameForValue, "chainId", sizeof("chainId"))) {
    chainId = value;
  }
  if (0 == ext_strncmp(nameForValue, "verifyingContract",
                       sizeof("verifyingContract"))) {
    verifyingContract = value;
  }

  if (name != NULL && version != NULL && chainId != NULL &&
      verifyingContract != NULL) {
    // First check if we recognize the contract
    const TokenType *assetToken;
    uint8_t addrHexStr[20];
    uint32_t chainInt;
    int ctr;
    IconType iconNum = NO_ICON;
    char title[33] = {0};
    char chainStr[33];

    for (ctr = 2; ctr < 42; ctr += 2) {
      addrHexStr[(ctr - 2) / 2] = hex_to_uint8(&verifyingContract[ctr]);
  
    }
    chainInt = str_to_uint32(chainId);

    // As more chains are supported, add icon choice below
    if (chainInt == 1) {
      iconNum = ETHEREUM_ICON;
    }

    assetToken = tokenByChainAddress(chainInt, (uint8_t *)addrHexStr);
    if (ext_strncmp(assetToken->ticker, " UNKN", 5) == 0) {
    } else {
    }
    ext_strncpy(title, name, 20);
    ext_strncat(title, " version ", 32 - strlen(title));
    ext_strncat(title, version, 32 - strlen(title));
    if (iconNum == NO_ICON) {
      // snprintf(chainStr, 32, "chain %s,  ", chainId);

      memcpy(chainStr, "chain ", 6);
      memcpy(chainStr + 6, chainId, strlen(chainId));
    }
    name = NULL;
    version = NULL;
    chainId = NULL;
    verifyingContract = NULL;
  }
  return SUCCESS;
}

/*
    Entry:
            eip712Types points to the eip712 types structure
            jType points to eip712 json type structure to parse
            nextVal points to the next value to encode
            msgCtx points to caller allocated hash context to hash encoded
   values into. Exit: msgCtx points to current final hash context returns error
   status

    NOTE: reentrant!
*/
int parseVals(const json_t *eip712Types, const json_t *jType,
              const json_t *nextVal, struct SHA3_CTX *msgCtx) {
  json_t const *tarray, *pairs, *walkVals, *obTest;
  int ctr;
  const char *typeName = NULL, *typeType = NULL;
  uint8_t encBytes[32] = {0};  // holds the encrypted bytes for the message
  const char *valStr = NULL;
  char byteStrBuf[3] = {0};
  struct SHA3_CTX valCtx = {0};  // local hash context
  bool hasValue = 0;
  bool ds_vals = 0;  // domain sep values are confirmed on a single screen
  int errRet = SUCCESS;

  if (0 == ext_strncmp(json_getName(jType), "EIP712Domain",
                       sizeof("EIP712Domain"))) {
    ds_vals = true;
  }

  tarray = json_getChild(jType);

  while (tarray != 0) {
    if (NULL == (pairs = json_getChild(tarray))) {
      errRet = JSON_NO_PAIRS;
      return errRet;
    }
    // should be type JSON_TEXT
    if (pairs->type != JSON_TEXT) {
      errRet = JSON_PAIRS_NOTEXT;
      return errRet;
    } else {
      if (NULL == (typeName = json_getValue(pairs))) {
        errRet = JSON_NOPAIRNAME;
        return errRet;
      }
      if (NULL == (obTest = json_getSibling(pairs))) {
        errRet = JSON_NO_PAIRS_SIB;
        return errRet;
      }
      if (NULL == (typeType = json_getValue(obTest))) {
        errRet = JSON_TYPE_T_NOVAL;
        return errRet;
      }
      walkVals = nextVal;
      while (0 != walkVals) {
        if (0 == strcmp(json_getName(walkVals), typeName)) {
          valStr = json_getValue(walkVals);
          break;
        } else {
          // keep looking for val
          walkVals = json_getSibling(walkVals);
        }
      }

      if (JSON_TEXT == json_getType(walkVals) ||
          JSON_INTEGER == json_getType(walkVals)) {
        hasValue = 1;
      } else {
        hasValue = 0;
      }
      confirmName(typeName, hasValue);

      if (walkVals == 0) {
        errRet = JSON_TYPE_WNOVAL;
        return errRet;
      } else {
        if (0 == ext_strncmp("address", typeType, strlen("address") - 1)) {
          if (']' == typeType[strlen(typeType) - 1]) {
            // array of addresses
            json_t const *addrVals = json_getChild(walkVals);
            sha3_256_Init(&valCtx);  // hash of concatenated encoded strings
            while (0 != addrVals) {
              // just walk the string values assuming, for fixed sizes, all
              // values are there.
              if (ds_vals) {
                dsConfirm(json_getValue(addrVals));
              } else {
                confirmValue(json_getValue(addrVals));
              }

              errRet = encAddress(json_getValue(addrVals), encBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }
              sha3_Update(&valCtx, (const unsigned char *)encBytes, 32);
              addrVals = json_getSibling(addrVals);
            }
            keccak_Final(&valCtx, encBytes);
          } else {
            if (ds_vals) {
              dsConfirm(valStr);
            } else {
              confirmValue(valStr);
            }
            errRet = encAddress(valStr, encBytes);
            if (SUCCESS != errRet) {
              return errRet;
            }
          }

        } else if (0 == ext_strncmp("string", typeType, strlen("string") - 1)) {
          if (']' == typeType[strlen(typeType) - 1]) {
            // array of strings
            json_t const *stringVals = json_getChild(walkVals);
            uint8_t strEncBytes[32];
            sha3_256_Init(&valCtx);  // hash of concatenated encoded strings
            while (0 != stringVals) {
              // just walk the string values assuming, for fixed sizes, all
              // values are there.
              if (ds_vals) {
                dsConfirm(json_getValue(stringVals));
              } else {
                confirmValue(json_getValue(stringVals));
              }
              errRet = encString(json_getValue(stringVals), strEncBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }
              sha3_Update(&valCtx, (const unsigned char *)strEncBytes, 32);
              stringVals = json_getSibling(stringVals);
            }
            keccak_Final(&valCtx, encBytes);
          } else {
            if (ds_vals) {
              dsConfirm(valStr);
            } else {
              confirmValue(valStr);
            }
            errRet = encString(valStr, encBytes);
            if (SUCCESS != errRet) {
              return errRet;
            }
          }

        } else if ((0 == ext_strncmp("uint", typeType, strlen("uint") - 1)) ||
                   (0 == ext_strncmp("int", typeType, strlen("int") - 1))) {
          if (']' == typeType[strlen(typeType) - 1]) {
            return INT_ARRAY_ERROR;
          } else {
            if (ds_vals) {
              dsConfirm(valStr);
            } else {
              confirmValue(valStr);
            }
            uint8_t negInt = 0;  // 0 is positive, 1 is negative
            if (0 == ext_strncmp("int", typeType, strlen("int") - 1)) {
              if (*valStr == '-') {
                negInt = 1;
              }
            }
            // parse out the length val
            for (ctr = 0; ctr < 32; ctr++) {
              if (negInt) {
                // sign extend negative values
                encBytes[ctr] = 0xFF;
              } else {
                // zero padding for positive
                encBytes[ctr] = 0;
              }
            }
            unsigned zeroFillLen = 32 - ((strlen(valStr) - negInt) / 2 + 1);
            for (ctr = zeroFillLen; ctr < 32; ctr++) {
              ext_strncpy(byteStrBuf, &valStr[2 * (ctr - (zeroFillLen))], 2);
              encBytes[ctr] = hex_to_uint8(byteStrBuf);
            }
          }

        } else if (0 == ext_strncmp("bytes", typeType, strlen("bytes"))) {
          if (']' == typeType[strlen(typeType) - 1]) {
            return BYTESN_ARRAY_ERROR;
          } else {
            // This could be 'bytes', 'bytes1', ..., 'bytes32'
            if (ds_vals) {
              dsConfirm(valStr);
            } else {
              confirmValue(valStr);
            }
            if (0 == strcmp(typeType, "bytes")) {
              errRet = encodeBytes(valStr, encBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }

            } else {
              errRet = encodeBytesN(typeType, valStr, encBytes);
              if (SUCCESS != errRet) {
                return errRet;
              }
            }
          }

        } else if (0 == ext_strncmp("bool", typeType, strlen(typeType))) {
          if (']' == typeType[strlen(typeType) - 1]) {
            return BOOL_ARRAY_ERROR;
          } else {
            if (ds_vals) {
              dsConfirm(valStr);
            } else {
              confirmValue(valStr);
            }
            for (ctr = 0; ctr < 32; ctr++) {
              // leading zeros in bool
              encBytes[ctr] = 0;
            }
            if (0 == ext_strncmp(valStr, "true", sizeof("true"))) {
              encBytes[31] = 0x01;
            }
          }

        } else {
          // encode user defined type
          char encSubTypeStr[STRBUFSIZE + 1] = {0};
          // clear out the user-defined types list
          for (ctr = 0; ctr < MAX_USERDEF_TYPES; ctr++) {
            udefList[ctr] = NULL;
          }

          char typeNoArrTok[MAX_TYPESTRING] = {0};
          // need to get typehash of type first
          if (']' == typeType[strlen(typeType) - 1]) {
            // array of structs. To parse name, remove array tokens.
            ext_strncpy(typeNoArrTok, typeType, sizeof(typeNoArrTok) - 1);
            if (strlen(typeNoArrTok) < strlen(typeType)) {
              return UDEF_ARRAY_NAME_ERR;
            }
            ext_strtok(typeNoArrTok, "[");
            if (SUCCESS != (errRet = memcheck())) {
              return errRet;
            }
            if (SUCCESS != (errRet = parseType(eip712Types, typeNoArrTok,
                                               encSubTypeStr))) {
              return errRet;
            }
          } else {
            if (SUCCESS != (errRet = memcheck())) {
              return errRet;
            }
            if (SUCCESS !=
                (errRet = parseType(eip712Types, typeType, encSubTypeStr))) {
              return errRet;
            }
          }
          sha3_256_Init(&valCtx);
          sha3_Update(&valCtx, (const unsigned char *)encSubTypeStr,
                      (size_t)strlen(encSubTypeStr));
          keccak_Final(&valCtx, encBytes);

          if (']' == typeType[strlen(typeType) - 1]) {
            // array of udefs
            struct SHA3_CTX eleCtx = {0};  // local hash context
            struct SHA3_CTX arrCtx = {0};  // array elements hash context
            uint8_t eleHashBytes[32];

            sha3_256_Init(&arrCtx);

            json_t const *udefVals = json_getChild(walkVals);
            while (0 != udefVals) {
              sha3_256_Init(&eleCtx);
              sha3_Update(&eleCtx, (const unsigned char *)encBytes, 32);
              if (SUCCESS != (errRet = memcheck())) {
                return errRet;
              }
              if (SUCCESS !=
                  (errRet = parseVals(
                       eip712Types,
                       json_getProperty(eip712Types,
                                        ext_strtok(typeNoArrTok, "]")),
                       json_getChild(udefVals),  // where to get the values
                       &eleCtx  // encode hash happens in parse, this is the
                                // return
                       ))) {
                return errRet;
              }
              keccak_Final(&eleCtx, eleHashBytes);
              sha3_Update(&arrCtx, (const unsigned char *)eleHashBytes, 32);
              // just walk the udef values assuming, for fixed sizes, all values
              // are there.
              udefVals = json_getSibling(udefVals);
            }
            keccak_Final(&arrCtx, encBytes);

          } else {
            sha3_256_Init(&valCtx);
            sha3_Update(&valCtx, (const unsigned char *)encBytes,
                        (size_t)sizeof(encBytes));
            if (SUCCESS != (errRet = memcheck())) {
              return errRet;
            }
            if (SUCCESS !=
                (errRet = parseVals(
                     eip712Types, json_getProperty(eip712Types, typeType),
                     json_getChild(walkVals),  // where to get the values
                     &valCtx  // val hash happens in parse, this is the return
                     ))) {
              return errRet;
            }
            keccak_Final(&valCtx, encBytes);
          }
        }
      }

      // hash encoded bytes to final context
      sha3_Update(msgCtx, (const unsigned char *)encBytes, 32);
    }
    tarray = json_getSibling(tarray);
  }
  return SUCCESS;
}

int encode(const json_t *jsonTypes, const json_t *jsonVals, const char *typeS,
           uint8_t *hashRet) {
  int ctr;
  char encTypeStr[STRBUFSIZE + 1] = {0};
  uint8_t typeHash[32];
  struct SHA3_CTX finalCtx = {0};
  int errRet;
  json_t const *typesProp;
  json_t const *typeSprop;
  json_t const *domainOrMessageProp;
  json_t const *valsProp;
  char *domOrMsgStr = NULL;

  // clear out the user-defined types list
  for (ctr = 0; ctr < MAX_USERDEF_TYPES; ctr++) {
    udefList[ctr] = NULL;
  }
  if (NULL == (typesProp = json_getProperty(jsonTypes, "types"))) {
    errRet = JSON_TYPESPROPERR;
    return errRet;
  }
  if (SUCCESS != (errRet = parseType(typesProp, typeS, encTypeStr))) {
    return errRet;
  }

  sha3_256_Init(&finalCtx);
  sha3_Update(&finalCtx, (const unsigned char *)encTypeStr,
              (size_t)strlen(encTypeStr));
  keccak_Final(&finalCtx, typeHash);

  // They typehash must be the first message of the final hash, this is the
  // start
  sha3_256_Init(&finalCtx);
  sha3_Update(&finalCtx, (const unsigned char *)typeHash,
              (size_t)sizeof(typeHash));

  if (NULL == (typeSprop = json_getProperty(
                   typesProp, typeS))) {  // e.g., typeS = "EIP712Domain"
    errRet = JSON_TYPESPROPERR;
    return errRet;
  }

  if (0 == ext_strncmp(typeS, "EIP712Domain", sizeof("EIP712Domain"))) {
    confirmProp = DOMAIN;
    domOrMsgStr = "domain";
  } else {
    // This is the message value encoding
    confirmProp = MESSAGE;
    domOrMsgStr = "message";
  }
  if (NULL == (domainOrMessageProp = json_getProperty(
                   jsonVals, domOrMsgStr))) {  // "message" or "domain" property
    if (confirmProp == DOMAIN) {
      errRet = JSON_DPROPERR;
    } else {
      errRet = JSON_MPROPERR;
    }
    return errRet;
  }
  if (NULL ==
      (valsProp = json_getChild(
           domainOrMessageProp))) {  // "message" or "domain" property values
    if (confirmProp == MESSAGE) {
      errRet = NULL_MSG_HASH;  // this is legal, not an error.
      return errRet;
    }
  }

  if (SUCCESS !=
      (errRet = parseVals(typesProp, typeSprop, valsProp, &finalCtx))) {
    return errRet;
  }

  keccak_Final(&finalCtx, hashRet);
  // clear typeStr
  memzero(encTypeStr, sizeof(encTypeStr));

  return SUCCESS;
}

//////////////////////////////////////////////////////

e_mem gen_mem(uint8_t *buffer, size_t len) {
  e_mem m;
  m.buffer = buffer;
  m.buffer_len = len;
  m.pos = 0;
  return m;
}

void *e_alloc(e_mem *mem, size_t len) {
  if (mem->buffer_len < len + mem->pos) {
    // assert(false);
  }

  void *ret = mem->buffer + mem->pos;
  mem->pos += len;

  memset(ret, 0, len);

  return ret;
}

e_item *gen_item_struct(e_mem *mem, e_item *parent, const char *key,
                        e_item *item) {
  e_item *it = e_alloc(mem, sizeof(e_item));
  it->key = key;
  it->type = ETYPE_STRUCT;
  it->value.data_struct = item;

  append_item(parent, it);
  return it;
}

void append_item(e_item *parent, e_item *child) {
  if (!parent) return;
  // assert(parent->type == ETYPE_STRUCT || parent->type == ETYPE_ARRAY);
  if (!parent->value.data_struct) {
    parent->value.data_struct = child;
  } else {
    e_item *it = parent->value.data_struct;
    while (true) {
      if (!it->sibling) {
        it->sibling = child;
        break;
      }
      it = it->sibling;
    }
  }
}

e_item *gen_item_string(e_mem *mem, e_item *parent, const char *key,
                        const char *val) {
  e_item *it = e_alloc(mem, sizeof(e_item));
  it->key = key;
  it->type = ETYPE_STRING;
  it->value.data_string = val;

  append_item(parent, it);
  return it;
}

e_item *gen_item_array(e_mem *mem, e_item *parent, const char *key) {
  e_item *it = e_alloc(mem, sizeof(e_item));
  it->key = key;
  it->type = ETYPE_ARRAY;

  append_item(parent, it);
  return it;
}

void output_item(e_item *it) {
  printf("{");
  if (it) {
    it = it->value.data_struct;
    while (it) {
      if (it->key) printf("\"%s\": ", it->key);

      if (it->type == ETYPE_STRING) {
        printf("\"%s\"", it->value.data_string);
      }
      if (it->type == ETYPE_STRUCT) {
        printf("\n");
        output_item(it);
      }
      if (it->type == ETYPE_ARRAY) {
        printf("[\n");
        e_item *itt = it->value.data_struct;
        while (itt) {
          output_item(itt);
          if (itt->sibling) printf(",\n");
          itt = itt->sibling;
        }
        printf("]\n");
      }
      if (it->sibling) printf(",\n");
      it = it->sibling;
    }
  }
  printf("}\n");
}

int encode_2(e_item *data, uint8_t *hashRet) { return 1; }