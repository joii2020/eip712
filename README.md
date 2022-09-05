# EIP-712 design documentation

* Provides C code for getting hash according to eip-712
* Provides examples
* Complete test case

## Interface

```
int get_eip712_hash(eip712_data* data, uint8_t* out_hash);
```

Get the hash according to eip-712 through the passed parameters.

* Arg1 data: Some parameters defined according to requirements.
* Arg2 out_hash: Output the generated hash, the pointer to a buffer of length 32.
* Result: If success return 0, else return non-zero.

### Struct
```
typedef struct _eip712_domain {
  uint8_t chain_id[32];
  char* name;
  uint8_t* verifying_contract;
  char* version;
} eip712_domain;

typedef struct _eip712_active {
  char* action;
  char* params;
} eip712_active;

typedef struct _eip712_data {
  eip712_domain doamin;
  eip712_active active;
  char* cell_extra_data;
  char* transaction_das_message;
} eip712_data;
```

Definition of ```eip712_data* data``` parameter


## Implement

### Modifications based on this project: [eip712tool](https://github.com/markrypt0/eip712tool)

This project is developed in C language and basically realizes all the functions of EIP-712. 
But it needs to be ported to risc-v. And because his parameter transfer uses Json, we will see if the situation is directly deleted later, and directly use the C structure to pass the parameters (In this, the ```types``` of eip-712 is determined).


### Verification

A verification file has been completed using [npm eip-712](https://www.npmjs.com/package/eip-712) that can be used later to verify that the results are correct.


### Generate eip712 data template

In requirements, the ```types``` of eip712 are fixed, and some of these items are filled with the data of the current transaction of ckb.


### Remove JSON

The parameter transmission of eip712tool uses json, but this requirement does not need to be developed with json, so it needs to be removed here.


### Test

#### A nodejs demo to generate a real EIP-712 hash
Correct the developed version as a real version of the demo:
```tools/nodejs_test/test_eip_712.js```. You can use the command: '''./tools/nodejs_test/test_eip_712.js ./tools/nodejs_test/data/data_dotbit.json'''

Output:
```
Domain hash: 0xad2ee3583cd6cfef2e2fda4f9c27bbd67b1a00408d58e4684e148fd4dc7326cf
Message hash: 0xa0096e1245f02a3563ebd75da920592ef533678e2ed5a06138c2f2cfcdb87b1f
Last message hash: 0xcce661e249e03e2e0c581e1763fa1432491863c625a4128dd966822cc5f1d2be
```

#### C testcases
Verify that the C code is executed correctly and check for memory problems, Also need to write fuzzing tests.

#### Contract Testcases
Test cases that are actually executed in the contract, use rust.
