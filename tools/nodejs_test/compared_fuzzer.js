#!/usr/bin/env node

const keccak256 = require('keccak256');
const eip712 = require('eip-712');

// console.log(Buffer.from(process.argv[2], "base64").toString());
eip712_data = JSON.parse(Buffer.from(process.argv[2], "base64").toString());

let domain_hash = eip712.getStructHash(eip712_data, "EIP712Domain", eip712_data.domain);
let message_hash = eip712.getStructHash(eip712_data, eip712_data.primaryType, eip712_data.message);

let data1 = new Uint8Array([0x19, 0x01]);
let last_message = keccak256(Buffer.concat([data1, domain_hash, message_hash])).toString("hex").toUpperCase();

if (last_message == process.argv[3]) {
  process.exit(0);
} else {
  process.exit(1);
}
