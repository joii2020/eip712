#!/usr/bin/env node

const fs = require('fs');
const keccak256 = require('keccak256');
const eip712 = require('eip-712');

const g_data = JSON.parse(fs.readFileSync(process.argv[2]));

let domain_hash = eip712.getStructHash(g_data, "EIP712Domain", g_data.domain);
let message_hash = eip712.getStructHash(g_data, g_data.primaryType, g_data.message);

console.log("Domain hash: 0x" + Buffer.from(domain_hash).toString("hex"));
console.log("Message hash: 0x" + Buffer.from(message_hash).toString("hex"));

let data1 = new Uint8Array([0x19, 0x01]);
let last_message = keccak256(Buffer.concat([data1, domain_hash, message_hash]));
console.log("Last message hash: 0x" + Buffer.from(last_message).toString("hex"));