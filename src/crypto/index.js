import { Ed25519VerificationKey2018 } from '@digitalbazaar/ed25519-verification-key-2018'
import EcdsaSecp256k1VerificationKey2019 from 'secp256k1-key-pair' // https://github.com/digitalbazaar/ecdsa-secp256k1-verification-key-2019

// import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020' // https://www.npmjs.com/package/@digitalbazaar/ed25519-verification-key-2020
// import { X25519KeyAgreementKey2019 } from 'x25519-key-agreement-key-2019' // see: https://github.com/digitalbazaar/x25519-key-agreement-key-2019/issues/10
// import { RsaVerificationKey2018 } from 'rsa-verification-key-2018'

// import { Ed25519KeyPair } from 'crypto-ld' // old way, replaced with 'use'
// import secp256k1 from 'secp256k1' // replace with eccrypto

import eccrypto from 'eccrypto'
import * as b39 from 'bip39'
import hdk from 'hdkey'
import { X25519KeyPair } from '@transmute/did-key-x25519' // https://github.com/transmute-industries/did-key.js/blob/master/packages/x25519/src/X25519KeyPair.ts

import { CryptoLD } from 'crypto-ld' // replaced previous...

const cryptoLd = new CryptoLD()
cryptoLd.use(Ed25519VerificationKey2018)
cryptoLd.use(EcdsaSecp256k1VerificationKey2019)

const getCompressedPublicFromPrivate = privateKeyHex =>
  eccrypto.publicKeyCreate(Buffer.from(privateKeyHex, 'hex')).toString('hex')

const getUncompressedPublicKeyFromCompressedPublicKey = compressedPublicKeyHex =>
  eccrypto
    .publicKeyConvert(Buffer.from(compressedPublicKeyHex, 'hex'), false)
    .slice(1)
    .toString('hex')

const mnemonicToKeypair = (mnemonic, hdPath) => {
  const seed = b39.mnemonicToSeed(mnemonic)
  const root = hdk.fromMasterSeed(seed)
  const addrNode = root.derive(hdPath)
  // eslint-disable-next-line
  const privateKeyHex = addrNode._privateKey.toString('hex');
  return {
    // this should be compressed.
    publicKey: getCompressedPublicFromPrivate(privateKeyHex),
    privateKey: privateKeyHex
  }
}

const createKeys = () => {
  // generate privKey
  let privKey
  do {
    const typedArray = new Uint32Array()
    privKey = window.crypto.getRandomValues(typedArray)
  } while (!eccrypto.privateKeyVerify(privKey))
  const pubKey = eccrypto.publicKeyCreate(privKey)
  return {
    publicKey: pubKey.toString('hex'),
    privateKey: privKey.toString('hex')
  }
}

const createEd25519Keys = async () => {
  const edKeyPair = await cryptoLd.generate({ type: 'Ed25519VerificationKey2018' })
  return edKeyPair
}

export const secp256k1 = {
  getCompressedPublicFromPrivate,
  getUncompressedPublicKeyFromCompressedPublicKey,
  createKeys
}

export const ed25519 = {
  createKeys: createEd25519Keys,
  X25519KeyPair
}

export const bip39 = b39

export const hdkey = hdk

export const ethereum = {
  mnemonicToKeypair
}
