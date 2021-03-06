import DIDWallet from '@transmute/did-wallet'
import * as ES256K from '@transmute/es256k-jws-ts' // https://github.com/w3c-ccg/lds-jws2020
import jsonpatch from 'fast-json-patch'

import {
  encodeJson,
  signEncodedPayload,
  getDidUniqueSuffix
} from '../func/index.js'

import * as didCrypto from '../crypto/index.js'
import MnemonicKeySystem from '../crypto/MnemonicKeySystem.js'

const op = method => {
  const { didMethodName } = method.parameters

  const getDidDocumentModel = (primaryPublicKey, recoveryPublicKey) => ({
    '@context': 'https://w3id.org/did/v1',
    publicKey: [
      {
        id: '#primary',
        usage: 'signing',
        type: 'Secp256k1VerificationKey2018',
        publicKeyHex: primaryPublicKey
      },
      {
        id: '#recovery',
        usage: 'recovery',
        type: 'Secp256k1VerificationKey2018',
        publicKeyHex: recoveryPublicKey
      }
    ]
  })

  const makeSignedOperation = async (header, payload, privateKey) => {
    const encodedHeader = encodeJson(header)
    const encodedPayload = encodeJson(payload)
    const signature = await signEncodedPayload(
      encodedHeader,
      encodedPayload,
      privateKey
    )
    const operation = {
      protected: encodedHeader,
      payload: encodedPayload,
      signature
    }
    return operation
  }

  const getCreatePayload = async (didDocumentModel, primaryKey) => {
    // Create the encoded protected header.
    const header = {
      operation: 'create',
      kid: '#primary',
      alg: 'ES256K'
    }
    return await makeSignedOperation(header, didDocumentModel, primaryKey.privateKey)
  }

  const getUpdatePayload = async (
    previousOperation,
    oldDidDocument,
    newDidDocument,
    primaryPrivateKey
  ) => {
    const patches = jsonpatch.compare(oldDidDocument, newDidDocument)
    const payload = {
      didUniqueSuffix: previousOperation.didUniqueSuffix,
      previousOperationHash: previousOperation.operation.operationHash,
      patches: [
        {
          action: 'ietf-json-patch',
          patches
        }
      ]
    }
    const header = {
      operation: 'update',
      kid: `${didMethodName}:${previousOperation.didUniqueSuffix}#primary`,
      alg: 'ES256K'
    }
    return await makeSignedOperation(header, payload, primaryPrivateKey)
  }

  const getUpdatePayloadForAddingAKey = async (
    previousOperation,
    newPublicKey,
    primaryPrivateKey
  ) => {
    const payload = {
      didUniqueSuffix: previousOperation.didUniqueSuffix,
      previousOperationHash: previousOperation.operation.operationHash,
      patches: [
        {
          action: 'add-public-keys',
          publicKeys: [newPublicKey]
        }
      ]
    }
    const header = {
      operation: 'update',
      kid: `${didMethodName}:${previousOperation.didUniqueSuffix}#primary`,
      alg: 'ES256K'
    }
    return await makeSignedOperation(header, payload, primaryPrivateKey)
  }

  const getUpdatePayloadForRemovingAKey = async (
    previousOperation,
    kid,
    primaryPrivateKey
  ) => {
    const payload = {
      didUniqueSuffix: previousOperation.didUniqueSuffix,
      previousOperationHash: previousOperation.operation.operationHash,
      patches: [
        {
          action: 'remove-public-keys',
          publicKeys: [kid]
        }
      ]
    }
    const header = {
      operation: 'update',
      kid: `${didMethodName}:${previousOperation.didUniqueSuffix}#primary`,
      alg: 'ES256K'
    }
    return await makeSignedOperation(header, payload, primaryPrivateKey)
  }

  const getRecoverPayload = async (
    didUniqueSuffix,
    newDidDocument,
    recoveryPrivateKey
  ) => {
    const payload = {
      didUniqueSuffix,
      newDidDocument
    }
    const header = {
      operation: 'recover',
      kid: `${didMethodName}:${didUniqueSuffix}#recovery`,
      alg: 'ES256K'
    }
    return await makeSignedOperation(header, payload, recoveryPrivateKey)
  }

  const getDeletePayload = async (didUniqueSuffix, recoveryPrivateKey) => {
    const header = {
      operation: 'delete',
      kid: `${didMethodName}:${didUniqueSuffix}#recovery`,
      alg: 'ES256K'
    }
    const payload = { didUniqueSuffix }
    return await makeSignedOperation(header, payload, recoveryPrivateKey)
  }

  const walletToInitialDIDDoc = wallet => {
    const didDocumentModel = {
      '@context': [
        'https://www.w3.org/ns/did/v1'
      ]
    }

    const publicKeys = []
    const commonVerificationMethods = []
    const keyAgreementkeys = []

    Object.values(wallet.keys).forEach(walletKey => {
      if (walletKey.type === 'assymetric') {
        if (walletKey.tags[0] === 'X25519KeyAgreementKey2019') {
          keyAgreementkeys.push({
            id: walletKey.tags[1] || `#${walletKey.kid}`,
            type: 'X25519KeyAgreementKey2019',
            usage: 'signing',
            [walletKey.didPublicKeyEncoding]: walletKey.publicKey
          })
        } else {
          if (walletKey.encoding === 'jwk') {
            publicKeys.push({
              id: walletKey.tags[1] || `#${walletKey.kid}`,
              type: walletKey.tags[0],
              usage: 'signing',
              [walletKey.didPublicKeyEncoding]: JSON.parse(walletKey.publicKey)
            })
          } else {
            publicKeys.push({
              id:
                walletKey.tags[1] !== undefined
                  ? walletKey.tags[1]
                  : `#${walletKey.kid}`,
              type: walletKey.tags[0],
              usage:
                walletKey.tags[1] &&
                walletKey.tags[1].split('#').pop() === 'recovery'
                  ? 'recovery'
                  : 'signing',
              [walletKey.didPublicKeyEncoding]: walletKey.publicKey
            })
          }

          commonVerificationMethods.push(publicKeys[publicKeys.length - 1].id)
        }
      }
    })
    didDocumentModel.publicKey = publicKeys
    didDocumentModel.verificationMethod = publicKeys
    didDocumentModel.authentication = commonVerificationMethods
    didDocumentModel.assertionMethod = commonVerificationMethods
    didDocumentModel.capabilityDelegation = commonVerificationMethods
    didDocumentModel.capabilityInvocation = commonVerificationMethods
    didDocumentModel.keyAgreement = keyAgreementkeys

    return didDocumentModel
  }

  const addDIDToWallet = (did, wallet) => {
    Object.values(wallet.keys).forEach(walletKey => {
      if (walletKey.tags[1] === undefined) {
        walletKey.tags.push(`#${walletKey.kid}`)
      }
      const fragment = walletKey.tags[1]
      walletKey.tags.push(did + fragment)
    })

    return wallet
  }

  const getNewWallet = async () => {
    const mnemonic = await MnemonicKeySystem.generateMnemonic()
    const ed25519Key = await didCrypto.ed25519.createKeys()

    const x25519Key = didCrypto.ed25519.X25519KeyPair.fromEdKeyPair({
      publicKeyBase58: ed25519Key.publicKeyBase58,
      privateKeyBase58: ed25519Key.privateKeyBase58
    })

    console.log({ x25519Key })

    const wall = DIDWallet.create()

    const notes = 'generated in did Manager.'

    wall.addKey({
      type: 'mnemonic',
      encoding: 'bip39',
      mnemonic,
      tags: ['BIP39 Mnemonic'],
      notes
    })

    const mks = new MnemonicKeySystem(mnemonic)
    const primaryKey = mks.getKeyForPurpose('primary', 0)
    const recoveryKey = mks.getKeyForPurpose('recovery', 0)

    // convert hex to jwk, so JOSE is easy....
    const secp256k1LinkedDataKey = {
      // id: 'did:example:123#WqzaOweASs78whhl_YvCEvj1nd89IycryVlmZMefcjU',
      // type: 'EcdsaSecp256k1VerificationKey2019',
      // controller: 'did:example:123',
      publicKeyJwk: await ES256K.keyUtils.publicJWKFromPublicKeyHex(
        primaryKey.publicKey
      ),
      privateKeyJwk: await ES256K.keyUtils.privateJWKFromPrivateKeyHex(
        primaryKey.privateKey
      )
    }

    wall.addKey({
      type: 'assymetric',
      encoding: 'jwk',
      publicKey: JSON.stringify(secp256k1LinkedDataKey.publicKeyJwk),
      privateKey: JSON.stringify(secp256k1LinkedDataKey.privateKeyJwk),
      didPublicKeyEncoding: 'publicKeyJwk',
      tags: [
        'EcdsaSecp256k1VerificationKey2019',
        `#${secp256k1LinkedDataKey.publicKeyJwk.kid}`
      ],
      notes
    })

    wall.addKey({
      type: 'assymetric',
      encoding: 'hex',
      ...primaryKey,
      didPublicKeyEncoding: 'publicKeyHex',
      tags: ['EcdsaSecp256k1VerificationKey2019', '#primary'],
      notes
    })

    wall.addKey({
      type: 'assymetric',
      encoding: 'hex',
      ...recoveryKey,
      didPublicKeyEncoding: 'publicKeyHex',
      tags: ['EcdsaSecp256k1VerificationKey2019', '#recovery'],
      notes
    })

    wall.addKey({
      type: 'assymetric',
      encoding: 'base58',
      didPublicKeyEncoding: 'publicKeyBase58',
      publicKey: ed25519Key.publicKeyBase58,
      privateKey: ed25519Key.privateKeyBase58,
      tags: ['Ed25519VerificationKey2018'],
      notes
    })

    wall.addKey({
      type: 'assymetric',
      encoding: 'hex',
      didPublicKeyEncoding: 'publicKeyHex',
      publicKey: x25519Key.toString('hex'),
      privateKey: x25519Key.toString('hex'),
      tags: ['X25519KeyAgreementKey2019', '#keyAgreement'],
      notes
    })

    const didDocumentModel = walletToInitialDIDDoc(wall)
    const createPayload = await getCreatePayload(didDocumentModel, primaryKey)
    const didUniqueSuffix = getDidUniqueSuffix(createPayload)

    const predictedDID = `${didMethodName}:${didUniqueSuffix}`

    addDIDToWallet(predictedDID, wall)

    return wall
  }
  return {
    getDidDocumentModel,
    makeSignedOperation,
    getCreatePayload,
    getUpdatePayload,
    getUpdatePayloadForAddingAKey,
    getUpdatePayloadForRemovingAKey,
    getRecoverPayload,
    getDeletePayload,
    getNewWallet,
    walletToInitialDIDDoc
  }
}

export default op
