import * as didCrypto from '../crypto/index.js'
import DIDWallet from 'simple-did-wallet'

const SERVICE = 'service'
const SERVICE_INDEX = 0

function bufferToHex (buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
export default (manager) => {
  // const { didMethodName } = manager.parameters

  const getKeypairByTag = (tag) => { // ex: '#primary' or '#root
    const tagKeypair = manager.wallet.extractByTags([tag])[0] // array of uint8array
    // get keys
    const keypair = {
      publicKey: tagKeypair.publicKey,
      secretKey: tagKeypair.privateKey
    }
    return { keypair }
  }
  const createKeypairFromDeviceName = async (deviceName, tag) => {
    const seed = await manager.hypnsNode.getDeviceSeed(deviceName) // uint8array
    manager.wallet = await createWallet(seed)

    const keypair = getKeypairByTag(tag)

    return keypair
  }

  const getDidFromKeypair = async (keypair) => {
    const didInstance = await manager.hypnsNode.open({ keypair })
    await didInstance.ready()
    const did = `did:hypns:${didInstance.key}`
    return { did, didInstance }
  }

  const getDidInstance = async (deviceName) => {
    const tag = '#root'
    let rootKeypair
    if (!manager.wallet) {
      rootKeypair = createKeypairFromDeviceName(deviceName, tag)
    } else {
      rootKeypair = getKeypairByTag(tag)
    }

    const { did, didInstance } = await getDidFromKeypair(rootKeypair)
    return { did, didInstance }
  }

  const getDid = async (deviceName) => {
    const { did } = await getDidInstance(deviceName)
    return did
  }

  const getDidDoc = async (deviceName) => {
    const { did, didInstance } = await getDidInstance(deviceName)

    if (didInstance.latest && didInstance.latest.didDoc) {
      return didInstance.latest.didDoc
    }

    const didDoc = walletToDIDDoc(manager.wallet)

    didInstance.publish({ didDoc })

    await getServiceInstance(deviceName)

    // add service endpoint to DiDDoc
    const item = {
      id: `${did}#peerpiper-merkle-root`,
      type: 'LinkedDomains',
      serviceEndpoint: `hypns://${manager.serviceInstance.key}`
    }
    didDoc.service
      ? didDoc.service.push(item)
      : (didDoc.service = [item])

    didInstance.publish({ didDoc })

    return didDoc
  }

  const getServiceInstance = async (deviceName) => {
    // Add a data service
    const serviceSeed = await manager.hypnsNode.getDeviceSeed(
      deviceName + '.' + SERVICE + '.' + SERVICE_INDEX
    ) // uint8array
    const serviceKeyPair = await manager.hypnsNode.getKeypair(serviceSeed) // uint8array

    const keypair = { // hex
      publicKey: bufferToHex(serviceKeyPair.publicKey),
      secretKey: bufferToHex(serviceKeyPair.secretKey)
    }

    manager.serviceInstance = await manager.hypnsNode.open({ keypair })
    await manager.serviceInstance.ready()

    // save this keypair to the wallet
    manager.wallet.addKey({
      type: 'assymetric',
      encoding: 'hex',
      publicKey: manager.serviceInstance._keypair.publicKey,
      privateKey: manager.serviceInstance._keypair.secretKey,
      didPublicKeyEncoding: 'publicKeyHex',
      tags: ['#service']
    })

    // retreive
    // const svcKeypair = manager.wallet.extractByTags(['#service'])[0] // array of uint8array
    // the keys
    // const kp = {
    //   publicKey: svcKeypair.publicKey,
    //   secretKey: svcKeypair.privateKey
    // }
    // return manager.serviceInstance
  }
  const keysFromSeed = async (seed) => {
    return await didCrypto.ed25519.createKeys(seed) // Uint8Array
  }

  const createWallet = async (seed = '') => {
    const primaryKey = await keysFromSeed(seed) // Uint8Array

    const recoveryKey = await didCrypto.ed25519.createKeys() // Uint8Array

    const x25519Key = didCrypto.ed25519.X25519KeyPair({
      publicKey: primaryKey.publicKey, // Uint8Array
      secretKey: primaryKey.secretKey // Uint8Array
    })

    const wall = DIDWallet.create()

    const notes = 'generated in did Manager.'

    /**
    * Initially, root key = primary key. But the primary key can eventually be rotated.
    * Root key stays the same, it's public key is used as the DID when there's a DID
    */
    wall.addKey({
      type: 'assymetric',
      encoding: 'hex',
      publicKey: bufferToHex(primaryKey.publicKey),
      privateKey: bufferToHex(primaryKey.secretKey),
      didPublicKeyEncoding: 'publicKeyHex',
      tags: ['Ed25519VerificationKey2018', '#root'],
      notes
    })

    wall.addKey({
      type: 'assymetric',
      encoding: 'hex',
      publicKey: bufferToHex(primaryKey.publicKey),
      privateKey: bufferToHex(primaryKey.secretKey),
      didPublicKeyEncoding: 'publicKeyHex',
      tags: ['Ed25519VerificationKey2018', '#primary'],
      notes
    })

    wall.addKey({
      type: 'assymetric',
      encoding: 'hex',
      publicKey: bufferToHex(recoveryKey.publicKey),
      privateKey: bufferToHex(recoveryKey.secretKey),
      didPublicKeyEncoding: 'publicKeyHex',
      tags: ['Ed25519VerificationKey2018', '#recovery'],
      notes
    })

    wall.addKey({
      type: 'assymetric',
      encoding: 'hex',
      didPublicKeyEncoding: 'publicKeyHex',
      publicKey: bufferToHex(x25519Key.publicKey),
      privateKey: bufferToHex(x25519Key.secretKey),
      tags: ['X25519KeyAgreementKey2019', '#keyAgreement'],
      notes
    })

    // wall.addKey({
    //   type: 'assymetric',
    //   encoding: 'jwk',
    //   publicKey: JSON.stringify(secp256k1LinkedDataKey.publicKeyJwk),
    //   privateKey: JSON.stringify(secp256k1LinkedDataKey.privateKeyJwk),
    //   didPublicKeyEncoding: 'publicKeyJwk',
    //   tags: [
    //     'EcdsaSecp256k1VerificationKey2019',
    //     `#${secp256k1LinkedDataKey.publicKeyJwk.kid}`
    //   ],
    //   notes
    // })

    return wall
  }

  const walletToDIDDoc = (wallet) => {
    const didDocumentModel = {
      '@context': [
        'https://www.w3.org/ns/did/v1'
      ]
    }

    const publicKeys = []
    const commonVerificationMethods = []
    const keyAgreementkeys = []

    Object.values(wallet.keys).forEach((walletKey) => {
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
              id: walletKey.tags[1] !== undefined
                ? walletKey.tags[1]
                : `#${walletKey.kid}`,
              type: walletKey.tags[0],
              usage: walletKey.tags[1] && walletKey.tags[1].split('#').pop() === 'recovery'
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

  return {
    createWallet,
    walletToDIDDoc,
    keysFromSeed,
    getDid,
    getDidDoc,
    getServiceInstance
  }
}
