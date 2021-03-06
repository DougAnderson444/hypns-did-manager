// import * as hash from 'hash.js'
import eccrypto from 'eccrypto'
import base64url from 'base64url'
import * as hashLib from 'hash.js'
import multihashes from 'multihashes'

// This function applies f, an async function, sequentially to an array of values
// We need it because:
//   - Promise.all executes all promises at the same time instead of sequentially
//   - for loop with await is very bad apparently
// Adapted from: https://stackoverflow.com/questions/20100245/how-can-i-execute-array-of-promises-in-sequential-order
export const executeSequentially = (f, array) => {
  return array.reduce((promise, value) => {
    return promise.then(() => f(value))
  }, Promise.resolve())
}

export const encodeJson = payload =>
  base64url.encode(Buffer.from(JSON.stringify(payload)))

export const decodeJson = encodedPayload =>
  JSON.parse(base64url.decode(encodedPayload))

export const payloadToHash = payload => {
  const encodedPayload = encodeJson(payload)
  const encodedOperationPayloadBuffer = Buffer.from(encodedPayload)
  const hash = new Uint8Array(hashLib.sha256()
    .update(encodedOperationPayloadBuffer)
    .digest())
  // const hashAlgorithmName = multihashes.codes[18] // 18 is code for sha256
  const multihash = multihashes.encode(hash, 'sha2-256')
  const encodedMultihash = base64url.encode(multihash)
  return encodedMultihash
}

export const getDidUniqueSuffix = operation => {
  const header = decodeJson(operation.protected)
  switch (header.operation) {
    case 'create':
      return payloadToHash(operation.payload)
    case 'update':
    case 'recover':
    case 'delete':
      return decodeJson(operation.payload).didUniqueSuffix
    default:
      throw Error(`Cannot extract didUniqueSuffixe from: ${operation}`)
  }
}

export const batchFileToOperations = batchFile =>
  batchFile.operations.map(op => {
    const decodedOperation = decodeJson(op)
    const operationHash = payloadToHash(decodedOperation.payload)
    const decodedOperationPayload = decodeJson(decodedOperation.payload)
    const decodedHeader = decodeJson(decodedOperation.protected)
    return {
      operationHash,
      decodedOperation,
      decodedOperationPayload,
      decodedHeader
    }
  })

// TODO check is signatures are the same as sidetree's
export const signEncodedPayload = async (encodedHeader, encodedPayload, privateKey) => {
  const toBeSigned = `${encodedHeader}.${encodedPayload}`
  const hash = hashLib.sha256()
    .update(Buffer.from(toBeSigned))
    .digest()
  const privateKeyBuffer = Buffer.from(privateKey, 'hex')
  const signature = await eccrypto.sign(privateKeyBuffer, hash) // eccrypto.sign(privateKey, msg).then
  const encoding = 'hex'
  const signature64 = base64url.encode(signature.toString(encoding), encoding)
  return signature64
}

export const verifyOperationSignature = (
  encodedHeader,
  encodedPayload,
  signature,
  publicKey
) => {
  const toBeVerified = `${encodedHeader}.${encodedPayload}`
  const hash = hashLib.sha256()
    .update(Buffer.from(toBeVerified))
    .digest()
  const publicKeyBuffer = Buffer.from(publicKey, 'hex')
  return eccrypto.verify(hash, base64url.toBuffer(signature), publicKeyBuffer)
}

export const base58EncodedMultihashToBytes32 = base58EncodedMultihash =>
  `0x${multihashes
    .toHexString(multihashes.fromB58String(base58EncodedMultihash))
    .substring(4)}`

export const bytes32EnodedMultihashToBase58EncodedMultihash = bytes32EncodedMultihash =>
  multihashes.toB58String(
    multihashes.fromHexString(
      `1220${bytes32EncodedMultihash.replace('0x', '')}`
    )
  )

export const toFullyQualifiedDidDocument = didDocument => {
  const did = didDocument.id
  const stringified = JSON.stringify(didDocument)
  const expanded = stringified.replace(/"#/g, `"${did}#`)
  return JSON.parse(expanded)
}

export const getOrderedOperations = operations => {
  const orderedOperations = [...operations]
  orderedOperations.sort(
    (op1, op2) =>
      op1.transaction.transactionNumber - op2.transaction.transactionNumber
  )
  return orderedOperations
}

export const addControllerToPublicKey = (controller, publicKey) => {
  if (typeof publicKey === 'string' || Array.isArray(publicKey)) {
    return publicKey
  }
  return {
    ...publicKey,
    controller: publicKey.controller || controller
  }
}

export const transformDidDocument = didDocument => {
  const transformProperties = [
    'assertionMethod',
    'authentication',
    'capabilityDelegation',
    'capabilityInvocation',
    'publicKey',
    'keyAgreement'
  ]
  const transformed = Object.entries(didDocument).reduce(
    (acc, [property, value]) => {
      if (transformProperties.includes(property)) {
        return {
          ...acc,
          [property]: value.map(pk =>
            addControllerToPublicKey(didDocument.id, pk)
          )
        }
      }
      return {
        ...acc,
        [property]: value
      }
    },
    {}
  )
  return transformed
}
