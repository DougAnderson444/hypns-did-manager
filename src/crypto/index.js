import {
  generateKeyPairFromSeed,
  generateKeyPair,
  convertPublicKeyToX25519,
  convertSecretKeyToX25519
} from '@stablelib/ed25519'

const createKeys = async (seed) => {
  if (seed) return generateKeyPairFromSeed(new Uint8Array(seed))
  return generateKeyPair()
}

const X25519KeyPair = (edKeyPair) => {
  const publicKey = convertPublicKeyToX25519(edKeyPair.publicKey)
  const secretKey = convertSecretKeyToX25519(edKeyPair.secretKey)
  return {
    publicKey,
    secretKey
  }
}

export const ed25519 = {
  createKeys,
  X25519KeyPair
}
