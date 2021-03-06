import secp256k1 from 'secp256k1'
import * as bip39 from 'bip39'
import hdkey from 'hdkey'

const getCompressedPublicFromPrivate = privateKeyHex =>
  secp256k1.publicKeyCreate(Buffer.from(privateKeyHex, 'hex')).toString('hex')

const getUncompressedPublicKeyFromCompressedPublicKey = compressedPublicKeyHex =>
  secp256k1
    .publicKeyConvert(Buffer.from(compressedPublicKeyHex, 'hex'), false)
    .slice(1)
    .toString('hex')

// FIXME: purposeIndex
const getPathForProofPurpose = (purpose, version) => {
  let purposeIndex = 0
  switch (purpose) {
    case 'primary':
      purposeIndex = 1
      break
    case 'attestation':
      purposeIndex = 2
      break
    case 'root':
    case 'recovery':
      purposeIndex = 0
      break
    default:
  }
  return `m/44'/60'/0'/${purposeIndex}/${version}`
}

export default class MnemonicKeySystem {
  static generateMnemonic () {
    return bip39.generateMnemonic()
  }

  constructor (mnemonic) {
    const seed = bip39.mnemonicToSeed(mnemonic)
    this.root = hdkey.fromMasterSeed(seed)
    // eslint-disable-next-line
    this.getUncompressedPublicKeyFromCompressedPublicKey = getUncompressedPublicKeyFromCompressedPublicKey;
  }

  getKeyFromHDPath (hdPath) {
    const addrNode = this.root.derive(hdPath)
    // eslint-disable-next-line
    const privateKeyHex = addrNode._privateKey.toString('hex');
    return {
      // this should be compressed.
      publicKey: getCompressedPublicFromPrivate(privateKeyHex),
      privateKey: privateKeyHex
    }
  }

  getKeyForPurpose (purpose, version) {
    return this.getKeyFromHDPath(getPathForProofPurpose(purpose, version))
  }
}
