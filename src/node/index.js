
const node = manager => {
  const { didMethodName } = manager.parameters

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

export default node
