import * as hypnsLib from 'js-did-hypns'

import op from './op/index.js'
import * as func from './func/index.js'
import MKS from './crypto/MnemonicKeySystem.js'

export class DIDManager {
  constructor ({ db, storage, parameters, hypnsNode, opts } = {}) {
    if (!parameters) {
      throw new Error('parameters is missing')
    }
    if (!parameters.didMethodName) {
      throw new Error('didMethodName parameter is missing')
    }
    if (!hypnsNode) {
      throw new Error('hypnsNode parameter is missing')
    }

    this.db = db || {}
    this.storage = storage || {}
    this.parameters = parameters
    this.hypnsNode = hypnsNode

    this.op = op(this)
    this.func = func

    // Resolver
    // this.resolve = resolve(this)
    const resolverOpts = {}
    if (hypnsNode) resolverOpts.hypnsNode = hypnsNode

    const resolver = hypnsLib.getResolver(resolverOpts)
    this.resolve = resolver.hypns

    // Sync (profiles across devices)
    // this.sync = sync(this)
  }
}

export const MnemonicKeySystem = MKS
