import op from './op/index.js'

class Manager {
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

    // this.didHypns = didHypns(hypnsNode)

    this.op = op(this)

    // Resolver
    // this.resolve = resolve(this)

    const resolverOpts = {}
    if (hypnsNode) resolverOpts.hypnsNode = hypnsNode

    // const resolver = hypnsLib.getResolver(resolverOpts)
    // this.resolve = resolver.hypns

    // Sync (profiles across devices)
    // this.sync = sync(this)
  }
}

export const DIDManager = (opts) => {
  return new Manager(opts)
}
