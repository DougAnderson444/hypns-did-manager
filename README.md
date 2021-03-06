# hypns-did-manager
Manage those DID Documents

## Dev notes

Rollup bundle fails on `process` and `buffer`. Use webpack bundler to build instead.

### Using this lib to Create Read Update Delete DIDs

Once you have an instance of the Sidetree class with the suitable adapters, you can access all the helper functions (`.func`) and perform CRUD operations (`.op`). Here are a few code snippet to get you started:

#### Create a DID

```js
const { DIDManager, MnemonicKeySystem } = require("hypns-did-manager");

// Instantiate the DIDManager class
const manager = new DIDManager();

// Generate a simple did document model
const mks = new MnemonicKeySystem(MnemonicKeySystem.generateMnemonic());
const primaryKey = await mks.getKeyForPurpose("primary", 0);
const recoveryKey = await mks.getKeyForPurpose("recovery", 0);
const didDocumentModel = manager.op.getDidDocumentModel(
  primaryKey.publicKey,
  recoveryKey.publicKey
);

// Generate Sidetree Create payload
const createPayload = manager.op.getCreatePayload(didDocumentModel, primaryKey);

// Create the Sidetree transaction.
// This can potentially take a few minutes if you're not on a local network
const createTransaction = await manager.batchScheduler.writeNow(createPayload);
const didUniqueSuffix = manager.func.getDidUniqueSuffix(createPayload);
const did = `did:elem:ropsten:${didUniqueSuffix}`;
console.log(`${did} was successfully created`);
```

#### Read a DID (aka resolve a DID)

```js
const didDocument = await manager.resolve(didUniqueSuffix, true);
console.log(
  `${did} was successfully resolved into ${JSON.stringify(
    didDocument,
    null,
    2
  )}`
);
```

#### Update a DID document

Add a new key to the did document

```js
// Get last operation data
const operations = await manager.db.readCollection(didUniqueSuffix);
const lastOperation = operations.pop();

// Generate update payload for adding a new key
const newKey = await mks.getKeyForPurpose("primary", 1);
const newPublicKey = {
  id: "#newKey",
  usage: "signing",
  type: "Secp256k1VerificationKey2018",
  publicKeyHex: newKey.publicKey,
};
const updatePayload = await manager.op.getUpdatePayloadForAddingAKey(
  lastOperation,
  newPublicKey,
  primaryKey.privateKey
);

// Create the Sidetree transaction.
const updateTransaction = await manager.batchScheduler.writeNow(updatePayload);
const newDidDocument = await manager.resolve(didUniqueSuffix, true);
console.log(`${JSON.stringify(newDidDocument, null, 2)} has a new publicKey`);
```

#### Recover a did document

How to recover a did document using the recovery key if the private key is lost:

```js
// Generate a recovery payload with the inital did document model
const recoveryPayload = await manager.op.getRecoverPayload(
  didUniqueSuffix,
  didDocumentModel,
  recoveryKey.privateKey
);

// Send Sidetree transaction
const recoveryTransaction = await manager.batchScheduler.writeNow(
  recoveryPayload
);
const recoveredDidDocument = await manager.resolve(didUniqueSuffix, true);
console.log(`${JSON.stringify(recoveredDidDocument, null, 2)} was recovered`);
```

#### Delete a did document

```js
// Generate a delete payload this will brick the did forever
const deletePayload = await manager.op.getDeletePayload(
  didUniqueSuffix,
  recoveryKey.privateKey
);

// Send Sidetree transaction
const deleteTransaction = await manager.batchScheduler.writeNow(deletePayload);
const deletedDidDocument = await manager.resolve(didUniqueSuffix, true);
console.log(`${JSON.stringify(deletedDidDocument, null, 2)} was deleted`);
```

