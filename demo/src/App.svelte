<script>
	import { onMount } from "svelte";

	import { DIDManager, MnemonicKeySystem } from "hypns-did-manager";
	import ObjComp from "./components/ObjectComp.svelte";
	import HypnsComponent from "hypns-svelte-component";
	import once from "events.once";

	export let hypnsNode;
	export let myInstance;

	let val, latest;

	let primaryKey, didDoc;

	// Instantiate the DIDManager class
	const db = {};
	const storage = {};

	// hypnsNode opts
	// You can configure the node to meet your networking needs
	let wsProxy = [
		"wss://super.peerpiper.io:49777",
		"wss://hyperswarm.mauve.moe",
	];
	let opts = {
		persist: true,
		swarmOpts: { announceLocalAddress: true, wsProxy },
	};
	let mounted;
	onMount(async () => {
		mounted = true;
	});

	$: mounted && !!hypnsNode ? init() : null;

	const init = async () => {
		const manager = new DIDManager({
			db,
			storage,
			parameters: { didMethodName: "hypns" },
			hypnsNode,
		});

		// Generate a simple did document model
		const mks = new MnemonicKeySystem(MnemonicKeySystem.generateMnemonic());
		try {
			primaryKey = await mks.getKeyForPurpose("primary", 0);
			const recoveryKey = await mks.getKeyForPurpose("recovery", 0);
			console.log({ primaryKey }, { recoveryKey });
			const didDocumentModel = manager.op.getDidDocumentModel(
				primaryKey.publicKey,
				recoveryKey.publicKey
			);
			console.log({ didDocumentModel });

			const wallet = await manager.op.getNewWallet();
			console.log({ wallet });

			didDoc = manager.op.walletToInitialDIDDoc(wallet);
			console.log({ didDoc });

			// Generate HyPNS signed payload
			const payload = await manager.op.getCreatePayload(
				didDocumentModel,
				primaryKey
			);

			// Publish to HyPNS
			const loadingInstance = await hypnsNode.open({
				keypair: {
					publicKey: primaryKey.publicKey,
					secretKey: primaryKey.privateKey,
				},
			});
			await loadingInstance.ready();
			myInstance = loadingInstance;
			myInstance.on("update", (val) => {
				console.log("Update!", { val });
			});
			const ret = myInstance.publish(payload);
			console.log("Return", { ret });
			latest = myInstance.latest;
		} catch (error) {
			console.error(error);
		}
	};
</script>

<main>
	<h1>Hello!</h1>
	<p>
		Visit the <a href="https://svelte.dev/tutorial">Svelte tutorial</a> to learn
		how to build Svelte apps.
	</p>
	<p>
		publicKey: {primaryKey ? primaryKey.publicKey : ""}<br />
		privateKey: {primaryKey ? primaryKey.privateKey : ""}<br />
	</p>
	{#if didDoc}
		<ObjComp
			val={didDoc}
			key={"Decentralized Id Document"}
			expanded={true}
		/>
	{/if}
	<p>
		Save this DID Doc as a signedpayload to hypns.<br />
		TODO: Do I push the payload logic to HyPNS?<br />
		1. Publish to hypns ✔️<br />
		2. Get the did doc<br /><br />
		3. Check signature of payload against key in Did doc<br />
	</p>
	<p>latest: {latest}</p>
	<HypnsComponent bind:hypnsNode {opts} />
</main>

<style>
	main {
		text-align: center;
		padding: 1em;
		max-width: 240px;
		margin: 0 auto;
	}

	h1 {
		color: #ff3e00;
		text-transform: uppercase;
		font-size: 4em;
		font-weight: 100;
	}

	@media (min-width: 640px) {
		main {
			max-width: none;
		}
	}
</style>
