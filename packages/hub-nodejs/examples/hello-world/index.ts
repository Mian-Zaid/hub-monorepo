import {
  FarcasterNetwork,
  getAuthMetadata,
  getInsecureHubRpcClient,
  getSSLHubRpcClient,
  HubAsyncResult,
  makeUserDataAdd,
  Message,
  Metadata,
  NobleEd25519Signer,
  UserDataType,
  ID_GATEWAY_ADDRESS,
  idGatewayABI,
  KEY_GATEWAY_ADDRESS,
  keyGatewayABI,
  ID_REGISTRY_ADDRESS,
  idRegistryABI,
  makeCastRemove,
  ServiceError,
  MessagesResponse,
  makeCastAdd,
} from "@farcaster/hub-nodejs";
import { ViemLocalEip712Signer } from "@farcaster/hub-web";
import { privateKeyToAccount } from "viem/accounts";
import * as ed from "@noble/ed25519";
import { mnemonicToAccount, toAccount } from "viem/accounts";
import {
  createWalletClient,
  decodeEventLog,
  fromHex,
  Hex,
  http,
  LocalAccount,
  publicActions,
  toHex,
  zeroAddress,
} from "viem";
import { optimism, foundry, mainnet } from "viem/chains";
import { ed25519 } from "@noble/curves/ed25519";
import axios from "axios";
import {
  readContract,
  getBalance,
  writeContract,
  simulateContract,
  waitForTransactionReceipt,
  getChainId,
} from "viem/actions";

import dns from "node:dns";
import { err } from "neverthrow";
import { ethers } from "ethers";
dns.setDefaultResultOrder("ipv4first");

/**
 * Populate the following constants with your own values
 */
const MNEMONIC =
  "picture angle spin winter music salon field depth sand fever mechanic reflect"; //0x0319B28efEeF6131f1bcC833eCAA86E5c9c75867 //0x0319B28efEeF6131f1bcC833eCAA86E5c9c75867
const OP_PROVIDER_URL = "http://127.0.0.1:8545"; // Alchemy or Infura url
const RECOVERY_ADDRESS = zeroAddress; // Optional, using the default value means the account will not be recoverable later if the mnemonic is lost
const SIGNER_PRIVATE_KEY: Hex = zeroAddress; // Optional, using the default means a new signer will be created each time
const ACCOUNT_KEY_PRIVATE_KEY: Hex = zeroAddress; // Optional, using the default means a new account key will be created each time

// Note: nemes is the Farcaster team's mainnet hub, which is password protected to prevent abuse. Use a 3rd party hub
// provider like https://neynar.com/ Or, run your own mainnet hub and broadcast to it permissionlessly.
const HUB_URL = "3.94.116.133:2283"; // URL + Port of the Hub
const HUB_USERNAME = ""; // Username for auth, leave blank if not using TLS
const HUB_PASS = ""; // Password for auth, leave blank if not using TLS
const USE_SSL = false; // set to true if talking to a hub that uses SSL (3rd party hosted hubs or hubs that require auth)
const FC_NETWORK = FarcasterNetwork.MAINNET; // Network of the Hub

const myFID = 818682;

const CHAIN = optimism;
const IdGateway = {
  abi: idGatewayABI,
  address: ID_GATEWAY_ADDRESS,
  chain: CHAIN,
};
const IdContract = {
  abi: idRegistryABI,
  address: ID_REGISTRY_ADDRESS,
  chain: CHAIN,
};
const KeyContract = {
  abi: keyGatewayABI,
  address: KEY_GATEWAY_ADDRESS,
  chain: CHAIN,
};

const account = mnemonicToAccount(MNEMONIC);
// console.log("Account is: ", account);

const accountAddress = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"; //account.address; //"0x53c6dA835c777AD11159198FBe11f95E5eE6B692";
const accountPrivateKey =
  "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a";
const walletClient = createWalletClient({
  account: accountAddress,
  chain: CHAIN,
  transport: http(OP_PROVIDER_URL),
}).extend(publicActions);

// console.log("Wallet client is : ", walletClient);
const hubClient = USE_SSL
  ? getSSLHubRpcClient(HUB_URL)
  : getInsecureHubRpcClient(HUB_URL);

const metadata =
  HUB_USERNAME !== "" && HUB_PASS !== ""
    ? getAuthMetadata(HUB_USERNAME, HUB_PASS)
    : new Metadata();

const getOrRegisterFid = async (): Promise<number> => {
  const balance = await getBalance(walletClient, { address: accountAddress });
  myLog("Balance in wei is : ", balance);
  myLog("Balance in Ethers is : ", ethers.formatEther(balance));
  myLog("Wallet Address is : ", accountAddress);

  var existingFid = myFID;
  try {
    existingFid = (await readContract(walletClient, {
      ...IdContract,
      functionName: "idOf",
      args: [accountAddress],
    })) as bigint;

    myLog(
      `Using address: ${accountAddress} with balance: ${balance} existing FiD: ${existingFid}`
    );
  } catch (error) {
    myLog("Error while getting id of: ", error);
    return existingFid;
  }

  if (balance === 0n && existingFid === 0n) {
    throw new Error("No existing Fid and no funds to register an fid");
  }

  if (existingFid > 0n) {
    myLog(`Using existing fid: ${existingFid}`);
    return parseInt(existingFid.toString());
  }

  var price = 0n;
  try {
    price = await readContract(walletClient, {
      ...IdGateway,
      functionName: "price",
    });
  } catch (error) {
    myLog(`Error while getting Price: ${error}`);
    return existingFid;
  }

  myLog(`Cost to rent storage in wei: ${price}`);
  myLog(`Cost to rent storage in Ethers: ${ethers.formatEther(price)}`);

  if (balance < price) {
    throw new Error(
      `Insufficient balance to rent storage,Ethers required: ${ethers.formatEther(
        price
      )}, balance: ${ethers.formatEther(balance)}`
    );
  }

  var fid = 0;
  try {
    const { request: registerRequest } = await simulateContract(walletClient, {
      ...IdGateway,
      functionName: "register",
      args: [RECOVERY_ADDRESS],
      value: price,
    });
    const registerTxHash = await writeContract(walletClient, registerRequest);
    myLog(`Waiting for register tx to confirm: ${registerTxHash}`);
    const registerTxReceipt = await waitForTransactionReceipt(walletClient, {
      hash: registerTxHash,
    });
    // Now extract the FID from the logs
    const registerLog = decodeEventLog({
      abi: idRegistryABI,
      data: registerTxReceipt.logs[0].data,
      topics: registerTxReceipt.logs[0].topics,
    });
    // @ts-ignore
    fid = parseInt(registerLog.args["id"]);
    myLog(`Registered fid: ${fid} to ${accountAddress}`);
  } catch (error) {
    myLog("Error while registering fid: ", error);
    return existingFid;
  }

  return fid;
};

const getOrRegisterSigner = async (fid: number) => {
  if (SIGNER_PRIVATE_KEY !== zeroAddress) {
    // If a private key is provided, we assume the signer is already in the key registry
    const privateKeyBytes = fromHex(SIGNER_PRIVATE_KEY, "bytes");
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);
    myLog(`Using existing signer with public key: ${toHex(publicKeyBytes)}`);
    return privateKeyBytes;
  }

  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = toHex(ed25519.getPublicKey(privateKey));

  myLog(`Private key is: ${toHex(privateKey)}`);

  // To add a key, we need to sign the metadata with the fid of the app we're adding the key on behalf of
  // We'll use our own fid and custody address for simplicity. This can also be a separate App specific fid.
  // const localAccount = toAccount(accountAddress);
  const appAccount = privateKeyToAccount(accountPrivateKey);
  // myLog("localaccount: ", localAccount);
  const eip712signer = new ViemLocalEip712Signer(appAccount);

  console.log("eip712signer: ", eip712signer);

  const metadata = await eip712signer.getSignedKeyRequestMetadata({
    requestFid: BigInt(fid),
    key: hexToUint8Array(publicKey),
    deadline: BigInt(Math.floor(Date.now() / 1000) + 60 * 60), // 1 hour from now
  });

  myLog("Metadata:", metadata);

  const metadataHex = toHex(metadata.unwrapOr(new Uint8Array()));

  myLog("Metadata Hex:", metadataHex);

  const { request: signerAddRequest } = await simulateContract(walletClient, {
    ...KeyContract,
    functionName: "add",
    args: [1, publicKey, 1, metadataHex], // keyType, publicKey, metadataType, metadata
  });

  // myLog("signerAddRequest", signerAddRequest);
  const signerAddTxHash = await writeContract(walletClient, signerAddRequest);
  myLog(`Waiting for signer add tx to confirm: ${signerAddTxHash}`);
  const receipt = await waitForTransactionReceipt(walletClient, {
    hash: signerAddTxHash,
  });
  myLog("Receipt: ", receipt);
  myLog(`Registered new signer with public key: ${publicKey}`);
  myLog("Sleeping 30 seconds to allow hubs to pick up the signer tx");
  await new Promise((resolve) => setTimeout(resolve, 30000));
  return privateKey;
};

const registerFname = async (fid: number) => {
  try {
    // First check if this fid already has an fname
    const response = await axios.get(
      `https://fnames.farcaster.xyz/transfers/current?fid=${fid}`
    );
    const fname = response.data.transfer.username;
    myLog(`Fid ${fid} already has fname: ${fname}`);
    return fname;
  } catch (e) {
    // No username, ignore and continue with registering
  }

  const fname = `fid-${fid}`;
  const timestamp = Math.floor(Date.now() / 1000);
  const localAccount = toAccount(account);
  const appAccount = privateKeyToAccount(accountPrivateKey);
  const signer = new ViemLocalEip712Signer(appAccount);
  const userNameProofSignature = signer.signUserNameProofClaim({
    name: fname,
    timestamp: BigInt(timestamp),
    owner: accountAddress,
  });

  myLog(`Registering fname: ${fname} to fid: ${fid}`);
  try {
    const response = await axios.post(
      "https://fnames.farcaster.xyz/transfers",
      {
        name: fname, // Name to register
        from: 0, // Fid to transfer from (0 for a new registration)
        to: fid, // Fid to transfer to (0 to unregister)
        fid: fid, // Fid making the request (must match from or to)
        owner: accountAddress, // Custody address of fid making the request
        timestamp: timestamp, // Current timestamp in seconds
        signature: userNameProofSignature, // EIP-712 signature signed by the current custody address of the fid
      }
    );
    return fname;
  } catch (e) {
    // @ts-ignore
    throw new Error(
      `Error registering fname: ${JSON.stringify(e.response.data)} (status: ${
        e.response.status
      })`
    );
  }
};

const submitMessage = async (resultPromise: HubAsyncResult<Message>) => {
  const result = await resultPromise;
  if (result.isErr()) {
    throw new Error(`Error creating message: ${result.error}`);
  }
  myLog("Message Created: ", result.value);
  const messageSubmitResult = await hubClient.submitMessage(result.value);
  if (messageSubmitResult.isErr()) {
    throw new Error(
      `Error submitting message to hub: ${messageSubmitResult.error}`
    );
  }
};

const hexToUint8Array = (hex: any) => {
  // Remove the "0x" prefix if present
  if (hex.startsWith("0x")) {
    hex = hex.slice(2);
  }

  // Create a Uint8Array with half the length of the hex string
  const byteArray = new Uint8Array(hex.length / 2);

  // Convert hex to byte values
  for (let i = 0; i < hex.length; i += 2) {
    byteArray[i / 2] = parseInt(hex.substr(i, 2), 16);
  }

  return byteArray;
};

(async () => {
  // myLog("Chain id: ", await getChainId(walletClient));
  const chainId = walletClient.chain.id; //await getChainId(walletClient);

  // myLog("Wallet Client id: ", walletClient.chain.id);

  if (chainId !== CHAIN.id) {
    throw new Error(`Chain ID ${chainId} not supported`);
  }

  const fid = await getOrRegisterFid();

  myLog("Sleeping 30 seconds to allow hubs to pick up the new FID");
  await new Promise((resolve) => setTimeout(resolve, 30000));

  const signerPrivateKey = await getOrRegisterSigner(fid);
  // const fname = await registerFname(fid);

  await getCastsByFid(fid);

  // Publish a cast

  const signer = new NobleEd25519Signer(signerPrivateKey);

  myLog("Signer is: ", signer);

  const dataOptions = {
    fid: fid,
    network: FC_NETWORK,
  };

  await submitMessage(
    makeCastAdd(
      {
        text: "Hello World!",
        embedsDeprecated: [],
        mentions: [],
        mentionsPositions: [],
        embeds: [],
      },
      dataOptions,
      signer
    )
  );

  // await getCastsByFid(myFID);
  // Now set the fname by constructing the appropriate userDataAdd message and signing it

  // const userDataPfpBody = {
  //   type: UserDataType.USERNAME,
  //   value: fname,
  // };

  // myLog("userDataPfpBody is: ", userDataPfpBody);

  // await submitMessage(makeUserDataAdd(userDataPfpBody, dataOptions, signer));

  // // Now set the PFP and display name as well
  // await submitMessage(
  //   makeUserDataAdd(
  //     { type: UserDataType.DISPLAY, value: fname },
  //     dataOptions,
  //     signer
  //   )
  // );
  // await submitMessage(
  //   makeUserDataAdd(
  //     { type: UserDataType.PFP, value: "https://i.imgur.com/yed5Zfk.gif" },
  //     dataOptions,
  //     signer
  //   )
  // );

  // myLog(
  //   `Successfully set up user, view at: https://warpcast.com/${fname}`
  // );

  hubClient.close();
})();

async function getCastsByFid(_fid: number) {
  // Create a request object for FidRequest
  const fidRequest = {
    fid: _fid,
  };

  // Call the getCastsByFid method
  var res = await hubClient.getCastsByFid(fidRequest);
  if (res.isOk()) {
    var messages = res.value.messages;
    myLog("Number of Casts: ", messages.length);
    messages.forEach((message, index) => {
      myLog(`cast ${index + 1}: `, message.data.castAddBody.text);
    });
  } else {
    myLog("Error fetching Casts: ", res);
  }
}

function myLog(log: any, data: any = null) {
  if (data == null) {
    console.log("\n", log, "\n");
  } else {
    console.log("\n", log, data, "\n");
  }
}
