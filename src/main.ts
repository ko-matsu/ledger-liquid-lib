import {Ledger} from './ledger'
import { app, BrowserWindow, ipcMain } from 'electron';
import cfdjs from 'cfd-js'

const path = require('path');
const url = require('url');

import {createServer, Server} from 'http';

const sleep = (msec: number) => new Promise(
  (resolve) => setTimeout(resolve, msec));

function generateTx(index: number, xpub: string) {
  // base xpub
  let authorizationPrivkey = '47ab8b0e5f8ea508808f9e03b804d623a7cb81cbf1f39d3e976eb83f9284ecde';
  const basePath = 'm/44\'/1784\'/1\'/0';
  const asset1 = 'aa00000000000000000000000000000000000000000000000000000000000000';
  const asset2 = 'bb00000000000000000000000000000000000000000000000000000000000000';
  const inputAmount = BigInt(5000000);
  const feeAmount = BigInt(50000);
  const inputAmount2 = inputAmount / BigInt(2);
  const inputAmount3 = inputAmount2 - feeAmount;
  // generate random utxo
  const txid1 = cfdjs.CreateKeyPair({wif: false}).privkey;
  const txid2 = cfdjs.CreateKeyPair({wif: false}).privkey;
  const txid3 = cfdjs.CreateKeyPair({wif: false}).privkey;
  const abfList = [];
  const vbfList = [];
  for (let i=0; i<3; ++i) {
    const abf = cfdjs.CreateKeyPair({wif: false}).privkey;
    const vbf = cfdjs.CreateKeyPair({wif: false}).privkey;
    abfList.push(abf);
    vbfList.push(vbf);
  }
  const valueCommitment = cfdjs.GetCommitment({
    amount: inputAmount,
    asset: asset1,
    assetBlindFactor: abfList[1],
    blindFactor: vbfList[1],
  }).amountCommitment;
  const signUtxoList = [
    {
      txid: txid2,
      vout: 1,
      bip32Path: '',
      amount: 0,
      valueCommitment: valueCommitment,
      descriptor: '',
    },
  ];
  // generate unblind tx
  
  const txData = {
    version: 2,
    locktime: 0,
    txins: [{
      txid: txid1,
      vout: 0,
      sequence: 4294967295,
    },{
      txid: txid2,
      vout: 1,
      sequence: 4294967295,
    },{
      txid: txid3,
      vout: 2,
      sequence: 4294967295,
    }],
    txouts: [{
      address: '',
      amount: inputAmount,
      asset: asset2,
    },{
      address: '',
      amount: inputAmount2,
      asset: asset1,
    },{
      address: '',
      amount: inputAmount2,
      asset: asset1,
    },{
      address: '',
      amount: inputAmount2,
      asset: asset1,
    },{
      address: '',
      amount: inputAmount3,
      asset: asset1,
    }],
    fee: {
      amount: feeAmount,
      asset: asset1,
    },
  };
  const max = txData.txouts.length;
  let count = 0;
  const txoutKeys = []
  while (count < max) {
    const keyPair = cfdjs.CreateKeyPair({wif: false});
    txoutKeys.push(keyPair.privkey);
    const addr = cfdjs.CreateAddress({
      hashType: 'p2wpkh',
      network: 'regtest',
      isElements: true,
      keyData: {
        hex: keyPair.pubkey,
        type: 'pubkey',        
      },
    });
    const ctAddr = cfdjs.GetConfidentialAddress({
      key: keyPair.pubkey,
      unblindedAddress: addr.address,
    });
    txData.txouts[count].address = ctAddr.confidentialAddress;
    count += 1;
  }
  let tx1;
  try {
    tx1 = cfdjs.ElementsCreateRawTransaction(txData);
  } catch (e) {
    console.log(txData);
    throw e;
  }

  // blind tx
  let txHex = '';
  const blindReqData: cfdjs.BlindRawTransactionRequest = {
    tx: tx1.hex,
    txins: [{
      txid: txData.txins[0].txid,
      vout: txData.txins[0].vout,
      amount: inputAmount,
      asset: asset1,
      assetBlindFactor: abfList[0],
      blindFactor: vbfList[0],
    },{
      txid: txData.txins[1].txid,
      vout: txData.txins[1].vout,
      amount: inputAmount,
      asset: asset1,
      assetBlindFactor: abfList[1],
      blindFactor: vbfList[1],
    },{
      txid: txData.txins[2].txid,
      vout: txData.txins[2].vout,
      amount: inputAmount,
      asset: asset2,
      assetBlindFactor: abfList[2],
      blindFactor: vbfList[2],
    }],
  };
  try {
    txHex = cfdjs.BlindRawTransaction(blindReqData).hex;
  } catch (e) {
    console.log(txData);
    throw e;
  }

  // calc auth signature
  // get authorization start ---------------------------------
  // console.log('*** calc authorization start ***');
  // console.log('SerializeLedgerFormat =', authorizationHash);
  const authSig = cfdjs.CalculateEcSignature({
    sighash: cfdjs.SerializeLedgerFormat({
        tx: txHex,
        isAuthorization: true,
      }).sha256,
    privkeyData: {
      privkey: authorizationPrivkey,
      wif: false,
    },
    isGrindR: false,
  });
  const authDerSigData = cfdjs.EncodeSignatureByDer({
    signature: authSig.signature,
    sighashType: 'all'});
  const authDerSig = authDerSigData.signature.substring(
      0, authDerSigData.signature.length - 2);
  // console.log(`*** calc authorization end. [${authDerSig}] ***`);
  // get authorization end ---------------------------------

  // const network = (networkType == NetworkType.LiquidV1) ? 'mainnet' : 'regtest';
  const network = 'regtest';
  const deriveKey = cfdjs.CreateExtkeyFromParentPath({
    extkey: xpub,
    childNumberArray: [index],
    extkeyType: 'extPubkey',
    network,
  });
  const pubkey = cfdjs.GetPubkeyFromExtkey({
    extkey: deriveKey.extkey,
    network,
  });
  signUtxoList[0].descriptor = `wpkh(${pubkey.pubkey})`;
  signUtxoList[0].bip32Path = `${basePath}/${count}`;
  return {
    tx: txHex,
    authSignature: authDerSig,
    signUtxoList: signUtxoList,
  };
}

async function signTest(loopMaxCount: number) {
  // const txHex: string = fixTxHex2;
  const loopSleepTime = 0;
  try {
    const basePath = 'm/44\'/1784\'/1\'/0';
    const xpub = await Ledger.getXpubKey({hdWalletPath: basePath});

    let count = 0;
    let failCount = 0;
    const txList = [];
    console.log(`generateTx loop start. count=${loopMaxCount}`);
    while (count < loopMaxCount) {
      txList.push(generateTx(count, xpub));
      count += 1;
    }
    console.log(`generateTx loop end. count=${loopMaxCount}`);

    count = 0;
    console.log(`getSignature loop start. count=${loopMaxCount}, wait=${loopSleepTime}sec`);
    while (count < loopMaxCount) {
      const startTime = Date.now();
      let sigRet = await Ledger.listSignatures({
          proposalTx: txList[count].tx,
          proposalTxSignature: txList[count].authSignature,
          signTargetUtxos: txList[count].signUtxoList,
        });
      const endTime = Date.now();
      console.log(`getSignature(${count}): ${(endTime - startTime)} msec`);
      if (loopSleepTime > 0) {
        await sleep(loopSleepTime * 1000);
      }
      count += 1;
      const isConnect = await Ledger.checkConnection();
      if (!isConnect) {
        console.log(`checkConnection fail.(${failCount})`);
        failCount += 1;
      }
    }
    console.log(`getSignature loop end. count=${count}, wait=${loopSleepTime}sec`);
  } catch (err) {
    console.log(err);
  }
}

// This a very basic example
// Ideally you should not run this code in main thread
// but run it in a dedicated node.js process
async function getLedgerInfo() {
  console.log('getLedgerInfo call.');
  await Ledger.connect();
  return 'connected';
}

// Keep a global reference of the window object, if you don't, the window will
// be closed automatically when the JavaScript object is garbage collected.
let mainWindow: BrowserWindow;
let server: Server;
let isUseServer = false;

function createWindow() {
  // Create the browser window.
  mainWindow = new BrowserWindow({
     webPreferences: {
      nodeIntegration: true
    }, width: 600, height: 430 });

  // and load the index.html of the app.
  mainWindow.loadURL(url.format({
    pathname: path.join(__dirname, './index.html'),
    protocol: 'file:',
    slashes: true
  }))

  // Open the DevTools.
  mainWindow.webContents.openDevTools()

  // Emitted when the window is closed.
  mainWindow.on("closed", async function() {
    // Dereference the window object, usually you would store windows
    // in an array if your app supports multi windows, this is the time
    // when you should delete the corresponding element.
    // mainWindow = null;
    await Ledger.disconnect();
    console.log('disconnect');
    if (isUseServer) {
      server.close();
      isUseServer = false;
    }
  });

  // ~~~ BASIC LEDGER EXAMPLE ~~~

  ipcMain.on("requestLedgerInfo", async (event) => {
    const result = await getLedgerInfo();
    console.log('ledgerInfo');
    console.log(result);
    mainWindow.webContents.send("ledgerInfo", result);
  });

  ipcMain.on("requestSignTest", async (event, value) => {
    let count = parseInt(value, 10);
    if (count == 0) count = 10;
    await signTest(count);
  });

  // http server
  server = createServer();
  server.on('request', async function(req, res) {
      const index = 0;
      const xpub = 'tpubD6NzVbkrYhZ4XyJymmEgYC3uVhyj4YtPFX6yRTbW6RvfRC7Ag3sVhKSz7MNzFWW5MJ7aVBKXCAX7En296EYdpo43M4a4LaeaHuhhgHToSJF';
      const txdata = generateTx(index, xpub);
      res.writeHead(200, {'Content-Type' : 'text/plain'});
      res.write(txdata.tx);
      res.end();
      console.log('[server] receive and response.');
  });
  server.listen(40000);
  isUseServer = true;
  // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
}

// This method will be called when Electron has finished
// initialization and is ready to create browser windows.
// Some APIs can only be used after this event occurs.
app.on("ready", createWindow);

// Quit when all windows are closed.
app.on("window-all-closed", async function() {
  // On macOS it is common for applications and their menu bar
  // to stay active until the user quits explicitly with Cmd + Q
  if (process.platform !== "darwin") {
    await Ledger.disconnect();
    console.log('disconnect');
    if (isUseServer) {
      server.close();
      isUseServer = false;
    }
    app.quit();
  }
});

app.on("activate", function() {
  // On macOS it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  if (mainWindow === null) {
    createWindow();
  }
});

// In this file you can include the rest of your app's specific main process
// code. You can also put them in separate files and require them here.
