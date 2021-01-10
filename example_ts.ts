/* eslint-disable require-jsdoc */
import * as cfdjs from 'cfd-js';
import {LedgerLiquidWrapper, WalletUtxoData, SignatureData, NetworkType, AddressType, GetSignatureState, ProgressInfo, UsbDetectionType} from './src/ledger-liquid-lib';
import {Device} from 'usb-detection';
import { features } from 'process';

process.on('unhandledRejection', console.dir);

let hashType = 'p2sh-p2wpkh'; // 'p2sh-p2wsh';
const blindOpt = {blind1: true, blind2: true};
let networkType = NetworkType.LiquidV1;
// eslint-disable-next-line prefer-const
let tx2InputCount = 2;
// eslint-disable-next-line prefer-const
let signTargetIndex = [0, 1];
let signedTest = false;
let setIssueTx = 0;
let setReissueTx = 0;
let authorizationPrivkey = '47ab8b0e5f8ea508808f9e03b804d623a7cb81cbf1f39d3e976eb83f9284ecde';
let setAuthorization = false;
let authPubKey = ''; // 04b85b0e5f5b41f1a95bbf9a83edd95c741223c6d9dc5fe607de18f015684ff56ec359705fcf9bbeb1620fb458e15e3d99f23c6f5df5e91e016686371a65b16f0c
let setIssuanceToTop = 0;
let setReissuanceToTop = 0;
let connectionTest = false;
let connectionMonitoringTest = false;
let connectDevice = '';
let getLedgerPath = true;
let mnemonic = '';
let mnemonicCheck = true;
// mnemonic = 'call node debug-console.js ledger hood festival pony outdoor always jeans page help symptom adapt obtain image bird duty damage find sense wasp box mail vapor plug general kingdom';
let dumpTx = false;
let txData = '';
let signTarget = '';
let fixedTest = false;
let waitCancelCount = 0;
let currentWaitCancelCount = 0;
let dumpPubkeyMode = false;
let debugMode = false;
let genTxTest = false;
let quickTest = false;
let loopMaxCount = 1;
let loopSleepTime = 0;
let targetBip32Path = 'm/44h/0h/0h';
let asyncConnectCheck = false;
let asyncCommandCheck = false;
let reconnectTest = false;
let testContractHash = '0000000000000000000000000000000000000000000000000000000000000000';
let continousCount = 0;
let continousSleep = 1;

for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i]) {
    if (process.argv[i] === '-r') {
      networkType = NetworkType.Regtest;
    } else if (process.argv[i] === '-gtt') {
      genTxTest = true;
    } else if (process.argv[i] === '-qt') {
      quickTest = true;
    } else if (process.argv[i] === '-d') {
      debugMode = true;
    } else if (process.argv[i] === '-nb1') {
      blindOpt.blind1 = false;
    } else if (process.argv[i] === '-nb2') {
      blindOpt.blind2 = false;
    } else if (process.argv[i] === '-dl') {
      getLedgerPath = false;
    } else if (process.argv[i] === '-t') {
      signedTest = true;
    } else if (process.argv[i] === '-tc') {
      connectionTest = true;
    } else if (process.argv[i] === '-mc') {
      connectionMonitoringTest = true;
    } else if (process.argv[i] === '-a') {
      setAuthorization = true;
    } else if (process.argv[i] === '-dp') {
      dumpPubkeyMode = true;
    } else if (process.argv[i] === '-f') {
      fixedTest = true;
    } else if (process.argv[i] === '-p') {
      dumpTx = true;
    } else if (process.argv[i] === '-tcwc') {
      waitCancelCount = 30;
    } else if (process.argv[i] === '-acc') {
      asyncConnectCheck = true;
      asyncCommandCheck = true;
    } else if (process.argv[i] === '-it') {
      setIssuanceToTop = 2;
      if (setReissuanceToTop) {
        setIssuanceToTop = 1;
      }
    } else if (process.argv[i] === '-rit') {
      setReissuanceToTop = 2;
      if (setIssuanceToTop) {
        setReissuanceToTop = 1;
      }
    } else if (process.argv[i] === '-ic') {
      mnemonicCheck = false;
      getLedgerPath = false;
    } else if (process.argv[i] === '-rct') {
      reconnectTest = true;
    } else if (i+1 < process.argv.length) {
      if (process.argv[i] === '-h') {
        ++i;
        hashType = process.argv[i];
      } else if (process.argv[i] === '-ak') {
        ++i;
        if (process.argv[i].length === 64) {
          authorizationPrivkey = process.argv[i];
        }
      } else if (process.argv[i] === '-n') {
        ++i;
        mnemonic = process.argv[i];
        getLedgerPath = false;
      } else if (process.argv[i] === '-txc') {
        ++i;
        txData = process.argv[i];
      } else if (process.argv[i] === '-st') {
        ++i;
        signTarget = process.argv[i];
      } else if (process.argv[i] === '-uc') {
        ++i;
        tx2InputCount = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-i') {
        ++i;
        setIssueTx = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-ri') {
        ++i;
        setReissueTx = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-si') {
        ++i;
        const numArr = [];
        const list = process.argv[i].split(',');
        for (const input of list) {
          numArr.push(parseInt(input));
        }
        signTargetIndex = numArr;
      } else if (process.argv[i] === '-cd') {
        ++i;
        connectDevice = process.argv[i];
      } else if (process.argv[i] === '-path') {
        ++i;
        targetBip32Path = process.argv[i];
      } else if (process.argv[i] === '-apk') {
        ++i;
        authPubKey = process.argv[i];
      } else if (process.argv[i] === '-ch') {
        ++i;
        testContractHash = process.argv[i];
      } else if (process.argv[i] === '-continous_test') {
        ++i;
        continousCount = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-continous_sleep') {
        ++i;
        continousSleep = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-lmc') {
        ++i;
        loopMaxCount = parseInt(process.argv[i]);
      } else if (process.argv[i] === '-lst') {
        ++i;
        loopSleepTime = parseInt(process.argv[i]);
      }
    }
  }
}

const sleep = (msec: number) => new Promise(
    (resolve) => setTimeout(resolve, msec));

let mnemonicRootKey = '';
function getExtKeyFromParent(bip32Path: string): string {
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  if (!mnemonicRootKey) {
    const seed = cfdjs.ConvertMnemonicToSeed({
      mnemonic: mnemonic.split(' '),
      passphrase: '',
    });
    mnemonicRootKey = cfdjs.CreateExtkeyFromSeed({
      seed: seed.seed,
      network: mainchainNwType,
      extkeyType: 'extPrivkey',
    }).extkey;
  }
  const extkey = cfdjs.CreateExtkeyFromParentPath({
    extkey: mnemonicRootKey,
    extkeyType: 'extPubkey',
    path: bip32Path,
    network: mainchainNwType,
  });
  return extkey.extkey;
}

function getPubkeyFromParent(bip32Path: string): string {
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  if (!mnemonicRootKey) {
    const seed = cfdjs.ConvertMnemonicToSeed({
      mnemonic: mnemonic.split(' '),
      passphrase: '',
    });
    mnemonicRootKey = cfdjs.CreateExtkeyFromSeed({
      seed: seed.seed,
      network: mainchainNwType,
      extkeyType: 'extPrivkey',
    }).extkey;
  }
  const extkey = cfdjs.CreateExtkeyFromParentPath({
    extkey: mnemonicRootKey,
    extkeyType: 'extPubkey',
    path: bip32Path,
    network: mainchainNwType,
  });
  const pubkey = cfdjs.GetPubkeyFromExtkey({
    extkey: extkey.extkey,
    network: mainchainNwType,
  });
  return pubkey.pubkey;
}

interface KeyPair {
  pubkey: string;
  privkey: string;
}
function getKeyPairFromParent(bip32Path: string): KeyPair {
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  if (!mnemonicRootKey) {
    const seed = cfdjs.ConvertMnemonicToSeed({
      mnemonic: mnemonic.split(' '),
      passphrase: '',
    });
    mnemonicRootKey = cfdjs.CreateExtkeyFromSeed({
      seed: seed.seed,
      network: mainchainNwType,
      extkeyType: 'extPrivkey',
    }).extkey;
  }
  const extkey = cfdjs.CreateExtkeyFromParentPath({
    extkey: mnemonicRootKey,
    extkeyType: 'extPrivkey',
    path: bip32Path,
    network: mainchainNwType,
  });
  const privkey = cfdjs.GetPrivkeyFromExtkey({
    extkey: extkey.extkey,
    network: mainchainNwType,
    wif: false,
  });
  const pubkey = cfdjs.GetPubkeyFromExtkey({
    extkey: extkey.extkey,
    network: mainchainNwType,
  });
  return {pubkey: pubkey.pubkey, privkey: privkey.privkey};
}

async function execSign(liquidLib: LedgerLiquidWrapper, txHex: string,
    signUtxoList: WalletUtxoData[], mnemonicWords: string,
    ignoreVerify?: boolean): Promise<string> {
  let sigRet;
  let parentExtkey = '';
  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  if (!mnemonicWords) {
    // get authorization start ---------------------------------
    console.log('*** calc authorization start ***');
    const authorizationHash = cfdjs.SerializeLedgerFormat({
      tx: txHex,
      isAuthorization: true,
    });
    console.log('SerializeLedgerFormat =', authorizationHash);

    const authSig = cfdjs.CalculateEcSignature({
      sighash: authorizationHash.sha256,
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
    console.log(`*** calc authorization end. [${authDerSig}] ***`);
    // get authorization end ---------------------------------

    console.log('*** walletUtxoList ***', signUtxoList);
    console.log('*** getSignature start. ***');
    const startTime = Date.now();
    sigRet = await liquidLib.getSignature(txHex,
        signUtxoList, authDerSig);
    const endTime = Date.now();
    console.log(`*** getSignature end. ***`,
        JSON.stringify(sigRet, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value, '  '));
    console.log(`getSignature: ${(endTime - startTime)} msec`);
    if (!sigRet.success && continousCount) {
      throw new Error('getSignature fail.');
    }
  } else {
    const seed = cfdjs.ConvertMnemonicToSeed({
      mnemonic: mnemonicWords.split(' '),
      passphrase: '',
    });
    parentExtkey = cfdjs.CreateExtkeyFromSeed({
      seed: seed.seed,
      network: mainchainNwType,
      extkeyType: 'extPrivkey',
    }).extkey;

    console.log('*** walletUtxoList ***', signUtxoList);
    console.log('*** getSignature start. ***');
    const signatureList: SignatureData[] = [];
    for (const utxoData of signUtxoList) {
      const extkey = cfdjs.CreateExtkeyFromParentPath({
        extkey: parentExtkey,
        extkeyType: 'extPrivkey',
        network: mainchainNwType,
        path: utxoData.bip32Path,
      });
      const pubkey = cfdjs.GetPubkeyFromExtkey({
        extkey: extkey.extkey,
        network: mainchainNwType,
      });
      const privkey = cfdjs.GetPrivkeyFromExtkey({
        extkey: extkey.extkey,
        wif: false,
        isCompressed: false,
        network: mainchainNwType,
      });
      const descriptor = (utxoData.descriptor) ? utxoData.descriptor : '';
      const desc = cfdjs.ParseDescriptor({
        isElements: true,
        descriptor: descriptor,
        network: networkType,
      });
      let redeemScript = '';
      let signHashType = hashType;
      if ((desc.scripts) && (desc.scripts.length > 0)) {
        if ('redeemScript' in desc.scripts[desc.scripts.length - 1]) {
          const scriptRef = desc.scripts[desc.scripts.length - 1];
          redeemScript = (scriptRef.redeemScript) ? scriptRef.redeemScript : '';
        }
        signHashType = desc.scripts[0].hashType;
      }
      if (signHashType === 'p2sh-p2wpkh') {
        signHashType = 'p2wpkh';
      } else if (signHashType === 'p2sh-p2wsh') {
        signHashType = 'p2wsh';
      }
      const utxoAmount = (utxoData.amount) ? BigInt(utxoData.amount) : 0n;
      const sighash = cfdjs.CreateElementsSignatureHash({
        tx: txHex,
        txin: {
          txid: utxoData.txid,
          vout: utxoData.vout,
          hashType: signHashType,
          keyData: {
            hex: (!redeemScript) ? pubkey.pubkey : redeemScript,
            type: (!redeemScript) ? 'pubkey' : 'redeem_script',
          },
          amount: utxoAmount,
          confidentialValueCommitment: utxoData.valueCommitment,
        },
      });
      const signature = cfdjs.CalculateEcSignature({
        sighash: sighash.sighash,
        privkeyData: {
          privkey: privkey.privkey,
          wif: false,
        },
        isGrindR: true,
      });
      const derSig = cfdjs.EncodeSignatureByDer({
        signature: signature.signature,
        sighashType: 'all',
      });
      signatureList.push({
        utxoData: utxoData,
        signature: derSig.signature,
      });
    }
    sigRet = {
      signatureList: signatureList,
    };
    console.log(`*** getSignature end. ***`,
        JSON.stringify(sigRet, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value, '  '));
  }
  if (ignoreVerify) {
    return '';
  }

  const signatureList = [{
    txid: '',
    vout: 0,
    hashType: '',
    redeemScript: '',
    utxoData: signUtxoList[0],
    address: '',
    sigList: [{
      signature: '',
      pubkey: '',
    }],
    requireNum: 0,
  }];
  for (const signatureData of sigRet.signatureList) {
    const descriptor = (signatureData.utxoData.descriptor) ? signatureData.utxoData.descriptor : '';
    let desc;
    try {
      desc = cfdjs.ParseDescriptor({
        isElements: true,
        descriptor: descriptor,
        network: networkType,
      });
    } catch (e) {

    }
    let pubkeyData;
    if (!mnemonicWords) {
      const pubkeyRet = await liquidLib.getWalletPublicKey(
          signatureData.utxoData.bip32Path);
      if (!pubkeyRet.success && continousCount) {
        console.warn(pubkeyRet);
        throw new Error('getWalletPublicKey fail.');
      }
      pubkeyData = pubkeyRet.publicKey;
    } else {
      const extkey = cfdjs.CreateExtkeyFromParentPath({
        extkey: parentExtkey,
        extkeyType: 'extPubkey',
        network: mainchainNwType,
        path: signatureData.utxoData.bip32Path,
      });
      const pubkey = cfdjs.GetPubkeyFromExtkey({
        extkey: extkey.extkey,
        network: mainchainNwType,
      });
      pubkeyData = pubkey.pubkey;
    }
    let redeemScript = '';
    let sigHashType = hashType;
    let requireNum = 2;
    if ((desc) && (desc.scripts) && (desc.scripts.length > 0)) {
      if ('redeemScript' in desc.scripts[desc.scripts.length - 1]) {
        const scriptRef = desc.scripts[desc.scripts.length - 1];
        redeemScript = (scriptRef.redeemScript) ? scriptRef.redeemScript : '';
        requireNum = (scriptRef.reqNum) ? scriptRef.reqNum : requireNum;
      }
      sigHashType = desc.scripts[0].hashType;
    } else {
      // const sighashByte = Buffer.from(signatureData.signature, 'hex');
      redeemScript = (signatureData.utxoData.redeemScript) ? signatureData.utxoData.redeemScript : '';
      sigHashType = (!redeemScript) ? 'p2wpkh' : 'p2wsh';
    }
    let verifyHashType = sigHashType;
    if (verifyHashType === 'p2sh-p2wpkh') {
      verifyHashType = 'p2wpkh';
    } else if (verifyHashType === 'p2sh-p2wsh') {
      verifyHashType = 'p2wsh';
    }
    try {
      const rawSignatureRet = cfdjs.DecodeDerSignatureToRaw({
        signature: signatureData.signature,
      });
      const utxoAmount = (signatureData.utxoData.amount) ?
          BigInt(signatureData.utxoData.amount) : 0n;
      const verifySig = cfdjs.VerifySignature({
        tx: txHex,
        isElements: true,
        txin: {
          txid: signatureData.utxoData.txid,
          vout: signatureData.utxoData.vout,
          signature: rawSignatureRet.signature,
          pubkey: pubkeyData,
          redeemScript: redeemScript,
          hashType: verifyHashType,
          sighashType: 'all',
          amount: utxoAmount,
          confidentialValueCommitment: signatureData.utxoData.valueCommitment,
        },
      });
      console.log('verifySigRet =', verifySig);
    } catch (e) {
      console.log('verifySignature fail. =',
          JSON.stringify(signatureData, (key, value) =>
              typeof value === 'bigint' ? value.toString() : value, '  '));
      console.log(e);
    }
    let isFind = false;
    for (const sigTarget of signatureList) {
      if ((sigTarget.txid === signatureData.utxoData.txid) &&
        (sigTarget.vout === signatureData.utxoData.vout)) {
        sigTarget.sigList.push({
          signature: signatureData.signature,
          pubkey: pubkeyData,
        });
        isFind = true;
        break;
      }
    }
    if (!isFind) {
      signatureList.push({
        txid: signatureData.utxoData.txid,
        vout: signatureData.utxoData.vout,
        hashType: sigHashType,
        redeemScript: redeemScript,
        utxoData: signatureData.utxoData,
        address: (desc && desc.address) ? desc.address : '',
        sigList: [{
          signature: signatureData.signature,
          pubkey: pubkeyData,
        }],
        requireNum: requireNum,
      });
    }
  }
  let tx = txHex;
  const signTxins = [];
  for (const sigData of signatureList) {
    if (!sigData.txid) continue;
    if (!sigData.address) continue;
    const utxoAmount = (sigData.utxoData.amount) ?
        BigInt(sigData.utxoData.amount) : 0n;
    let signedTx;
    if (!sigData.redeemScript) {
      signedTx = cfdjs.AddPubkeyHashSign({
        tx: tx,
        isElements: true,
        txin: {
          txid: sigData.txid,
          vout: sigData.vout,
          signParam: {
            hex: sigData.sigList[0].signature,
            derEncode: false,
          },
          pubkey: sigData.sigList[0].pubkey,
          hashType: sigData.hashType,
        },
      });
    } else {
      const jsonParam = {
        tx: tx,
        isElements: true,
        txin: {
          txid: sigData.txid,
          vout: sigData.vout,
          signParams: [
            {
              hex: sigData.sigList[0].signature,
              derEncode: false,
              relatedPubkey: sigData.sigList[0].pubkey,
            },
          ],
          redeemScript: (sigData.hashType === 'p2sh') ? sigData.redeemScript : '',
          witnessScript: (sigData.hashType === 'p2sh') ? '' : sigData.redeemScript,
          hashType: sigData.hashType,
        },
      };
      for (let i = 1; i < sigData.requireNum; ++i) {
        jsonParam.txin.signParams.push({
          hex: sigData.sigList[i].signature,
          derEncode: false,
          relatedPubkey: sigData.sigList[i].pubkey,
        });
      }
      // console.log('jsonParam => ', JSON.stringify(jsonParam, null, '  '));
      signedTx = cfdjs.AddMultisigSign(jsonParam);
    }
    signTxins.push({
      txid: sigData.txid,
      vout: sigData.vout,
      address: sigData.address,
      amount: utxoAmount,
      descriptor: sigData.utxoData.descriptor,
      confidentialValueCommitment: sigData.utxoData.valueCommitment,
    });
    tx = signedTx.hex;
    if (signedTest) {
      console.log('*** sign tx ***\n', tx);
    }
  }
  const reqVerifyJson = {
    tx: tx,
    isElements: true,
    txins: signTxins,
  };
  if (signTxins.length > 0) {
    const verifyRet = cfdjs.VerifySign(reqVerifyJson);
    console.log('\n*** VerifySign ***\n', JSON.stringify(verifyRet, null, '  '));
  }

  return tx;
}

async function signTest() {
  // parse signTarget -> WalletUtxoData
  const utxoList = signTarget.split(' ');
  const utxoDataList: WalletUtxoData[] = [];
  for (const utxoText of utxoList) {
    const infoList = utxoText.split(':');
    utxoDataList.push({
      bip32Path: infoList[0],
      txid: infoList[1],
      vout: parseInt(infoList[2]),
      amount: (infoList[3].length === 66) ? 0n : BigInt(infoList[3]),
      valueCommitment: (infoList[3].length === 66) ? infoList[3] : '',
      descriptor: infoList[4],
    });
  }

  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const tx = await execSign(liquidLib, txData, utxoDataList, '');
  console.log('*** signed tx ***\n', tx);
  if (mnemonic) {
    const tx = await execSign(liquidLib, txData, utxoDataList, mnemonic);
    console.log('*** mnemonic signed tx ***\n', tx);
  }
  await liquidLib.disconnect();
}

let isConnectCheck = false;
async function checkConnecting(lib: LedgerLiquidWrapper) {
  if (isConnectCheck) {
    const connCheckRet = await lib.isConnected();
    const accessing = lib.isAccessing();
    if (connCheckRet.success) {
      console.log(`isConnected : connect, accessing=${accessing}`);
    } else if (connCheckRet.disconnect) {
      console.log(`isConnected : disconnect, accessing=${accessing}`);
    } else {
      console.log('isConnected fail: ', connCheckRet);
    }
    setTimeout(async () => {
      await checkConnecting(lib);
    }, 1000);
  }
}

async function checkConnectingQuick(lib: LedgerLiquidWrapper) {
  if (isConnectCheck) {
    const connCheckRet = await lib.isConnected();
    const accessing = lib.isAccessing();
    if (connCheckRet.success) {
      console.log(`isConnected : connect, accessing=${accessing}`);
    } else if (connCheckRet.disconnect) {
      console.log(`isConnected : disconnect, accessing=${accessing}`);
    } else {
      console.log('isConnected fail: ', connCheckRet);
    }
    setTimeout(async () => {
      await checkConnectingQuick(lib);
    }, 200);
  }
}

let isDumpSignature = false;
let lastState = '';
let pastAccessTime = 0;
async function dumpSignatureProgress(lib: LedgerLiquidWrapper) {
  const result = lib.getSignatureState();
  const cur = new Date();
  const hour = (cur.getHours() > 9) ? cur.getHours() : ('0' + cur.getHours());
  const min = (cur.getMinutes() > 9) ? cur.getMinutes() : ('0' + cur.getMinutes());
  const sec = (cur.getSeconds() > 9) ? cur.getSeconds() : ('0' + cur.getSeconds());
  const msec = (cur.getMilliseconds() > 99) ? cur.getMilliseconds() :
      (cur.getMilliseconds() > 9) ? ('0' + cur.getMilliseconds()) :
          ('00' + cur.getMilliseconds());
  const timeStr = `[${hour}:${min}:${sec}.${msec}]`;
  if (result.success) {
    let prog: ProgressInfo = {current: 0, total: 0};
    switch (result.currentState) {
      case GetSignatureState.AnalyzeUtxo:
        prog = result.analyzeUtxo;
        break;
      case GetSignatureState.InputTx:
        prog = result.inputTx;
        break;
      case GetSignatureState.GetSignature:
        prog = result.getSignature;
        break;
      default:
        break;
    }
    if (result.errorMessage === 'not execute.') {
      if (lastState !== result.errorMessage) {
        console.log(`${timeStr} getSignatureState:`, result);
        lastState = result.errorMessage;
      }
    } else {
      const state = `${result.currentState}: ${prog.current}/${prog.total}`;
      if (lastState !== state) {
        console.log(`${timeStr} getSignatureState(${state})`);
      } else if (pastAccessTime !== result.lastAccessTime) {
        console.log(`${timeStr} getSignatureState(${state}): time[${result.lastAccessTime}]`);
      }
      lastState = state;
      pastAccessTime = result.lastAccessTime;
    }
  } else if (!isDumpSignature) {
    console.log(`${timeStr} getSignatureState:`, result);
  } else if (lastState !== result.errorMessage) {
    console.log(`${timeStr} getSignatureState:`, result);
    lastState = result.errorMessage;
  }
  if (isDumpSignature) {
    setTimeout(async () => {
      await dumpSignatureProgress(lib);
    }, 500);
  }
}

let multiAccessTestCount = 0;
async function multiAccessTest(lib: LedgerLiquidWrapper) {
  if (multiAccessTestCount === 0) {
    const pubkeyRet = await lib.getWalletPublicKey('44h/0h/0h');
    console.log('async getWalletPublicKey:', pubkeyRet);
    setTimeout(async () => {
      await multiAccessTest(lib);
    }, 5000);
  } else if (multiAccessTestCount === 1) {
    const xpubkeyRet = await lib.getXpubKey('44h/0h/0h');
    console.log('async getXpubKey:', xpubkeyRet);
  }
  multiAccessTestCount++;
}

async function cancelWaiting(lib: LedgerLiquidWrapper) {
  if (currentWaitCancelCount) {
    --currentWaitCancelCount;
    if (currentWaitCancelCount) {
      setTimeout(async () => {
        await cancelWaiting(lib);
      }, 1000);
    } else {
      lib.cancelConnect();
      console.log('cancel waiting.');
    }
  }
}

async function testNotifyFunction(state: UsbDetectionType,
    device: Device) {
  console.log('notify: ', state, ' device:', device);
  await sleep(100);
}

async function execConnectionTest() {
  // connect wait test
  const liquidLib = new LedgerLiquidWrapper(networkType);
  if (waitCancelCount) {
    currentWaitCancelCount = waitCancelCount;
    setTimeout(async () => {
      await cancelWaiting(liquidLib);
    }, 1000);
  }
  const devListResult = await LedgerLiquidWrapper.getDeviceList();
  if (devListResult.success) {
    for (const desc of devListResult.deviceList) {
      console.log('connect device :', desc);
    }
  } else {
    console.log('getDeviceList error. ', devListResult);
  }

  LedgerLiquidWrapper.startUsbDetectMonitoring();
  LedgerLiquidWrapper.registerUsbDetectListener(
      testNotifyFunction);
  let connRet = await liquidLib.connect(60, connectDevice);
  if (!connRet.success) {
    console.log('connection fail.(1)', connRet);
    LedgerLiquidWrapper.finishUsbDetectMonitoring();
    return;
  }
  if (asyncConnectCheck) {
    isConnectCheck = true;
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
    setTimeout(async () => {
      await checkConnectingQuick(liquidLib);
    }, 200);
  }
  console.log('current application:', liquidLib.getCurrentApplication());
  console.log('last connect info  :', liquidLib.getLastConnectionInfo());
  for (let connTestCount = 0; connTestCount < 120; ++connTestCount) {
    const connCheckRet = await liquidLib.isConnected();
    if (connCheckRet.success) {
      console.log('10 sec wait start.');
      await sleep(10000);
      console.log('10 sec wait end.');
      connTestCount += 10;
      if (reconnectTest) {
        console.log('exec connect.');
        connRet = await liquidLib.connect(0, connectDevice);
        console.log('connect result:', connRet);
      }
    } else if (connCheckRet.errorMessage === 'connection fail.') {
      console.log('disconnect. start reconnection.');
      connRet = await liquidLib.connect(60, connectDevice);
      if (!connRet.success) {
        console.log('connection fail. ', connRet);
        break;
      }
      console.log('reconnect success.');
      console.log('current application:', liquidLib.getCurrentApplication());
      console.log('last connect info  :', liquidLib.getLastConnectionInfo());
    } else {
      console.log('isConnected fail.(2)', connCheckRet);
      break;
    }
    await sleep(1000);
  }
  await liquidLib.disconnect();
  LedgerLiquidWrapper.finishUsbDetectMonitoring();
}

async function execMonitoringConnectionTest() {
  const liquidLib = new LedgerLiquidWrapper(networkType);
  let isError = false;
  const checkAndConnect = async function() {
    console.log('reconnect start.');
    const connRet = await liquidLib.connect(0, connectDevice);
    if (!connRet.success) {
      console.log('connection fail.', connRet);
      if (connRet.disconnect) {
        console.log('wait connecting...');
      } else {
        isError = true;
      }
    } else {
      console.log('reconnect success.');
      console.log('current application:', liquidLib.getCurrentApplication());
      console.log('last connect info  :', liquidLib.getLastConnectionInfo());
    }
  };
  const checkConnect = async function() {
    const connCheckRet = await liquidLib.isConnected();
    if (connCheckRet.success) {
      // do nothing
    } else if (connCheckRet.errorMessage === 'connection fail.') {
      console.log('disconnect. wait connecting...');
    } else {
      console.log('isConnected fail.(3)', connCheckRet);
      // throw new Error('connection fail.');
      isError = true;
    }
  };
  const testMonitoringNotify = async function(
      state: UsbDetectionType, device: Device) {
    console.log('notify: ', state, ' device:', device);
    if (state == UsbDetectionType.Add) {
      setTimeout(async () => {
        checkAndConnect();
      }, 200);
    } else if (state == UsbDetectionType.Remove) {
      setTimeout(async () => {
        checkConnect();
      }, 200);
    }
  };

  const devListResult = await LedgerLiquidWrapper.getDeviceList();
  if (devListResult.success) {
    for (const desc of devListResult.deviceList) {
      console.log('connect device :', desc);
    }
  } else {
    console.log('getDeviceList error. ', devListResult);
  }

  LedgerLiquidWrapper.startUsbDetectMonitoring();
  LedgerLiquidWrapper.registerUsbDetectListener(testMonitoringNotify);
  const connRet = await liquidLib.connect(60, connectDevice);
  if (!connRet.success) {
    console.log('connection fail.(1)', connRet);
    return;
  }
  console.log('current application:', liquidLib.getCurrentApplication());
  console.log('last connect info  :', liquidLib.getLastConnectionInfo());
  for (let connTestCount = 0; connTestCount < 60; ++connTestCount) {
    if (isError) break;
    await sleep(1000);
  }
  if (isError) {
    console.log('connection fail on error.');
  }
  await liquidLib.disconnect();
  LedgerLiquidWrapper.finishUsbDetectMonitoring();
}

async function example() {
  const addrType = AddressType.Bech32;

  const asset1 = '5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225';

  if (tx2InputCount < 2) {
    tx2InputCount = 2;
  }
  if (!getLedgerPath && !mnemonic) {
    getLedgerPath = true;
  }

  // connect wait test
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    if (continousCount) {
      throw new Error('connect fail.');
    }
    return;
  }
  console.log('current application:', liquidLib.getCurrentApplication());
  const fwVer = await liquidLib.getApplicationInfo();
  console.log('firmware version:', fwVer);
  if (!fwVer.success && continousCount) {
    throw new Error('getApplicationInfo fail.');
  }
  console.log('last connect info  :', liquidLib.getLastConnectionInfo());

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const parentPath = '44\'/0\'/0\'/0';
  const childNumber = 0;
  const childPath = parentPath + '/' + childNumber;
  const parentPubkey = await liquidLib.getWalletPublicKey(parentPath);
  console.log('parentPubkey -> ', parentPubkey);
  if (!parentPubkey.success && continousCount) {
    throw new Error('getWalletPublicKey fail.');
  }

  const extkey = cfdjs.CreateExtkeyFromParentKey({
    network: mainchainNwType,
    parentKey: parentPubkey.publicKey,
    parentDepth: 4,
    parentChainCode: parentPubkey.chainCode,
    childNumber: childNumber,
  });
  console.log('childExtkey =', extkey);
  const keyInfo = cfdjs.GetExtkeyInfo(extkey);
  console.log('childExtkeyInfo =', keyInfo);

  const xpub = await liquidLib.getXpubKey('44\'/0\'/0\'');
  console.log('getXpubKey =', xpub);
  if (!xpub.success && continousCount) {
    throw new Error('getXpubKey fail.');
  }

  const xpub2 = await liquidLib.getXpubKey('m/44\'/0\'/0\'');
  console.log('getXpubKey2 =', xpub2);
  if (!xpub2.success && continousCount) {
    throw new Error('getXpubKey fail.');
  }

  const legacyLockingScript = liquidLib.getPublicKeyRedeemScript(
      parentPubkey.publicKey);
  console.log('legacyLockingScript =', legacyLockingScript);

  const addrData = await liquidLib.getAddress('m/44\'/0\'/0\'', addrType);
  console.log('getAddress =', addrData);
  if (!addrData.success && continousCount) {
    throw new Error('getAddress fail.');
  }

  let directMnemonic = false;
  if (mnemonic) {
    const mnemonicExtPubkey = getExtKeyFromParent(childPath);
    if (extkey.extkey !== mnemonicExtPubkey) {
      if (mnemonicCheck) {
        console.log('unmatch mnemonic. extPubkey =', mnemonicExtPubkey);
        return;
      }
      directMnemonic = true;
    }
  }

  interface PubkeySet {
    bip32Path: string;
    pubkey: string;
  }
  interface PathData {
    bip32Path: string;
    pubkey: string;
    pubkeyList: PubkeySet[];
    address: string;
    descriptor: string;
    confidentialAddress: string;
    blindingKeyPair: KeyPair;
    issuanceData: cfdjs.IssuanceDataResponse[];
    vout: number;
    amount: bigint;
    valueCommitment: string;
    abf: string;
    vbf: string;
  };
  const pathList: PathData[] = [];
  const dummyPathList: PathData[] = [];
  const reissuePathList: PathData[] = [];
  const reissueTokenPathList: PathData[] = [];
  const issuePathList: PathData[] = [];
  const issueTokenPathList: PathData[] = [];
  if (tx2InputCount < setIssueTx) {
    tx2InputCount = setIssueTx;
  }
  const maxPathCnt = tx2InputCount + setReissueTx * 3 + setIssueTx * 2;
  for (let i = 0; i < maxPathCnt; ++i) {
    const childPath = parentPath + '/' + i;
    const blindingKeyPair = getKeyPairFromParent(childPath + '/0/0');
    const pathData = {
      bip32Path: childPath,
      pubkey: '',
      pubkeyList: [],
      address: '',
      confidentialAddress: '',
      descriptor: '',
      blindingKeyPair: blindingKeyPair,
      issuanceData: [],
      vout: -1,
      amount: 0n,
      valueCommitment: '',
      abf: '',
      vbf: '',
    };
    if (i < tx2InputCount) {
      pathList.push(pathData);
    } else if ((setReissueTx > 0) && i < tx2InputCount + setReissueTx) {
      dummyPathList.push(pathData);
    } else if ((setReissueTx > 0) && i < tx2InputCount + (setReissueTx * 2)) {
      reissuePathList.push(pathData);
    } else if ((setReissueTx > 0) && i < tx2InputCount + (setReissueTx * 3)) {
      reissueTokenPathList.push(pathData);
    } else {
      if (issuePathList.length < setIssueTx) {
        issuePathList.push(pathData);
      } else {
        issueTokenPathList.push(pathData);
      }
    }
  }

  const allList = [pathList, dummyPathList, reissuePathList,
    reissueTokenPathList, issuePathList, issueTokenPathList];
  for (const list of allList) {
    for (const data of list) {
      if (getLedgerPath) {
        const pubkey = await liquidLib.getWalletPublicKey(data.bip32Path);
        data.pubkey = pubkey.publicKey;
        if (hashType.indexOf('p2wsh') >= 0) {
          const pubkey1 = await liquidLib.getWalletPublicKey(data.bip32Path + '/0');
          const pubkey2 = await liquidLib.getWalletPublicKey(data.bip32Path + '/1');
          const pubkey3 = await liquidLib.getWalletPublicKey(data.bip32Path + '/2');
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/0',
            pubkey: pubkey1.publicKey,
          });
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/1',
            pubkey: pubkey2.publicKey,
          });
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/2',
            pubkey: pubkey3.publicKey,
          });
        }
      } else {
        data.pubkey = getPubkeyFromParent(data.bip32Path);
        if (hashType.indexOf('p2wsh') >= 0) {
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/0',
            pubkey: getPubkeyFromParent(data.bip32Path + '/0'),
          });
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/1',
            pubkey: getPubkeyFromParent(data.bip32Path + '/1'),
          });
          data.pubkeyList.push({
            bip32Path: data.bip32Path + '/2',
            pubkey: getPubkeyFromParent(data.bip32Path + '/2'),
          });
        }
      }
      if (hashType.indexOf('p2wsh') >= 0) {
        const addr = cfdjs.CreateMultisig({
          isElements: true,
          hashType: hashType,
          network: networkType,
          nrequired: 2,
          keys: [
            data.pubkeyList[0].pubkey,
            data.pubkeyList[1].pubkey,
            data.pubkeyList[2].pubkey,
          ],
        });
        data.address = addr.address;
        data.descriptor = 'wsh(multi(2,' + data.pubkeyList[0].pubkey +
            ',' + data.pubkeyList[1].pubkey + ',' +
            data.pubkeyList[2].pubkey + '))';
        if (hashType === 'p2sh-p2wsh') {
          data.descriptor = `sh(${data.descriptor})`;
        }
      } else {
        const addr = cfdjs.CreateAddress({
          isElements: true,
          hashType: hashType,
          network: networkType,
          keyData: {
            hex: data.pubkey,
            type: 'pubkey',
          },
        });
        data.address = addr.address;
        data.descriptor = `wpkh(${data.pubkey})`;
        if (hashType === 'p2sh-p2wpkh') {
          data.descriptor = `sh(${data.descriptor})`;
        }
      }
      const ctAddr = cfdjs.GetConfidentialAddress({
        unblindedAddress: data.address,
        key: data.blindingKeyPair.pubkey,
      });
      data.confidentialAddress = ctAddr.confidentialAddress;
      console.log(`addr(${data.bip32Path}) =`, data.address);
    }
  }

  const tx1InputCount = 1 + setReissueTx;
  const dummyTxid1 = '7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd';
  const empty256 = '0000000000000000000000000000000000000000000000000000000000000000';
  const inputAmount = 5000000n;
  const inputAmount2 = 5000000n;
  const tx1Data = {
    version: 2,
    locktime: 0,
    txins: [{
      txid: dummyTxid1,
      vout: 0,
      sequence: 4294967295,
    }],
    txouts: [{
      address: pathList[0].address,
      amount: inputAmount,
      asset: asset1,
    }],
    fee: {
      amount: 50000n,
      asset: asset1,
    },
  };
  if (tx1InputCount > 1) {
    for (let i = 1; i < tx1InputCount; ++i) {
      tx1Data.txins.push({
        txid: dummyTxid1,
        vout: i,
        sequence: 4294967295,
      });
    }
  }
  if (pathList.length > 1) {
    for (let i = 1; i < pathList.length; ++i) {
      const pathData = pathList[i];
      tx1Data.txouts.push({
        address: pathData.address,
        amount: inputAmount2,
        asset: asset1,
      });
    }
    if (dummyPathList.length > 0) {
      for (let i = 1; i < dummyPathList.length; ++i) {
        const pathData = dummyPathList[i];
        tx1Data.txouts.push({
          address: pathData.address,
          amount: inputAmount2,
          asset: asset1,
        });
      }
    }
  }
  let tx1;
  try {
    tx1 = cfdjs.ElementsCreateRawTransaction(tx1Data);
  } catch (e) {
    console.log(tx1Data);
    throw e;
  }

  if (setReissueTx > 0) {
    for (let i = 0; i < reissuePathList.length; ++i) {
      const pathData = reissuePathList[i];
      const tokenPathData = reissueTokenPathList[i];
      const issueRet = cfdjs.SetRawIssueAsset({
        tx: tx1.hex,
        issuances: [{
          txid: tx1Data.txins[i + 1].txid,
          vout: tx1Data.txins[i + 1].vout,
          assetAmount: inputAmount2,
          assetAddress: pathData.confidentialAddress,
          tokenAmount: inputAmount2,
          tokenAddress: tokenPathData.confidentialAddress,
          contractHash: testContractHash,
          isRemoveNonce: false,
          isBlind: true,
        }],
        isRandomSortTxOut: false,
      });
      tokenPathData.issuanceData.push({
        txid: issueRet.issuances[0].txid,
        vout: issueRet.issuances[0].vout,
        asset: issueRet.issuances[0].asset,
        entropy: issueRet.issuances[0].entropy,
        token: issueRet.issuances[0].token,
      });
      tx1.hex = issueRet.hex;
    }
    // console.log('issueTx =', tx1.hex);
  }
  if (blindOpt.blind1) {
    if (signedTest) {
      console.log('*** before blind rawtx1 ***\n', tx1.hex);
    }
    const blind1Data: cfdjs.BlindRawTransactionRequest = {
      tx: tx1.hex,
      txins: [{
        txid: tx1Data.txins[0].txid,
        vout: tx1Data.txins[0].vout,
        asset: asset1,
        blindFactor: empty256,
        assetBlindFactor: empty256,
        amount: inputAmount,
      }],
      txoutConfidentialAddresses: [],
      issuances: [],
    };
    if (setReissueTx > 0 && blind1Data.txins && blind1Data.issuances) {
      for (let i = 0; i < reissuePathList.length; ++i) {
        const pathData = reissuePathList[i];
        const tokenPathData = reissueTokenPathList[i];
        blind1Data.txins.push({
          txid: dummyTxid1,
          vout: i + 1,
          asset: asset1,
          blindFactor: empty256,
          assetBlindFactor: empty256,
          amount: inputAmount,
        });
        blind1Data.issuances.push({
          txid: dummyTxid1,
          vout: i + 1,
          assetBlindingKey: pathData.blindingKeyPair.privkey,
          tokenBlindingKey: tokenPathData.blindingKeyPair.privkey,
        });
      }
    }
    if (blind1Data.txoutConfidentialAddresses) {
      for (let i = 0; i < pathList.length; ++i) {
        const pathData = pathList[i];
        blind1Data.txoutConfidentialAddresses.push(
            pathData.confidentialAddress);
      }
      for (let i = 0; i < dummyPathList.length; ++i) {
        const pathData = dummyPathList[i];
        blind1Data.txoutConfidentialAddresses.push(
            pathData.confidentialAddress);
      }
      for (let i = 0; i < reissuePathList.length; ++i) {
        const issuePathData = reissuePathList[i];
        blind1Data.txoutConfidentialAddresses.push(
            issuePathData.confidentialAddress);
      }
      for (let i = 0; i < reissueTokenPathList.length; ++i) {
        const tokenPathData = reissueTokenPathList[i];
        blind1Data.txoutConfidentialAddresses.push(
            tokenPathData.confidentialAddress);
      }
    }
    tx1 = cfdjs.BlindRawTransaction(blind1Data);
  }
  if (signedTest) {
    console.log('*** rawtx1 (ignore sign) ***\n', tx1.hex);
  }
  const dectx1 = cfdjs.ElementsDecodeRawTransaction({
    hex: tx1.hex, network: networkType,
    mainchainNetwork: mainchainNwType});
  console.log('*** blind dectx1 ***\n', JSON.stringify(dectx1, null, '  '));

  // set utxo data
  if (dectx1.vout) {
    const unblindTxoutList: cfdjs.UnblindTxOut[] = [];
    const utxoPathList = [pathList, reissueTokenPathList];
    for (const txout of dectx1.vout) {
      const addr = (txout.scriptPubKey && txout.scriptPubKey.addresses) ?
          txout.scriptPubKey.addresses[0] : '';
      if (!addr) continue;
      for (const list of utxoPathList) {
        let isFind = false;
        for (const pathData of list) {
          if (pathData.address === addr) {
            pathData.vout = txout.n;
            if (txout.valuecommitment) {
              pathData.valueCommitment = txout.valuecommitment;
            }
            pathData.amount = inputAmount;
            unblindTxoutList.push({
              index: txout.n,
              blindingKey: pathData.blindingKeyPair.privkey,
            });
            isFind = true;
            break;
          }
        }
        if (isFind) break;
      }
    }
    const unblindData = cfdjs.UnblindRawTransaction({
      tx: tx1.hex,
      txouts: unblindTxoutList,
    });
    if (unblindData.outputs) {
      for (const data of unblindData.outputs) {
        for (const list of utxoPathList) {
          let isFind = false;
          for (const pathData of list) {
            if (pathData.vout === data.index) {
              pathData.abf = data.assetBlindFactor;
              pathData.vbf = data.blindFactor;
              isFind = true;
              break;
            }
          }
          if (isFind) break;
        }
      }
    }
  }

  const tx2Data = {
    version: 2,
    locktime: 0,
    txins: [{
      txid: dectx1.txid,
      vout: pathList[0].vout,
      sequence: 0xffffffff,
    }],
    txouts: [{
      address: pathList[0].address,
      amount: pathList[0].amount,
      asset: asset1,
    }],
    fee: {
      amount: 50000n,
      asset: asset1,
    },
  };
  const blindReqData: cfdjs.BlindRawTransactionRequest = {
    tx: '',
    txins: [{
      txid: dectx1.txid,
      vout: pathList[0].vout,
      amount: pathList[0].amount,
      asset: asset1,
      assetBlindFactor: pathList[0].abf,
      blindFactor: pathList[0].vbf,
    }],
    txoutConfidentialAddresses: [pathList[0].confidentialAddress],
    issuances: [],
  };
  let totalAsset = 0n;
  let startOffset = 1;
  if ((setReissuanceToTop > setIssuanceToTop) &&
      (reissuePathList.length > 0)) {
    startOffset = 0;
    tx2Data.txins = [];
    blindReqData.txins = [];
    for (let i = 0; i < reissueTokenPathList.length; ++i) {
      const pathData = reissueTokenPathList[i];
      tx2Data.txins.push({
        txid: dectx1.txid,
        vout: pathData.vout,
        sequence: 0xffffffff,
      });
      totalAsset += pathData.amount;
      if (blindReqData.txins) {
        const asset =
          (pathData.issuanceData && pathData.issuanceData[0]) ?
            pathData.issuanceData[0].token : asset1;
        blindReqData.txins.push({
          txid: dectx1.txid,
          vout: pathData.vout,
          amount: pathData.amount,
          asset: (asset) ? asset : asset1,
          assetBlindFactor: pathData.abf,
          blindFactor: pathData.vbf,
        });
        if (blindReqData.issuances) {
          blindReqData.issuances.push({
            txid: dectx1.txid,
            vout: pathData.vout,
            assetBlindingKey: pathData.blindingKeyPair.privkey,
            tokenBlindingKey: pathData.blindingKeyPair.privkey,
          });
        }
      }
    }
  }
  if (pathList.length > 0 && tx2Data.txins) {
    for (let i = startOffset; i < pathList.length; ++i) {
      const pathData = pathList[i];
      tx2Data.txins.push({
        txid: dectx1.txid,
        vout: pathData.vout,
        sequence: 0xffffffff,
      });
      totalAsset += pathData.amount;
      if (blindReqData.txins) {
        const asset =
          (pathData.issuanceData && pathData.issuanceData[0]) ?
            pathData.issuanceData[0].token : asset1;
        blindReqData.txins.push({
          txid: dectx1.txid,
          vout: pathData.vout,
          amount: pathData.amount,
          asset: (asset) ? asset : asset1,
          assetBlindFactor: pathData.abf,
          blindFactor: pathData.vbf,
        });
      }
    }
    if ((setReissuanceToTop <= setIssuanceToTop)) {
      for (let i = 0; i < reissueTokenPathList.length; ++i) {
        const pathData = reissueTokenPathList[i];
        tx2Data.txins.push({
          txid: dectx1.txid,
          vout: pathData.vout,
          sequence: 0xffffffff,
        });
        totalAsset += pathData.amount;
        if (blindReqData.txins) {
          const asset =
            (pathData.issuanceData && pathData.issuanceData[0]) ?
              pathData.issuanceData[0].token : asset1;
          blindReqData.txins.push({
            txid: dectx1.txid,
            vout: pathData.vout,
            amount: pathData.amount,
            asset: (asset) ? asset : asset1,
            assetBlindFactor: pathData.abf,
            blindFactor: pathData.vbf,
          });
          if (blindReqData.issuances) {
            blindReqData.issuances.push({
              txid: dectx1.txid,
              vout: pathData.vout,
              assetBlindingKey: pathData.blindingKeyPair.privkey,
              tokenBlindingKey: pathData.blindingKeyPair.privkey,
            });
          }
        }
      }
    }
  }
  if (pathList.length > 0 && tx2Data.txouts) {
    tx2Data.txouts.push({
      address: pathList[1].address,
      amount: totalAsset - tx2Data.fee.amount,
      asset: asset1,
    });
    if (blindReqData.txoutConfidentialAddresses) {
      blindReqData.txoutConfidentialAddresses.push(
          pathList[1].confidentialAddress);
    }
  }
  if (reissueTokenPathList.length > 0 && tx2Data.txouts) {
    for (let i = 0; i < reissueTokenPathList.length; ++i) {
      if (reissueTokenPathList[i].issuanceData.length > 0 &&
        reissueTokenPathList[i].issuanceData[0]) {
        const token = reissueTokenPathList[i].issuanceData[0].token;
        tx2Data.txouts.push({
          address: reissueTokenPathList[i].address,
          amount: reissueTokenPathList[i].amount,
          asset: (token) ? token : '',
        });
        if (blindReqData.txoutConfidentialAddresses) {
          blindReqData.txoutConfidentialAddresses.push(
              reissueTokenPathList[i].confidentialAddress);
        }
      }
    }
  }
  const tx2 = cfdjs.ElementsCreateRawTransaction(tx2Data);

  let blindTx2 = tx2;
  const issueList = [];
  if (setIssueTx) {
    let cnt = 0;
    const startIdx = (!setIssuanceToTop) ?
        pathList.length - issuePathList.length : 0;
    const maxIndex = (!setIssuanceToTop) ?
        pathList.length : issuePathList.length;
    for (let i = startIdx; i < maxIndex; ++i) {
      const pathData = issuePathList[cnt];
      const tokenData = issueTokenPathList[cnt];
      issueList.push({
        txid: dectx1.txid,
        vout: pathList[i].vout,
        assetAmount: inputAmount2,
        assetAddress: pathData.confidentialAddress,
        tokenAmount: inputAmount2,
        tokenAddress: tokenData.confidentialAddress,
        contractHash: testContractHash,
        isBlind: true,
      });
      pathData.issuanceData.push({
        txid: dectx1.txid,
        vout: pathList[i].vout,
        asset: '',
        entropy: '',
        token: '',
      });
      if (blindReqData.issuances) {
        blindReqData.issuances.push({
          txid: dectx1.txid,
          vout: pathList[i].vout,
          assetBlindingKey: pathData.blindingKeyPair.privkey,
          tokenBlindingKey: tokenData.blindingKeyPair.privkey,
        });
      }
      if (blindReqData.txoutConfidentialAddresses) {
        blindReqData.txoutConfidentialAddresses.push(
            pathData.confidentialAddress);
        blindReqData.txoutConfidentialAddresses.push(
            tokenData.confidentialAddress);
      }
      ++cnt;
    }
    try {
      const issueRet = cfdjs.SetRawIssueAsset({
        tx: blindTx2.hex,
        issuances: issueList,
        isRandomSortTxOut: false,
      });
      blindTx2 = issueRet;
      if (issueRet.issuances) {
        for (const issueData of issueRet.issuances) {
          for (const pathData of issuePathList) {
            if (pathData.issuanceData &&
              (pathData.issuanceData[0].txid === issueData.txid) &&
              (pathData.issuanceData[0].vout === issueData.vout)) {
              pathData.issuanceData[0].asset = issueData.asset;
              pathData.issuanceData[0].token = issueData.token;
              pathData.issuanceData[0].entropy = issueData.entropy;
            }
          }
        }
      }
    } catch (e) {
      console.log(issueList);
      throw e;
    }
  }
  console.log('*** tx2 ***\n', tx2);

  if (blindOpt.blind2) {
    if (reissueTokenPathList.length > 0 && tx2Data.txouts) {
      const issuanceList: cfdjs.ReissuanceDataRequest[] = [];
      for (let i = 0; i < reissueTokenPathList.length; ++i) {
        if (reissueTokenPathList[i].issuanceData.length > 0 &&
          reissueTokenPathList[i].issuanceData[0]) {
          issuanceList.push({
            txid: dectx1.txid,
            vout: reissueTokenPathList[i].vout,
            amount: inputAmount2,
            address: reissuePathList[i].confidentialAddress,
            assetBlindingNonce: reissueTokenPathList[i].abf,
            assetEntropy: reissueTokenPathList[i].issuanceData[0].entropy,
          });
        }
      }
      try {
        const reissueRet = cfdjs.SetRawReissueAsset({
          tx: blindTx2.hex,
          issuances: issuanceList,
          isRandomSortTxOut: false,
        });
        blindTx2 = reissueRet;
      } catch (e) {
        console.log(issuanceList);
        throw e;
      }
    }
    console.log('*** before blind tx2 ***\n', blindTx2);
    console.log('*** blindInfo ***\n',
        JSON.stringify(blindReqData, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value, '  '));
    blindReqData.tx = blindTx2.hex;
    blindTx2 = cfdjs.BlindRawTransaction(blindReqData);
  }
  if (signedTest) {
    console.log('*** blind rawtx2 ***\n', blindTx2.hex);
  }

  // console.log('*** Blind ***\n', tx2);
  const dectx2 = cfdjs.ElementsDecodeRawTransaction({
    hex: blindTx2.hex, network: networkType,
    mainchainNetwork: mainchainNwType});
  console.log('*** blind dectx2 ***\n', JSON.stringify(dectx2, null, '  '));

  if (!dectx2.vin) {
    return;
  }
  const walletUtxoList: WalletUtxoData[] = [];
  for (const num of signTargetIndex) {
    if (num >= dectx2.vin.length) {
      continue;
    }
    const i = num;
    const txin = dectx2.vin[i];
    let isFind = false;
    const txid = dectx1.txid;
    const utxoList = [pathList, reissueTokenPathList];
    for (const list of utxoList) {
      for (const data of list) {
        if (data.vout == txin.vout) {
          if (data.pubkeyList.length > 0) {
            for (const pubkeyData of data.pubkeyList) {
              walletUtxoList.push({
                bip32Path: pubkeyData.bip32Path,
                txid: txid,
                vout: txin.vout,
                amount: data.amount,
                valueCommitment: data.valueCommitment,
                redeemScript: '',
                descriptor: data.descriptor,
              });
            }
          } else {
            walletUtxoList.push({
              bip32Path: data.bip32Path,
              txid: txid,
              vout: txin.vout,
              amount: data.amount,
              valueCommitment: data.valueCommitment,
              redeemScript: '',
              descriptor: data.descriptor,
            });
          }
          isFind = true;
          break;
        }
      }
      if (isFind) continue;
    }
  }

  if (!walletUtxoList) {
    console.log('*** Sign target not found. ***\n', signTargetIndex);
    return;
  }
  if (!directMnemonic) {
    if (debugMode) {
      isDumpSignature = true;
      setTimeout(async () => {
        await dumpSignatureProgress(liquidLib);
      }, 500);
    }
    if (asyncConnectCheck) {
      isConnectCheck = true;
      setTimeout(async () => {
        await checkConnecting(liquidLib);
      }, 1000);
    }
    if (asyncCommandCheck) {
      setTimeout(async () => {
        await multiAccessTest(liquidLib);
      }, 5000);
    }
    const calcInfo = liquidLib.calcSignatureProgress(
        blindTx2.hex, walletUtxoList);
    if (calcInfo.success) {
      console.log(`sign utxo count = ${calcInfo.analyzeUtxo.total}`);
      console.log(`tx in/out/issuance count = ${calcInfo.inputTx.total}`);
    } else {
      console.log('calcSignatureProgress:', calcInfo);
    }
    const txHex = await execSign(liquidLib, blindTx2.hex, walletUtxoList, '');
    console.log('*** signed tx hex ***\n', txHex);
    if (dumpTx) {
      const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
        hex: txHex, network: networkType,
        mainchainNetwork: mainchainNwType});
      console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
    }
    isConnectCheck = false;
    isDumpSignature = false;
    if (asyncConnectCheck) {
      const accessing = liquidLib.isAccessing();
      console.log(`accessing: ${accessing}`);
    }
  }
  if (mnemonic) {
    const tx = await execSign(
        liquidLib, blindTx2.hex, walletUtxoList, mnemonic);
    console.log('*** mnemonic signed tx ***\n', tx);
    if (dumpTx) {
      const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
        hex: tx, network: networkType,
        mainchainNetwork: mainchainNwType});
      console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
    }
  }
  await liquidLib.disconnect();
};

async function execBip32PathTest() {
  // connect wait test
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    if (debugMode || (connRet.disconnect === false)) {
      console.log('connection failed. ', connRet);
    } else {
      console.log(connRet.errorMessage);
    }
    return;
  }

  const pubkey = await liquidLib.getWalletPublicKey(targetBip32Path);
  if (debugMode || (pubkey.success === false)) {
    console.log('getWalletPublicKey =', pubkey);
  }
  if (pubkey.success) {
    const xpub = await liquidLib.getXpubKey(targetBip32Path);
    if (debugMode || (xpub.success === false)) {
      console.log('getXpubKey =', xpub);
    } else {
      console.log(`xpub(${targetBip32Path}) = ${xpub.xpubKey}`);
      console.log('PublicKey =', pubkey.publicKey);
    }
  }
  await liquidLib.disconnect();
}

async function setAuthKeyTest() {
  if (!authPubKey) {
    console.log(' Please input authorization pubkey!');
    console.log(' usage:');
    console.log('     npm run setauthkey -- -apk <authrizationPubkey>');
    console.log(' example(develop key):');
    console.log('     npm run setauthkey -- -apk 04b85b0e5f5b41f1a95bbf9a83edd95c741223c6d9dc5fe607de18f015684ff56ec359705fcf9bbeb1620fb458e15e3d99f23c6f5df5e91e016686371a65b16f0c');
    return;
  }
  if (authPubKey.length !== 130) {
    console.log(' Authorization pubkey can only be used with uncompressed pubkey!');
    return;
  }
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    if (debugMode || (connRet.disconnect === false)) {
      console.log('connection failed. ', connRet);
    } else {
      console.log(connRet.errorMessage);
    }
    return;
  }
  console.log('authrizationPubkey:', authPubKey);
  const setupRet = await liquidLib.setupHeadlessAuthorization(authPubKey);
  console.log('--HEADLESS LIQUID SEND AUTHORIZATION PUBLIC KEY --');
  if (debugMode) {
    console.log(setupRet);
  } else if (setupRet.success) {
    console.log('Authorization pubkey register success.');
  } else if (setupRet.errorCode === 0x6985) {
    console.log('Authorization pubkey already registed.');
  } else {
    console.log(`Error!! error code = 0x${setupRet.errorCodeHex}`);
  }
  await liquidLib.disconnect();
}

const fixTxHex = '020000000103b716647dcad588b5957dd8e560c15c57074a5fffad4fa00101ecad9ed46fedb60200000000ffffffff3a961119251ab3faa675ab8161cfba1206f0b2d440d95f7bc3397cbc679ff10b0100000000fffffffff5d8b58d27407fd84c7b4bbde71140506b20e3a97ceb17896c63cb7aadaad6cf0100000000ffffffff070b6e0037526679be1a229fbb92bc2075865b2b70a0820d6f4163f5ed0378a1f260081a56a7c3a9a43ff1e9ed97570fc7e96c7b08d777e0d0fae1832cc8ed1e0b14df03a03b9e150d8c8dc59a3a9bba5b31a970595076fc74b72c7bb1675b65efa872bc2200203a5ddaf62186dfd0e7602cebaa2c696e5562395c6004b3b9f727c2a3e3869ae00a09b4e18f1ad1b32ed71dd8f61ba98ad154e3fefb37d5beea3b31835b7acfa14a0918e6f8fb5be833fac305fecdf1f3001655cc4e35bd120e2d7222487035af8731038df5acfaace27c11c4a2261f64b9cb8270124973ebf051c512f089034ace51f4160014819b2e81a007ccf5a145a3acc0d218e39cb98b7f0a4157ad0e83600c456774b8f9689462d9a49bd62eef9f2a8aba25984058a53c53082300d9eb00ef92d2f9efcb202e94e4e67f11d1040e5637d9a18180d1e488d37503ba436e2b56f25a361f5108ea779205f63231ab61b3aa6bfa8b2326e0619f22f916001477a5d35340c64a99938bd8ea49542278344a160d0baae4c0fd5376ea3206ca5d0b24677eaae0e898a38552a36a7d619f0803c22ede08ffab51cf56a0d22692fb3b7dc438e90183656b6b6a78ceb3b75ef8385af1ecb203c52d8ec7a0d71be4a163c8706c13c4f427ad52029322341363fb2fc360c35a1322002006d9511d1d863dcac3bf5b31d5c4ee50c39f8269281431d1fc2ae9fc4a5e8f260a5556bc2895e06a82562926c2eb799119bd0ad784569ce57e20f6d5d63be8418908dfea4354921185a4311f424888912fa5a28b48a4ef476468e404e2823faf9c020391db6b3b966e34e4acdf7ae92021c8365fbca6126140620616971a712d4dea6f1976a914c429439eccc87e5bc0b666a9e245fca0d06f4a2388ac0bd74d0d859999447393385d5154e65c21777bcfd32f0716e7ed33b3f6bd405be009d818b3be49a3bd87c532d127bd8820dcce8b161114d10a3c357b35707eea1e5103009e94cc4ff5c9a3b13cfa29556fa0a0a01bc0bdfcaeb23e800e2b0e654abf0a1976a914a806744d8502be1cc456d9038f77b7713810be7b88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001bb0000000000000000000000000000000000000830300079dfed75435a350375bb013c6d6247d934bb0b592d7bf8598680e26984cb679dee7b0b923eee3847382a7e71179292b5f9022fdf61538178bb4d35fd4123c12926c9038816aa4a08fb18ac1b05a1b1a7f9c0ec2d7746c6b8fb0e27b4cea638439f92b1d3ee0897825b9b89e51d93a6504a12b1c129ccf4e14ca87598e5c508a79fd4d0b602300000000000000013efb016c295a06bf4e95caf8b771c1e5fdf8fb73fb3ca874c76e31ff8e81a4617c26f961ec52510d3fa22ffecbb1ac8f6993dbba7bd1d7a10bc4f8480710cbbb1f385ecaf0980a9506064476e6e4ab43f45025628f6b35e90255884cf59c76681ea674bc8ea08485768f77a717dbe69c8ff99dd7e3767cf9593f53ac11f32596db5181a4a4891db5f8abb5a06e4e0eb78ab758bc16e4e2f46467333e3538ffa3348046e80a7fd2dca928ab07d449e57117c03b1d38a7b5316ffe9de05a7499825c05ec0696f76ace137dd5966a20295e6e3f9d1ee28a3756ee706874be416ebeebde4e3843066461181928a3173b08e35ca47d00d409b98fbb5f96338c73945e31196b5587e05691af8d0c1e7742cb13d0166c9b6e994d3e4a09985b8395d09ee80b5015f3da36fc336631474eaadf345203aee4d3e78782d67aae7324691118bbedda7b17b23b2badff1d58de00edbffbc68d1cbcd9a36ee83542acedf5b2a0125f84b5fcc8109bc7a094dceff49b63eb5da6265e0f915b49ea60f6f5e29e4e06a0fe2ad629da2d76a423722e4c2e3810812d325a68a42658037a94bd567f7a02696c002e62d1973420685a6bf6c4c3975ffee88d3e158248b4ba7d6113dd567d6160a7e27c8e32db2094a10dfe9b0b99766e1a2df1ec9e0036ff1a2609160a5835ac7b15b505504827bc1c3bac44f0ec70ba2e726ea328522a8ada94fc9bb13414c7627fc236d42e01c58c4afd05f985d927da1a83362e16186e872de3912bcecc5f3c42e0b80b98bbc980cc51fc12b1577dedbd3186af5a7cb7678a8a457b3e82a041408ed6ceed3b7aa0df29362915abcade821ee5c2c204aa2fb858cd3c0e2e54e9036178d0c656d35eeee1a91684fddd636500fcbb81e7b4786d6b8cd06d65225bea3040e7eac1209cd4980e871788fa3e399f01193bf4ed658b98b405f11c2588386934075f6dcbdebba0886e44c3135d350fef558a04bd4b6eb0e9bb50038ee6100c77fe60ca58b8222b4f999211b12d0fdcedb9212f77a9a13ddb702e6befcdecb8beb474f5c504b62072b97537df2f998a5b45834e4c62f4f9e4d2c805ab6aa54c303c7a9172d0abfb035d3caf6929b72bf4353adf0297d5b2f3f334a6d29726e1f8f8c61628714478c843099925056c74a14439432b25a8a226056aa5a9664ca43464e30ad157f5d4db909dbb600e3643503620f1888254f777d071ca7e61a16c0332b4e0c58ed18738c0a80159a749197b0a5699baae462b83053f61cd3ac0f768b34a799c99dc7bd83ca65f36e9aa5d95fb1bc474d59df6fc5fc50c07ef0cf644116d7530e55a9505f6a667d02f509037bdadbecbede18db751aacc8a7a3d02f866069bc9b6fa6cbff1c99924bbe4cbac207e023cfc5bfd4bab8bf485221de7624c0440a4eff6c08983f5428055212c3ff4d5afe6e8c59e0f4e37ef56416b9641d226173f8a05e6f41e41b05962793648ede411a58c26c78810cbfaf3df50339d47647bc1598bdec14915332b54b539d742c29e2f516b5a2f7b3397991590b4ed1a76a70d9ca49562c805678a8a7eb84f75662a900e440b9752e0090a1448b07605ce7102d64b9148f91c202d408719f331bc454ae604e1f505f3467c3e8352975323b76773b61ee57fc68b5c5a4576ad414a758738fe44abf826753559dec16978842d205a122f1b568cec9529b0bb8f81b1274e27cd5eb66c71ef5c3a16b5e501e978a42cd2fab34947cc6dce08c4c4096a78428c844c914835f563dc4a92683cde28538ec13def435061030ed34f8020cab12402c4611a7c526c6f8467f360b9f9cef37fa7aa20fed9d2bee8c00b337fa73f093db0426d157cca82e6d8bb54821009d3b5d500f941954fadf746798124cf9a3cf48662fb3f8e8a4067b50437084b7a52104e51349e93ada61d464f78cd984b2089bcdfc1645a3eac4dedd7cf2c66782777529a1d6889ef82239a2c4ec190586cab1ed8c1983fc5884de24bb06faaff92021fb95fd9312ba55e0a1e3e4805ff38b390fe1aeb65e7ab936fc3d58bc905a970e8746efd59d1608e07955411b1865587df1bd04a9a3f2253216907af43efb1a4d27eada34812943c1eb98a411c270c0aad11a89c2e838f4465548833f1f93f9deaf922686711784a5f414c759de63a052327d3a7f8c381633935e2977ca452ca8c3c4589e5d4d0d5d17057a574985fd7ce1d6287092418b5719bbaf0edf3d6bb074913c0d74cda8a0d5b148d44387e412b416a1329eefd20cf48f227895e2fe07b770c8160a1d83529792435f18c18077ce030b67e39c20e67ad5938e1ae22f6713c69307afb9b98249ddbfbdddd251c818eb1e8240425c6289770e8805637c6e908b821257577faecdfec04924e163da6e8066c7a3e4ded8b9867c221f4e35c4e0a7a5e50b3775855d27b1527fbae32ca22d1e9a82c5c050c0d37992c17cb0ba867572146eb729580f3b2e564c91da0985a4da835e7f87cbc904cb244fba70a91b79087782bcb15b25279765af4a87351f459895c67d92c159aa8fa1cbb93aa89050f981f06179ddeffccfd62cd06d50d391417b6c0e40dec620e596c67de415492271d17133a42754b6147beaab3da78fa5b38355b02434b575169bbe21a1551d5ab4764b2e0d48c497c22a1e58ae7097c5fed4ba82647a361d11dca00db3092dc41386aa73db24af3c659f763504c3ccc3d3532b6727ac86158d08cbc7f047e4e85f3b9ba72c557ca93e6b70c2e5c4c76eebf5808be0abc35e9271d5018a46e7e86aa98e2f7a9f4be83e061d091f64b59478628a413b8baf89f39653ef305f756aa5f4f17befb2f8022c391abc63f40e20df11c7ede6d98f466bdd5f5fa2edc2a9d8f668deb8148460200fee45204a4204c1782d3be19059bee095a8a80dfb61d7adedda55f1be82edf63e2b8b1a5527a7c1a049ff45494a17b2ff11bf8c47cabb2c0f44edae53c1f2f8ebbc4e509f6f0de6fc07ecd78b2cdf3ee099d9caed26f7d1e9797526d508b4a8950b4c1ca3c1d387392644c70c90dd13e94a6ea775087b5f9384d7e9cf92f5e6460107f72a4dd0d6694e1c876fcf815903bf171f6f048cd7f86b55fb226f015eae674aa0246bf2f1a501c65179a2088a1498ceadcba739c7b74e9a8512017e2eae592bd60053d07259cc71abf7ebf7aab3b33a336158159a4496ad57478e2f653de5e50e0e9dc744df5516646e9da27543a5fa6b5dce8cbb97757252d6b4c30d3cbcfd01615cc771d0721d7e56e1cfda241536479def4338ceebdf79b6071e332b3234dc096d2c2a03f008a7f489427562b3eaee25417db988e649bae3e6a84233f3732e965d2e890a1b4cc52964a965bf89967861acd1b9ecaf94748436eb8c34ab916cc6ced65cfd26014ee9281bda6a5f7dcda2192b141e06888dfdb5e608030b95ed1353cc3d3621afd663da1f62c3d34d3b5ac440f899a149d521247c1e40c5339d154b4bc1bb504b2f3d5e292b2b37773b448bc4b954f2ae8be666272b4c1fa659183ee75721f08caa19837ffb1c58899c97b7549bfa3b4c8aa4d8dcfa31dbccf19659d83180a0c6f56ebd409463491e6633e055f658b312d9b1aedaa4f6a0f209d2672fb1f3beafa5d21fffe19901a65ea1123282461981ebac37bb1950c7564a939582ed9b9e3a97b9cbb3404c099eb96a7191c1c3f7e7beb21965a63bb4981dbdc26648cbf258ea894638d2995f0c42ce9481247c7fc767517acfe77449413edb119fb06d5bc9d98e3c2c6e8d3d9685c68de265a2ec270e2da963bb4cd29cf11315703baa656fce151faa9000f9b64db6f7746cce2455f32f9648325740fe3562114e459055a814bd9f83daae2cd5edd1a1eecb0033a6b2f3a11e804089e443c292f1adb53eb4e16ee8e3b3437592ff5e280351d5d40d8a3c7b64e814c6d8f4acd84a6aef1949ae5061f2bd3a8701001c94f0c84874f7745436e91b94591b3f589fb8f54dc4843006e06d4cdd2f5ce28738a799915521caa7b399ba4af28e44ffc63254cb3ba690a24774f6ab2fc027682e975d99f4fadc4bdfc96dc4a1e14694f7d94c7fbbba783030007dcf0691a1123bde76b1008e07a3524ce9c8032118048ff2c5e668ff65b1722eb31871e5502226652259ccf6f2876735ffc223590cc50400a2aec151efb75eea192ad685d87b867091ed9d26840aa615eae6c99a6a2e676e2d8d111a9ccbe7b7fc1a0ffb2d91954d9f273d0336fd603130f2d3a8f20c3316a3355326c3496afe3fd4d0b6023000000000000000135cb01778f0005c5d8e1922733a6af6ae74318ca8e428a4cb27bb4ac6c3e4c5e13e5fc40596834b682e24841432ef113e68e8fd93f9983eb8b548110f82d3bfb22056f04d29db41c902c617933cefb39d93e0cc9723fe3ffe31419ddea91022aa25b82f946b2e82d6745277c72c875fca4350b4c213c42691b003f4538092e31f51867a8a61c25ab87671a18da522b8da2bd7eaa38a298dfa5dc874170ade11ff0ef0b17079130425d4562d6e82389497fb99c3ba5af9706084b50fb6ef10b1c1c2bea805107ff747f7c160c95ae0298b710dddfe1a9ae570b492aa7db0337184c87f3d7d50a9997c4a429690abdbb2ba0c952caeb18bae3cd47e4d8ae2137846d1670ec99ef420d7eaec09d2948a25df4605cc8f1bf3c21e83a67aa83a7ed77bc458a7ee8b74996e59239fa63ceb4e56969606261b5a09377a14e1b28385cafeee03777cec2d0ce8aff47b4efec6b726ea13a984a17d5930b5c15f6b52a6cc44cf1f663104db31c6536a9e999584d0af187a37da995877db4cb734ec1fbd5cc68ec94a6b071abca6812500a27cf9293755e6d91916b929ac37e4befb496dc3abf72eff3f39afcda1cd805fab2658b94c3dca55554ed22d104ff5926d386c65e75f20e41254440a64163047344b4beef986d2eb07ef2f49e6d79ce097131703cf70528433514f4c3506af45ecbaa6ed0ddf1047c670ff98c16cda717bb3220f61289d5f409a27fb5b054c2aa9790390dfec0c5a333c32915298cd432e505fe49360c257474b0da174e71547653c08335eb8d8c8cab63262178cb3cb719b7a9b0e94029995c0c2ec9c2edbf6f21d6e44805d0586ba19276c0a06e93bbaaee2dc73a7c3e79bcefdf8a646863589060f48d1576527c1e4cb2150abc5dd1dae84a364073af9dc18dff3fc17fe8dd32fdf31696cc0f66fe63a102d65c116a4df33495c1a791646813adc7698089525045640088579add1d41aded6f86678fad41a674061a15cbc6ad1adea6b9026b19376d8ade0ab9e04dc9b41ad06ddd6e57819ea15393fb105ac5f3e32b26baf49b84f0117691e2489979186a7d68cf6bc7d4988d2a9e7e030a06b4150c1893603f69a75eb561d7b5915142de480306d17b5ac10bfc7717659118fb2f17b5128357713a214bfd08a1f9d7345e8c81925d884447d5c316d6f29e76159e0738b2951c20e9c871868219e75297b27aaa74ebfdf7a88aa07a0c49eb6d7dc63aa5414349ee793b0937579ca2236e97416eebce7a6b2c210fe14d08153639ab24248bcc99eb695ecb64fc556edb2c353d75aaac8e7e8a8f2a4b37a14b43c3c1667a1ed5bcf730442e7a301868dd60acd3355309f96034e95222803eedb975329790a6f8a69c21ef404659f7b41cb263be57eb77e12086240f2e9948236b1bb73f3c523c897ff39d879c02ca65fb433c87a33dcac0107ea46c11d5f5ba4223a171ebcf481db2c233f05544153e868c7432b4f722ad035fbb8cb4b18d97a4c41dd4ffa0188dba9359a16010986f7531a89e26ebd49a23fb126752d20324db296fcbb74c96121e0ba5d18483bb4252971aee2fa7276e54ff5e81c46d8365cb175341c69654afd5861d565e815f098b91b9381f0f28004669193158bb34b12ab61519978c1970532eb2c05c5f5fff99b6094e6d5ec72f8d1b66261cf80de1bae5971d5b97cd20ffb673bdc74f2fc36f726b26bfabf31a2f05eb08d91bdba329a4c64c60556800e1857a23cfeb2506710b5ab7fcfc24bb293a2cef055c373c2073c233ecc7ff60127102365399f5b7219175f69a04e85a9b9a6bfc81937a5a4ede8bc6eb7685966f8f84ba324c78bd59df428532d02408f81b75998b201e59480d164dd624deb887b395424e45ca306bb9b15e4619d810c7e6f06d6e98e5a7258b8783e40096dabbbdaeeb09d0b17d94f0f56b4a177cf24aa7a6e7370831da48ce38330bbc60df90fda37c42474d1c1e3045576c7abb69ad27b97b09b60146d59f2840ad24ae06823e3c81aa63c4417359bca558001a41d90696c6266f0d6316950812fce41c3ebba5b5c8f3ba54ef6007659ecba2c7f748f8c26464374cd688636dea3701307d95190b89525dfc82f770190d2942f60977e8bc2aca4c1afc1c544f12206434059e5fd2a929919534695fddfefac397792b8ef62143e4f85c5054f7860e23e2ec56207afb6e6dfd8370ea3e2988c96b2190a9f5d38507bbf0748d511d1c360892ea6dd8918a5843791f9158e2b29bd169484a083925812364c0f44dac55bf49ab3095d311f5fd764b30e6c58d2ad6b6bf53ed0c86a5e899dbd37b11e188c7f377e96b524b8037185b54d0fab109ab5f619f398ccedba48a3042a27cd97e2ea4b2f06e7e027e21ea2a09ae23b60de10330e99a742ce2416d6b179a71ced411c4ea76d3abe3e684399ef6300fe9eb4e75e756de82d0162126988bd97f8d0fc7fd0faac83860049d839a0574e054edf4194852e24be5a97462524413e2b51151949d732f1414ac97ab4ec03b5e9ba0e925e24c88f3ae897324fe1cbd2d69a53b026fb51f8d7e0733c0880f95c19a30e4123b98ec3e76de30f4ac8a6cfbb5666ff99ea4a43878291e63902231b0d6a38e5c9b8421c5cc59ea4a0e75f502ec06e5cabcba91a18cece72c27e9df906d8407c10a3de3b06d6c4f8426b638a01bf0bdb6e7d1928f912dd6d44df19442d7509c4c13c706dbbcd7adb9f13e3d63eefaabd3304ab29abbb30f990975b5a380fc19da3209b00def5c4d17db4e4ecc9a03ca0df9cac0619d431ad627b53d48d413fecc5784e70625aaf352d6fb97dcb100e189af85fd0bc085afef28232ce7fb05fb510c61c099b14724f0bc788aedfe0ecbf2d94e98f8541b565da0bc3ad68ddc4ee4816ab2ec457b45d373102d78818318c2fb4f5112099c2aa2f494a033b08d95f8d22933682bf060985ca5cb3a1c00e11cf3d478da87d24492bcd78119d86957b11d39534911aaf6fea6b6efbee9a4d30aa1c56cfa8379ab1747163c70d9512b07d1bb1c1e296718266d355db01253d7adea89544ea97c5454ee7be9c96260c0de6b433de3c280db204f0d8d7619554d19e5df8a65b81f9a51279ca5c60a48801c5e6aa6cb52b3f8e01d7d52f764b8bfaf73cafc60b1801daebc2f1c42a88b959fca5ff40af283c024624252416fd1664aac2f1cfe7feda96454504390c6cec22c606fe43b5c5d381df429370ea5a65131c7cbdfa3d062427a66e3bddab4c6759d737b3414ca9f888b8653f05e4129eb6852908cbefdd3008d48793d12cac411482da2d3e589f120cf7a026be7c4e92b7ea52dc46f218d3356d5368ca66910f161e883db9b89d190dada664c49066ef944f0942f0f1da00a2b402fc827e732f7a07a83781e10195cff1ac83d17b4a72fad3220555385308296b60ab98c75df635328fc1eab0cbac1fef62aba556faf59a167edddb1098e8b62a9990051c8f48d251d4f391fd10fbcdc886cd04d4251238bc21998c199415a7f7e529b6feae2daa700d65a03222b4feced9fc6c4c2902e06d62d8459c687a07a282a5f696c01735f39bbeabaceb804085907283fed76abca8a41c36fda97b5b67c12e336060ef0089bfc3137c2592fae01901447a2fac72df3dbfd35ab7db3ee22c4be4744ff88b62ede55e6391a59c2bd3840581d948de4d6fa032da550a5e9492da904f0d9016f8e4859cd6c3f7c213ab0039460fd2b95c1c7d5a13d671c1d3dd31665a18eba3d3e5b16f88a01ec9f2ba4f0a402b89351679a73758b2b6b946cdd28e668bd1f29d66749f470c6708c058fe9a8c5a4a0e1477f897a362148854157ab86662a2f079d067c2e3ff3d42d29bce95d183bfd682fb87d22a3364d2dea6a5b6b1abf9ea24ef3e8e816a657a37a637b404f6c7e915bd25ad9912a8f0bfaf64fe943d9789d8bfe8b0414825c3bbe0fa3d961eface6d30861cb80721ab21474c8e9843d5b85208594ae094739758dd5ce7dbe28b2cf739b7c941008b1e30b0f845ca00796aa5e74e6e8a61c3a5e7f21177a74d46ffa40f005269f6652f41887d30891a621d2640ff61051ce4b830300074c23684fff1b4306a7f9eb406fa63ed28995d4e4aa420bc41400314bc21789380a8b92a9a67bc551ebfaa0800c74bf56b89660d05010b66a3af2688977a633080c89f54f89223dcf99be380f34a74684b05297c5ff6fa7bc40b96deb7ce0e1d1c68b6ed33fc76656208842a07f9204a0cdf963e4c305206a56a01c62f383dd41fd4d0b6023000000000000000169fe00ef36cf7d9db1c3a81a01e8c2eddfe8bb785f25e5f11f6ab7061cb2bac8e584884dc8717b87bdd91ad444ac5e39f40dfa8f7e4b12425c5c901808d820754fcf000171521688802df2f5548fe8343472bad0ec0b164a2b0aa5a1122cc54dd0eafc31a75002b76b16a6c618983d4c8a96b2cb561b2594aabae1bde7586ca01707cb8255190565edf1a5931286873374d961200b63050b9229dcd3fabf84b0118b409f6d01f096a6052185759b74dc2fff56cc37747ddbc184f6bbd23d91a75bb6b02323f0bbc56a24f2a8b6ac9d036f212158b4e240bc7d9f57faac04118ca9b9e97e45b37e7bd133b71d6a4537ae1ee11e5bf9262cd62877daaeecbb04bb22d093a8a8e6ce523914e02f734993f79f66d3daeed4f3d47c00f81caedb638f4b3c40a336bb104d0567510ea6b32a68371f7d81229680cfc4d523a553bf18ce3770b5fa879d4abbd7644d54f83d359404bf8718c0e851968f26d483d11dc793302e492337571aa66b06be3dd169085289c809adef57189b200f7821ccf250e9e66a7996c7c49502204aa705d9bb1f939f409fe2415ac98cd98ed6145d396890e6fc35d3222b15c72923c93ab060ee190d975458b9c9fc2d67e33d679e3e10ef97844a204267b1f55f60046139b837aefa75119b38f3229daab86f841b9a57a185b29d56358394d9ee56c321b874dcb33e0ea39d3d5b23537cb87d1b5d3cd264113ae8fe3f2b5c1171eb2a1e347064015c238769350ee2a1199583a13faa0480aee68d8d2cf02fd7a2921074565aa71eb341f7e5c374270f6781b2dd5fdcd2aa362fcd742d092ef50f12704136d308d3b2300e925a33c83fc8237b20c255e365eda31cac810467de3756a275962af7b19553562a53c357314ca7c876bdfeda8480879b577d323127d706b3e61752eb7e1bf3fc00b7f78d14bb6ddccd838da46af19432d1f359002c514c956069a35122741be65f19cd04d834c5824e312e93554f1aefe331ed9ff85b17d24eefae8a3e40db935e72336b5ab80dbd2687c481d7d4f6ec6a9b668be06e2996ec0714b787238d5bb95b298883cd1d9254527ba7fd6731398b4a7c39f4efdf47d955edcb351c19df0c190b9de30ca4c2b92c3cae06c0ed796130a1b1d9273b0b20d6ad93e9e05641575c09211c68c77ec53a1f3e03dc2e26af6254926e9d2d61554ce7cee8330da6abfa32b31ee0ba9b804dc38e7a97a51b2df1cde47e90bdc55bd489707becc0f7b98099b6972c0d08323ad2ec931a5d3e2140abd675b189300b6893b68eafa63c158e699dbbc9ea9d13a5e6afda8d715662475cb901c641e8338b97e5600ead66a48e525ebb4418b2af62fae214a2c21374e0f77e78168b0b981814648bb6242f008b5ebd3b111694334572ffee691061bcbd506995a9eb4662f6419c3bc0c2adc8d9610f0130642f6d0933f7740ab192fc6afbf43268db7a07148cfbbd4ecdd1e8a8557a90f3bf6fda6fc2cb59f2a3f0d2ca2179673ed855d4e99aef673082b0c92e5ba98eaacdcffe1b54682afb569abf126bd2dc3464c60e7b8b8249fca93889ec34d6536b43251b7ffb071f17787c5e21327e6f317a35cb004935d67f40c1e1cd8efd0669418b88cb43f347c8bed157db6d114432fb67ef600c480d2409aadfd94a2a8aaa063b5fc21833c17320e04fcee5aebd2fb56e4e98bc08347e6a59458232e752b4072849ce73095bc093122e43cb0e0b21dc888628206ae58c96df382d669f8a83652b306c85984be91bdd1a3729307f50fa8c40c0c4adcf0db63a101f19b03084eeb1b468eef5e151262380eb7ed8a16209b1f6efca2a98c486c45aa8c1813606652d13f744d9f85a26e125686ad47476616f3bc0e40547a4e5c697833479e1e6afa4ff3f1079a29f402afff8c15b8e8dbc59b30e0fefea577730376a8d2a085de36ee7fc88191be8702bb47e501b838f6745d34e9e691a2d069b995ee953804300a46d430c56c75911030ec227f10e9bd08e968faa11abac02c0e844bb662bed85c1515ad68f9daf25e1c9b2f4376feaf35b15e5d33a98f3cef654952b3a32a34def5e90db6d5a4b6e9d4b3e7b75faaebcc78bdf723fa080df5611da74a62bd231e3195bd71d0e18acd866569bad987a87315f59368d530f16a0688f1a94012db048d0749bd494c7b005159f75760e6b1ad1b3560853d336dcc944b6ba42f965bbba389414fe8c777d626c562264321d5d06247bc5d5cad9823f969545975293d18f251248efe32cd77e43a5513eb5719b9b5c11b3cf24e7343ca1ab0690119769ce560120f64aaa8c863abbd57b961023d10d2e873eec935d94c54fda3c75c8e46e1f8329e629d9066d86d63d92c26600b4bd6ef0d8016395e7a8c0419dc6f4b48975733b170ceda9781bc34c9deac753fcdfd84f2e34138262ca5a872f89e0be945ed69596a3e644f75a7c948ba7a9db58a699cd6b57b4b78f40d253bcb27c173a51e623f8564f6b31199e08f273cf25b8e6fe6d0f9a754ccad456508778bb22652ded0fe4b7a647bd08daa714df9a3ea8fd9e3eacd70dcf886f8fabcec016d63ca161d87e60d0676a3a4f364641d3cf27ecef87526c065667a0268d42afe946bbd3f763dd8574e1b3430472d5821e86658a4f56f109d7eba2e0f3c56fb05a627b852219b80ed29af6d146c9e90548335866b5969abd19815d06c9fc29d478f90eb83699e69c85c41715e4e02e9bb5dd4d9d8283356cf3f2d3f1a6179cfcc77da51ed62712e9f4b151c03854a4e740651aa0c428ce19e38593f5352c3bbdc09fb047557b30e7a330e933738e7f1ed5487b2d20308e15e58cb20232f434b058467f6217e66bf00968de266ff1afa094784e1f589482d128813dc7541f15c503f3187590c5b0e14daef310bee93e98619fc3acd55df9e3e3fa87c0565c97817ca6ead9c22702afadea47c4bdac8f17f2a521bcbeac5200ba4036b6d39e9175018bf51894cf4f908705b8de86c1e40eaf5fb8d6569cc562a675ff5f3a095df31721931b84badeb1879871fd90317cd63d2b66345f59060287edb14229a7e72cee6904a56c36ea5a47e372798cd75d49ea790b71a03dd0466d4cab333868995aa16d7528e98f10541fa2f65221b58f27d82debea1eea68270166c6a6bbdef9eea0d3dd83ed702ee831ce8c5f171fc2993e4e2c209cdd344a4b740656fd0d307fe97f223f69104758e8573ab1a0d298a2956eac92c5a427e022b226005c90ec89a023dd91b376552688b9cae4b32ca0230e43a5a475889ece074bdb6aca03deb0353493326b817fb26d675dcf6b3898fcc7193c7db496e89f2b4b6ac4606ce4fdbcaa6b2a0e6234c1290512e8d8841781b5ebebe617e0c8346ff43ad7b9ef2c385090f0faeeca7a893f3deef234c8990dd114cc0840f33a1627de39aa15516ae5f502e99e08791b11b077639be53585adf05ab93c61453c8a4d5bb7ca81f0da1eea2844c12f3f85939f7b3c07e047b30ad17963b65f8419d7e299873430dc83d268db3da1f66132a7c5b3a3371ff1c04e83341647e1ab6d867bd452a979e6de1a121f87a0b588387d933a8fee57983d96b0a142a1dcf4d43c4bd5fcb735f03637c4a70280ce814273bd799ee60bbedd637e227618e6f6f0046eaea377c4633a9523704804f3ecc36e72bf654616f9865ffcb2e919d4cd68e30240be77e46fde095e9750e22404810efa2e7054e04664576ece5b68f4aa53e10590b6009595fec196d471d844db0d9c62ce48e669de49f6d94a19e7d26bbd3e1bf953632070ad934bd2ccfc9fa0d01ddd2839cdc3a4d0f5314af4d5c9f73ec269435c80faa497108b872b90558d76ecf8eefb823f91e0f0e103b7e0baada6bd50300c818de54b3ade0cf6a246077cd35050e45efad74f55e8a11da641ec41b1c6c07f840ddfbc2efcc09b21e1590ab7c1ee320522615a819335311c25f5943e296c2b9c08d7db1fb6af983c249b9fa8c7f1628e65b62b2624eda592dc5897b29ec9b2090c90a557b63141b4162e5ea06137caeb6f29cffd673a3a5c6720ff553e7bca7d735abe0a1a1acaee4503507d143be0830300074fcffcfbedaa3f3da980d9d23a2b163ffac44c9f5817675742a53c19b67c489e401d715ad61fa1cc599b24bf2f3c22e081935af6a1a222923ad7753a1e9c31d44e0b35f9159699f04616bb40855eac04859bd85cab464f30af3b7ef0257971d105d540409bc8a4732a68cc792a81ccd9aba58a0ebfda05d373b6d2ef600176cafd4d0b6023000000000000000147c301623b7318b4b0004f6022a932943f28661cd4ceb5b10e685c4874649123f7a05e52c20f175e82c9d2e44b353ae7f3ee89e619399919c6e526ade400b1af298f3eadb083463e583c0965aa22bdce0d6c8465b00bf2881311b51d9a63ae6a9141ccea5bf41cdb2bfc860a59df49440407ce83577d5def19911e7ddd4c1f90eef15550be555ae16907b0b162126c1bc603902baf7602571e6fc5f10088ff1c7877e2119b58a334abcedba34ba995fe3f2dc41a1d289d4d50bcd2f5555e4658be1fe10ec494c981b3091eb8ce0af4e42eeae8ad00dfd2a40c303eee915e3d13620d0d177515cf014833d75de352d991979456f8360c1d0a9d74428b2ad3f843eb76e7d75eaacf101ab7912fed69ef300eb008c8f1c533cc523d06f01fd23c5e550fe2dd5aa29f46d944b7da367ddbae9b8f80f0f6b83bed848048b3135d93ffcf92c8e80d3424c3db8fbf7d1bd3cf47667b08bfdddd662a1df017730a0e3273e8170cf71924ae07286f74c9160b427e23d4e25bacca54972b5d98f1ec788809da9082db89d157c84e33619332586a85fc75b66d9f58493dd679b10d6f35e26bca02db951ba08984ea094e0e048ac867301aae7949a2b8a74351dcd8fb60ba96a057fd219403e34de505a1f82be0a5044d467e7b092437f31d082bfe9ed5b4b72d549cd239a3ee32b4c939066067cc8991cf6a0138430bd413b29b36f2288a36777dc4c5aed3e8dd4782a3d7e8177324456277d5d356338ed48dc8511eab79818bb1bd74ed49d5f90bd7375d62ec4b62b7f0ec6433402986ef6def4019f31ee21f6b7dad767a616d4e26b33403040d3f3a847dbd2818a5e7fc92629d4be3aeddbd3291a13c6f2c8ccab09fe96402ac98726b6bd7353aabc6795078717c7e6fe41cdf5c490b831894272eac43582b3586773a35e28277492ebbff1782ad40732d1a29c73a9f71b8510ea16d7c6f8f8e8857fa64ea4a5832f2103865ed4bd7bae18ba2473037cf91d7b52e152253eddf06a54ab0578246a6856d012d621b2c4348ed9dc6479653d431ecfb71f7fa55faba43a841d18eb1f9ecabc45686a8f173daa31752e0862692c3b08ce6fa45002efc6b6ed45ac252c8bf67d72f73cf8d93d503a7738d4abf73c7354e8999e465497ab23c4237344f3e9059201162e8e4b659cd1e8b7ada1f1b20791f1ae47d7f84efbe03c21660d950676a63b0bb8f59cc155861ffef8572369630e8d33ce7597cebcba716c206869c3eee1c1e68dae10c33bdf0b4217f8bb332a8d138c343374807ddfd7b4e881e950fc27aedeb842c55ba6d7d261e0bee21581ec96dd245822fa6549f0ac5abf539afbad645c166c2edf4b18045c3e9b9fc893412ac3d9134cd46037a8210ed6bee8ed6f771aab47a02280bd89d8172025be6fc2a30413c292db979a63bf72f59e01b36698fe49628e7ee1bd49c50760ae0bc333a25bd5ef0062b4d22671e512b667a62429517b02a420c60f5ca3fea20cfee28f19264db3ac4217731a3063b77a1e20416eefe6c864e837df2c520b02f9011b3ad62dcef879a74366acbcb4bb48fc55298f6fd7dc844a7f1e328a10674d4e32df8b15b613d20753ba645efe80489afe4f67f23297a44265b5e62b8676522fe5712ae983c3a38be9c4eeea8793239e0438ae7717ae489b1baa2f4cbf7aede4cfef9cadcc8ef83185002cf142aac538727db19e2a6bfec2bc2e1dae2ba020e681653f1c0ce7f640af80e291efe697c8ac22716e521c8fee6619875624d67ac218118317624b918dfcc9fc5ed4d4a9f8ea6c59c8e2ac77f70332a8137bf207d8d89dd9b4901eb54458ce60b3179947317d2915b9aad6646e611d358067b70b1ea43fbe13db649292cfd2ac985cd3b0b0656714739c685afa726d0e55566580f78bb572114ed8e6e00208c1fc37c88a17334a6362ced4b5f04f1df2798945ee2bb286124b7c0cc77665f4c7dfcdcf2537301707908a354fbcd78d4dfd2afacaa62ebeec014302ef318a1f9db315a055b6aba0823aa0e3e385bcba82374044b1d62bf1d94ea3325599c46a90ee6607c66283f8b00bc091cc63c7bafb18bc0c1d9ae877a6000b7d68650f8747ba33f32b12334c000499847609fec2c25b83a5bbfc8e6825d080f652192c08270fa842336c888c8c1e72d6b4c4a7db158474137d29ec883150bc9c27bc6d25c8f82c07beb61be0781e06c71525aa5b157ebef95accf0c55cfa02a4aeba66a612a849ea6a7afd99cabd221fe8f87bcb20849746d22830ce8d5d91294d7aa0f7dcbd15e199b7c9b619cc41411f44437b3c765a8eb7d2c35dc1a2b05b1055d12cdbcae324ef41a7c1608049b43fd28c6d043ff761e6066d695fa8599635adbb81a801b25d0ede16fe6d6a35beba79588e292c50a1d3a9cd7d7b366bf90e8b6b3c195f1786183c854c87d3261b39d666e2067b2d1b9aa1979b88070b6db2a599e8194f6bce938deb327d65609c738ad386d21c377bd72d20964ca8d4db671714277ce6a20666f647a1ed4125baecce21025ed0adc808824287af49b76eaac2bbd310970bf530ccfec081ad5dc3c4c9849eecefdbb4e8c1742e60ecb6849e3c64895264ecb0a8af4307d5f431df33b55b546bbe739e61587d11bd0cee3c059485374d95fd5e606a745e20f4efbb46fe77296ce4e4b08434e789e9a503bcb718f856798e70e216b9f63cb9d297fcabe669e00ef974a268d7f1b139b631169af5198a0fe350dd3fceca6404cd865b9d17abce0d2fd5ad4e35eb9313f9e66931508680607b5e73fad96f6c5856061db8044e2cede0c38dfc4306c1b029974b5294a0beb0869a06aaf6e52531f1326f96f0eb0bea454155000500e28a2c1f291f1874dfd2bc9fcf0321dd57985b5ed1284f7939f067110b601d1bb356a13fcf06c2cf4c33addaf62a8a94b9d80c8879ffb16e74f035ab5a86fb5f9306cd154c8f76120a3279f39f6e72f672124d1ea7d30e82be441ff863dfd65c5ea1a1037c7dc1b6518e9ac89f48517ee1d7eb9023a4712f74f74e1ddce3a4f2fa259b8ecedbbf21394a30b89bf800145fe31cc4d997bc6e6915a6b0a83756e4a814d68c768178e6f91de34fb5e86f07825561ffcd204c3c6ebcd25c9cf86429729ab5c5aadb59941e5689e192ca9ae1a9cf9b8832c1324e389285a2137de258f3504230f763a0360bc2839991c530cee80bf85d837eb34d2f7ac5040fc4b209793e3ab302841dd930bee48493fd61e9071d9c224eb32698cfad33d8fca58b6d60e280d24546daf7015125113b03cfbfe763aef7e3ca257b6e803c2d1d697cf3cd5a3c4d4821b3e75651102501029dc4b1df0f75441cdb7bf9c191bde1175376548743f33d94b9db941a724666869ade57daf73bc617f18e6c9db44638b6ac86544b8acdfccc8fefdedcd9116c4672e9589cddf6bddfa4fa6e20689299c1ebbe58ab898ebbf0bd659eb79afa0fee869e265d0b766e46b4d9905f99f8eeeed944334606808d860de05de3b071cdb80a5ee00d416f45b803fc4fd5fc9f0c25e9c1c3948cc6c4cea665b2a1cb6692ce224ba172c0eb7dbbebb35f337868e6a5f908afa44de99399d6b6ccd3acf3be3a9fcdb73827ca2dd671bc1cbb7aac993e687fc6746191c50da3d0db66ddadf9071c1773a0911bc126eef40e4c1038a14277c76202fbdef1845ededd8b827ffda726e1911a77cbe70436365aed5e8c5cb08e0b66e569de0e9a7ccb7d99ab2d9fddba2e9ab78f8c50005d900d801537fa8a7fb3d79d83d2b105e9404c3cd2b7ff2c7913fe983baf04e4b9288cd58f524d2c8009d9f0dc79dbd4c30f1253c5734e55aa3fb987b0ec889e0567b5df39145ec5b867a122a3de1122636c0ed54ea1ef4c5e8db7df536bb9ca4e23ba8a43a3df94c0a0aabf9dc96c529c651ff68cdb79d8f7b8021aa0899edec82b46155fd13a79d9b30cb14686a0e830d236f97004934d648f5acf3f992efbbe950dc056147e9f873a01c5ddb0e67ca944a8b6f000236d29a48331198abe60482319a7a6b56103eae14684004712007e42534a925600d05b59b445efa38cb33dcd00875830300076108887a8f9c8d8fb1e1d204e9d48dbb55a28cdedbcf6258ba775108326ac8105ae20db39088fb25ac9b6e685d9d74de5316214307c5087b17aed5eca113e98d2b4fa108f857fb305020a6f6fb56c807d0685385927ebef7b53db61c9448f8405d9e4a5116cf3e6100126b5c21bd2eeef78b7294a2a0ac356f3dcdd51b1e8a7efd4d0b60230000000000000001dbb100c24bae77452ed1830c85fe17f579a31a90c1e87bdd76900168775e9f1601594864a4ad699ffaa30b4e0e301552e9ab77534dfdf9386aa42e6ec4b3761d8329dae05e7b67796f5d110606aba7989136958e9cf622167a69ce222404a787b72db5ce1740174e4da7b164527eb297dba396988562d59acdc61f52e96800fc033104f3dd6398a8ade84cb704ee52914fe3da2eda4b3901c9f6104365517d4bf4021d5339119560a4d8ef78297b7b201abcfc0955739c26a9c9a8f887776a9fedbf656f7ae3d644c6f2ab9f6f90d3f9b9f0528b2682603cd5199fdce7abf5440a840d986e99e8a0f76424c4e9cb233466b3b97247e77403b1cf1f8fb8ad8085603cbca5c671b0de0d53539546bd1b7926d402e40974894e4bf4a6022dbd950ec95a4202da634ca71d9c48942e282493baa8eb5cace782a18b57b3f796436f7c3e0411be4b62a2509c00f176a9ca97380c79fd85d0d879f77620f0c079684286b2aa512fba170e564af5cbafe0e0d1a3bf4fe9024b86ae97517705dae403d034583ca5ae13f77e9cdebc61cfd547495d71f8f2772f32eb061a89c2a23ecd7ede8b779bd87e2a37b9538e53341e7fd26f65a63012924ddbb26d64599e52bcb7c7ecc35c383ec5eef862c31091f909701f333028b18fafa359857009a26fadf255b776262f2536d6e4c387119a2c120098135f1a7b2d81ddda263442605e1ff03a17b74125bb673f7d35560e9c72883104f2229c4715167a990af1600ee333e1ebc29d0a54a2fe67ee8d7185a81e3be5072cd0994ee01a80df7f1d5a28420f5afe1516b27beae3774cde034c165d095c589fb81a3fa7e99b5a1d3a7cb3a6bf19ea4e65473a0af859e2e260f41bd78a055115b8708c523dbdc457ae5d833756af17dc3c45a76fc546a636bb5d652d14e951b9a051bf7965da0df74f751aefb585ceca7391ec5d628b8d9e548a8f7c216e05d6cc41a4bd4077c826673190f62f25337bfd11ade44a2e25f0fd015eebcac57f31dc05d79cc0a5aebceb868dbb5ab85c30ddc05bdd66b2193b07eae40815389b0201cb871c184754e3dfd6cd005bf67b97c9ff55e73b807645a200e8c93c49ad9e54e7bffdae15757179d82593e6aadd997970023db7ba425ebc6122d5f3c2b91255cdbb625a9b799154b779bbfe3db3d86d923cd705d9f64eddfc7ea89c0fb98208aacec00e2121a2062ad0d00fd95c46b586971b735aeed47aaf1b82ea8ec04eea0fe6a4e9885ed2a69fdfa8ae22983537e4aad5ceb6c0db59f69f9aaa84768755398063b08444e9523a9b28c4b128f9b48cfa237bf1b740645b1672fc407731cf03dd6f2ac6558e769066457471270dbb0dc0abf25490b89459bbd7fa67aa79aaba2a0aa775d901dcebca9f948d255425ab32ff143d8bbc51d1016e972041b3d552fb941b99525c7efad512d8ffe30e3bde9cac81e0ce1a3e96e0b8f02ea399c085fb85787091c3496d26da71596f9e3d9764bc0d1455abb68c65dc9e492a0c892baf609849988250b4745875b3189919c23f559ece496dd22797c41c8acffa8d0ec161c949b388681066004616bc65e87e83779f83bcb4526037c1ffc141fb0c320d6ea6062c80e54f5b88c9dc50a7cc6b131f11198f875b29bc7dbdec4354a08fced9490cd7cf6710f983f3813ca915ddf74a471848d61ea512edaa590dadce3de4e47f162c59faa2d72f3bcb40bf1ee6ec9f45128ae2254ac0bc8497cf6ae53945729bbe77e3e54e4196ba6498ec66a1472efc9e84677c16b4592b901685a4beb48d0e6078fbcf21e9a365120b897e2321dc4115cfd10288048761fb000f4ebf7287bd3061cf13d413de59ef65c6ee9aa56722a3d55daafb92245f929c6d61c3538fb1e853cdce906e5a0af5510a3cb75050b247a1216100506ff4204622b6b8b44fce600640c2ee58a8df9f85098c6fb2178115dd27c97eea7d14a2546f84663c7d1e89888ed2f6c6c17a904c89c5a2d36ee11532a9328fc0f5ad9d5bcb30b177bc90986b0e130a42518f817cfb1062da321db8c9b0da75ed21a197c05b4678e2acc55440878f4c7ebe6c0d081668d7510441f6d54766c7b342674ffc03fcd8a8d5f130e39aaeaf05407ce6712e2c6554467cb45c21656491188b5b29521984194ec1c5dba0219b2a0e719bb9a68ed6799a54b4593e069526897d00f5c171e96cc62682b014904832206e605e92e0d707ce5e2972e2b74abe39d0bdc29157c8dc9782febfbd15b68f8d45629346c1087b16f6531a693da31f0b94e6f01dc64df3f9e11cc344cbcdc465c97d79bc03dba48d85f7b743669b88567f0df5c85c69703e4eae4cd2384a21a6a326b50f2d3ff541c901c0c4e666d950969330329a14b821ad80a6694b20508bc5af4d872dbf8897cb9aa50180f31f45975d02627eef5e8c39dc019b57055c8eef6ca2879e9a02830d8bec592f964b2ef0a1c32e8dec2b862886d9204b490606c56ab498b9ff8b481fb491d4be6d89bbf378d5d7938ab983f3337d9869983e1f2153e1e16cb71e441ee0e1ab0558790fd037d30c17ef8536c310645e1d4a24d681428c275dcdef61ba0fd59dee8887cd7f54f2e95dc20727680f39794dcd726b5a0fff83d80da80297fb6db5b0b676d1b28b29955704913b1d9eb1442f8bab65fc93f1fcacc658089418c340c52757ff0d69561e2e7edfaf6551bc5ba39a8a93c6744d019e6c624741e9cdb95bd824280074a1dcf4a82093cb33ac5655f634c8696b9378921e8107063d6720fb0ce89743e577872246ee1f2b618810c6539e614d0384a2eec4c42d0fe8108b02f51866f2b90838df65d9097403b9c5f7105d5f75ce1dce13c7a830fd50c81b608df0b3cf955a89455b09efb026beec5e95e6c106dc3f88a2b31ffb1ab60690edf505a6d881053a2ad6e4d2f7b53471f2f5695aa8f3deab7b16fd6b732abf28a08e6850dea5b72e0e852241d88b367bf508f57c326070a516779016e2595af7a623bde538870579f4d40d88cecb5c0e7cb92ee596766bf8f20986e29340756b262ee01ddd8e0e5e225cdfd8dd170785c7089daae6331356e88f8a363d614e11735f08e6301cbfb889ff4ef75fd5582d4f735fab006b344452fef87145f47a3b1e6ea9030a8893f49f6db8cf01b03284831bbf340a46d6b59f1acd8b4ea06eabdd80093711471959525fa5609321b27ebb68be4c6951f331d1e273a9f65dbc1885c1557648cba5e5fca6776524552c0f548f9faf2843d50325b570fb14e55c9bcfd43873cb3f22ef3ab52f969ad4b8dc881e2b4ab503f4512ec0d4247a48051359092417383a57184dac6208ca80a7b405deb3668a63d49697973c93a04c4b0a2ce47332f0bfb457c5a8338ebdde89d5256bc363db82ca635b768c9f50f92d8e18b1fbb40c5b5a982b2ce9350612cd39f7ea703e6a935e5502e02063361b341d4ab113dcddabc789e4a2725c4ce03620b8244124145cf4e4dc2b76e7014ea2e5045e4ee4e309e857de645a7f5e96a9ff4937a3d93be633259d2c32075f2b78eefea25294025c078c7b90d266922a887608f90611303a433dbb3b7e22852f69a273613f60a4529c592cbeaccac2a63c6555222fa6cbf254dce9aaa176f68309348d4c41669c3a8e9e3f66179c63a9f52a5f1aed96d99af0a9fa358a130030d16ce967e4e62172df23c3b415ec735e5a95a0ce97a7ee7ae97797d3311d04c32005c6b20cedcfd7daaac2e9a81e7d1b47f06125d0373e06b62f7d82fdc0b1afccef9f71b1512b2064cd648b79b33a4901445f2e8eacdcc123d34af0aea49335fb7a5c4caa8a6e8862c0e529ea905a2a4f44fd96d2b64d7bf882ad89036a5c5609fde535c3bdc0bbb8f38cc293b6591ba1b634554577539cee30f6e51a55028c2fd9424b88b520f60844987930ed049bd9ca57f1da23a608689b76138c49d652328a37caf29ea935a021602aa4bf281d534fc65b6d791b42cd201e5810169169b45277d21f0ea3815aa9872a0ee97ed13beb0f16547213b722ad6fea7feac7b96c457b8fa1fb070aa55c05e9236abfe4381f1d5d5b0bd72136126cd88303000710926c67d1d676dd76e4d4dd6ed60693b45a0dd4eacd1fbcd4d7db6cde097e121743d6aa8d90100600777c67b00bc65521d7d9515f1e8c31bafc5d31815744cc8d49e560faac0b9633cd64c6226942c5bec46382426ee54eec6d12b03ad507c4370d31802f74b3b3384f11bb791d95d82f9dd9a6da69da4b826ba719039cf282fd4d0b60230000000000000001dfb701da82db09faaebf21b5ba1d0e7cdabf2589b385150c5b92de7775bab1de5a4bc2e3cd34dc24fb2f9a1c7963b81d11e43ad253b7a35e167cc86270d8d81fcfb3b4f77a6384f794e9710105b75f1aac82581328579fabf33e535d8fc63151c8b50d206c317c6089417cb403c9df8c77fdf642b372cec878a33d4ca874f19c9284ec88f3834d8c2aad43b2bbc09bc8adbdb78014b9ce941d36ccd6236f69397c4c315d9b7e249b8410f3641005bf29b0ed4500978b44c3f49ca24968dee8fb9a2092d1958ce4fcfdd2f27ae1f17659ac29905daf3e2bef713dbaae4418d5aa1c8570d6b94d942b279f2300b59c9e1f188621bad942d228a2ce1e67e7e2936cc993eb6f6c2f1aa0857eb2c5cae4bce770758b2f9ba7ac33143a7e13f0b2c30853b11ab3e46a81d192d8031ec09a29b2a091be40bd3e1cf6aa8ca95f020121c4c1a0230e172f13f7443b2c128c5d1f613c8edf9438f50dd5f2e1372c399138090b4aff5299ee8433281557891f1d7d14d805254b30fc507952b133df476d240ec2506f7e50d07d48fab8e03581580b0c969e365bfdde78701dbeb35533171d82346f4bf7c1619f95b93ec10c26e4458b0b2cf117ef3fe0fe42c69ca7216db176a2f886814aa740b37fc53c1cd52b9efffd66905fe06ac7174505c5cc80eb4dd68f228ea53d96b3fddbaaf3ba283cad002d3e52e210f65114eefc7a69de620c074b5356c28738be90b269cc10d9b382fba8a184b1ac2938b177b74419c744e81aa41b5b94360f34644c8314d07038e723f3b12010d353663555c86ba9c29194c6fc7403afa3773a69883f52d3ab56dc09753e1a2e40cae2eb69a6cbfb487f971f706cab04884798a092daacb5eba17db7b7073d8e45f9b781005414c608942a8fa79ed1cbc586e5295934d4f17d14f7cc7a46c30df7a779c28f1236d6ca5f5dc185ff815e88e1b69504e4f6fcbbe314dfac575aa40cfb89ad65c4448d6221973430b8daa33b91fb9c6a6c5103e43a0a2010ce229910e9532927dd54de8658db86319d6eee142ffff2b0787c2d25d736d2da49ac395c1c2648851ebf1fbf60a860cb39e7c2f99a65088235fb9d42536d58d10e55a170953ec86bd38e3d9764a604aac70dc1d12de3738a9df6e40263b68ea314cd192b57b4892676428fc7cdceacd627a1c4324d8848b04db2ec038be318154772bcc8c5cc3b21ab2e2f6c01a8e7b10923fd0c457e98ba704952ca8adad89cd0172d5ebaced644bec4d87278e9a6ffdecefacaa1e729d722fcd4e1669ed4a62808eeeb4cd22e6e0db06737c6ebd287de12eae37622b7a95f421c43245b7c3b982e3baa39b2a70dcc3eaf59883d15e4d666db50e479c431de2d698fe3e1d92725cd6f948fd9e666499133bd9edc14d7255d19bcbd45a8b549c10ee9370154c0d120b93799a6ba2e0d854d1874b9817fb01f470463ea9026b0715e5fabb88df729e87de62cbf9a77ce746f38ae44911f3cb71c456711edca5ae9205abf2c629734e51fe993bf8cba0074ecd92fab62cfda8e53c9cca56e58a950d27826644b980af95562f0c3c1880245b0cc08249c2ee49e5d7b758cc5bc865daa5ac571692dc6845e6456a1145a148d752f79715072537e4465fc6396f2f1835885947038c2f113742c3ee55481a1e5def959fc90dad7441aa943e01e8c89dda1da6b6669d076a80355510466379b56f3608529acb3f13683977e382923916407ae2b22374cdffe3f2aec7ab132cf134345656aceea5b6b590345da4018b2428fb09d5492b55226939e8174d17ae421ffbccbd1e860540e8c7221cec6a2b01034dcef6fd8da68fac4f9dce69ad86ff5f075090ef528c0cca66a1da366337a1c668e2abbe84af21153293e058b83e930969bd8a21df8ecb4e1e2b8d6d0773d341c3ad62078817386397161c4769b3636141ff19f03ecb6298310ab42aa531e696e51780d58b014bd0a3f8a203287f23888dc27a6938c018b01aacb1417dcd7f2960a14bde8ec83c7c43d192ce7be7c1fe1ab8c6d0ac0a9a91b448ee5a07815588f97deaac7fe1bc95939733c99f418167f5036faf869202023fffd15910628f0daca2decef32194f28f4a9db4286487b3ce8d07c6647acbf6e6ffa2ce5c33794ef40494a20dec84642aa96e5a391fb7888b2356b0671872f6d2d777d759058a82b1a2697122341421ebc4971d2b32457774a38638a0827d93c921ccc4099ada65b3f5877d35b7c637ada3dad8f9cf9e556ec8a47cdaf5e3a685846b10c99f4dec1129b90e9fd8d8e1e0d16d61bd03e662f51c3d4a1bc336e3ae2e3d5ec97344c8cf32f786043be94320aaa0dcea0dd49439156e6b0393864434f4147ba40d1e56535aab420424f4062ef1ffbb6fff6fef5152f2d0f66ea8d2602d74e4dbebe888cfd17a9b2e6569de78345c7d5840d8151b352e97901b3ba57dbb76881f1c460c9c79d2e7e36f59f65e7d0691571f5595a3e2d7b0a88d4f1d40f84c260604392821ced619889a673192901a495310a3db2aa65e1d88c0595c26b2bf21ea89a7789f581bfd72d1939ac5f8e139519389235d2663b54ffefb4e379b4ba27c8d94f12466dfba967f6372fde44d9122a34499d291d39810f704a34bafbe0107050283462fa30936f3a254ecec5d50fc955fd00044f4b8b058b18e9b6c204ec957fd8355efdac979a981c724f467a80f76bb92d1fbb60bb0b34131bb778264ac15292994f1d141d36df09799b54485ef3cdc74ae970d7de6149812b7abf4da5226f6db4396411b11c1b3d81036efc85983fd1b3ff28c46939a85c4d8e7d18a8d9a1d8f4cddeb18ae681730a084cf8b6ce4e571da10b79cc245f21f083f55cad82d2fa4cf83a10e5680279393f2d6096d78efcfde6db3135cb7d40fd9b46a248aa86c9b5f6c0ea685a186ddca2a5b0760556e66460348affa5561ea685d00a22b2b2419fd78e8c2ea08399d6b4bfd3fcb5ec23c089338be6c6256e5162c0c84e3d7bc573425a917dc4b85237573cb41bb2923718ff0a9a5b15a14ecb79b2e599674d30470103cd8a66e5aa9734dc68fe647b705ef9024886565343779d01b9ade5c531cf19c0940c961b09c10ed8de842b66e8ef42009c8cbd67e3e0dd5c787a4521405ae7ac774459a5b76cb89e0d78d6e922082d868ae35c89bb4e7fd46a48d858499519eafbe5b0d8b50aedde9b5ae43db83c3acd39406b2d6ce4519e7694e39c39d1834999a5facda3d31df3e5e7b4549b16d8ff4c95226e2710a586d3886740943767e00de834233d2112b1829a5d66903587adb91487dd86e5a85119627738d0241fb0a8796770d61a1f08b2b0bc451a813cc9e35bbfa66a70e8e599b59b05f54c1cf644e652fc42cb8ac924b6bdce781d2dc0be8a7efaf60938f1413a3475f34d44674b54e6eb05848816c65b09d0580db6ead93de7f3f54d5b64d87915bfb9d020aabcf6977ff87f06ea55e54fa5788ac4ab9d2768e78f0a4f57b63b5ffb3c1a26e61c37a93cf86b8854ddb309f28a36183c6aa78f1fb4561d4a8c032c44920de55a3960685121f6641e7ecb97c79814cec3317e3551b9266b31aeb6ed040c42d99e373c3128aa06057f104ed4ca95b2df2fdef903f761c4ff9a31790dc018f08021455af5f2ef20ff2775ea3ed2b78fe9677faa56d2b831e0e24f0738d3ab46fdfcd743a8898323e41ef035021f23faf93e7f1d67fcaf5f2b66d6fa42ea2fbf04617fca89370f5f7535d787f77737ad537a949f3d83288a656e723f31340a17c9ccef29e82097ecb9e208ba5a8ffcfa80922e8252d3c35847f4be1715a7d09867c1d9c4e895acd311066f36dcdbf9792154714df5c85fa0628b60f2a0e8a4cf1b14f14c16dc70669c406b2cf1a9096a711bffdb8546e616108234e91adbe086decab094c3b56516d99c12250fd7840dae02029c5e91e752524def84b8b38924a96bbb7c0bf39f9c72060a591de2d85e1ec9a970fc31c922bdeee6a42ed272430eeb9881bfc1eb7196d8e7fc9e60181dff308717bf50d69ef9d3e74142b7fabe91802b84f5b99239e9a29d88b00bada2f0f1a06c18bb930000';

const fixTxHex2 = '020000000103916c2e9812a1ce5ac298101dc2f6f792d10c1c0241138cf3ac1752a4445d70310200000000ffffffff04ea8b94f2e4d66231d45bb1768bad4eca05102dc7c16361878ceada070987950300000000ffffffff49cbd2a4a710e8cd105cdd62f8d731345bf2f398e089310c4dd7960245ea3f9f0600000000ffffffff070b26330513ec66fe24b4d94928e20afa7d6819acedab7bd617ffb7e82f48c7d19808f8e2352cf1a65460727dab7b0871a09e5ec50c41d7484025ccf68ec574ef77cc0217a71c9e15dec47b1db23042917bbc689b420f9922f1192cdb987f69a296b9ad1600145f3eae0aa9b4fafdde62bfca2badc34cc62cdb160bf4a6065b7df1026c17d3d67ced8eb604e9b9d239be832a6a09b7a885d1d4669309ab6657a2b33df09b1576c205a3738c539cc03db5b58cc08405c9e053b9cea89003265085ec2085cd1abdf509d8d6fb74bc15f5e4b039ce3a9e98b5b195e8a4dde41600146ac320f98a20613490cbd2c335b5d397403dee810b45665e47e9bd8a067914777306a8d013d854e8b28734a0429d72ff229d14b511093bd53d104344cbe45bf68c1641075c7d7ba4acb5a6a1f2d11184af0f58e8b99103c37be7669ffd87603dcc416496242f9c7a1caf14ebc8e119811dc2b869917f1716001497e4c8d9c297e7a4d8aea1a5ed2189f03c1360f10b40a259ea147f4b48854532fe5dfada9dfa2fe7389c71dfc6bfa51f248395451608c3e6a82b9fc4fbc270a779380667d253fe60d8008ad7c33bdf2ec34c608559e802760db2ea84ea4e05b069d640596cd1cd80b4dc5a6cdf593f627761db95fa050b160014672580086b24e5a84b06b529ca6ea3f9ed3100840b9cc04c2599812c1b4c618c9286acfefdf0cb9ba7a4cfff1ce47b1da1513e5512098748103dd8a3d8aa823e1571e9a8d49f3dd4f0c111decd1031a96db509c1487503ccee5b8f20eeecd3c4bf9041c7125a02c5beb310003507f4550b8f643254c00d1976a9149b1e0a9fe4baa31cf5d8501a2f93d1d8438f151688ac0a68fac9bd00bd459e98e6401d5027223631b60971da61ec1f016140f7935f044709ef185ca54a0a563b1db9c23855893a67f1dedff7b3ad6cc44851abb8c2dacd2c0322f73186b94f558234a5c5fe0201489daaad978ebce45c7eb22c989bb3c635dc1976a9149165b3daace9948960a8a0f36870b6dba059f2ad88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001b4700000000000000000000000000000000000083030007f13dfafbfd0e9670caf1872d74959689adf4a31963173df33aef35df657bc89ff0bbd94e133e71a4ab20daa213206e2dc5bbabee05ac996197e94ef9050467cc82008ef3cffc950ee8567055823526372055169a64ab432303d8447a1cc23fa000c3ae8433b890134ec5e16e1d585d9bc67ea003c5ffe0e1451329d715f86a1bfd4d0b60230000000000000001668d015380b68a630d77c55864005ebdfebea457c22019ec20c480846d5f3462adf067807463028ff68addb30480ae6665b5acaffc280e1203ba3121e39cbec6dbdb137a8c788836473ccf8ac12df62d1bf908712e1b89085712b9cab88ff0ea30160243ea961389edaa031021c3467e058ef11a6d0f022b515bdaf05b7a4e6be529f11a9eeeff81e18f1f447284dd624e2b4a135c29835323392b5b9ba6461d0e5a20d6016f27a9906ad369fa374bc410c6f77980c8238575d92a3b9c0d01f9174e0e0cbfb832ed1fccc8f49e39f9ee9d73acc5496609df0f10077a566fb23113874ca0f104cc2f49ab779826a5b806921d347b051605eddeb71fe60ce57f893a5ce3a7c627cf4e9c50006f3fe1057ea37575f9c4d919365d2eb5e5174adc6f917b75fa0aebe8e10bd5c8df7d6d75e4128c016f887bac31945b580266b95c1b3fd0878adadc8f8219e2b6e3d062d73fc844b76099a8c71f169a6d438095e5d0c9c263f2a92c7547a04a37a4b2840793c56f201f2ea2f1492cce0b8a8fd714e17ac3487646ac3ae7b49a11add5b3950e1cafd4cb6defb22e081ebcdb9c41f1ce928100f40e41385d38ff71bd147250e3f9d178fa5f3bac55728c798b6899d680ccf3c419b2c4c3ddeb5ad36dc66609d80a9f253b849acdc517e26276c664de62583d88994dd469f1fd1a09f49db5348dece3780be6405647c2d7ed1e568cc28fcb64ba278bd30d52dc72a779c201a9883c6db3810fb934167c1375833cac793c59775311cce3cca500ab639fc03efbf383e99e4a1bca8f85c5ac4007cc9166b9ac6cea0a7366526d7508d37f06072b0acddfba79e3bc5dc2cf5a11b3dc4fed21c789dd5dbadc27bfe847719ad959367337681b3b38576e2d20a5393fbeab427d5ad57f32d1469d8f8b1297915999d592e2da8b6b12873a2a93645562b9f5fa3fa649114e0af0bdd95b11a2493388845cade7697801392591ec54739c9fd96b9c0f03dccc1438e6ea18745d46aa86ab14e267b7ab611337f15e34bc5478357b7c00a415e12794d65883d8a87f60740ad420a2d4c34c090f58936d1fe4e2b12c353705584c0c56496312210aa23b9f79b5167fb9aeaf55063f602fa84f97642acd742b1f1bbf12ca3a56a7a6af7b21e97c9a8721771a32d75c96d198d1b1d392aa17a338c8fc24650e9abb5a5651c54b3d609a882ebb7c761478d7be2ba46f17b29584c7e3260dcf750f6568e0ac3ed971fcc64f7495f5f9bbace435f70fd206ab18277e717deeb3a9c9452a3f88a677ff576e777bd5ff9fef3af0592eb4ffe4ee3dcfe51ac19e9dfbe3a2b8a65d334af7cb6915c40d8cff5e8134b4a53ac4895b0cbe90992b8c5ab566034edad16158f943d42a1d84e247df04a1899afa73f7870e66e89b8f08e44c8f43415fa4f0b9e7c50f0e5e8f0c36c40e5220ea555a62c43067e977147896699c5eb174cd44b5086c0a0a384ee4be5d88fda27f6850be6166728b77107cc7d6ef620f83abcdf87601ea35131e6a6bf9014b85f9232102aa2eedaf8eedb5c9e1581acf499cb13db22a0185168594e79a4863f68302565b397529637e4911e267a7ae54c3c5841a8ea1fc3dd7e2dc2c7a76418bf5580a3e703b78620651bae0a9746a50c7b2808e227ad9d120e5ffafab0e01d921180a191e48b0e552e89739cca4f7af28e91bd28db59c603e6094ec33d6930e0531e247357f0c79562a2736526a628f3fa4a9257e54451f1218e1ff59f98d7206d318dfc826be6d86815d16e930d6c9d30501847a0384bbbdb9c1fa488af7c323a52166318bb19d3f3142d4f04b954983bb55fc38c877184092478c5574005d4ae3405f2e7aaf1ae41fc41dd6dfd6ef86e273a5ab83c9b47b2fe00eed4188240502e85697c89cc72152f4a32aaacd0fae6aae1f638545703f5bb0d8a07a4e04fd2a53f67255653e53f787439a2007c470b2e948e0de467b913b5f3e2b06de08802ef0fbd520fdb63a871f59d5a1450d3fb9575bd3d1b508abfc3076f570ad3a211ee7426232ac5f8cccb2bf6670a1ccee89a04b3506168aad59dd085d5516e1a7a5b25e84d9304879f528330bafd91302214d92ec160064ea6d9660e949df6bfe59c14679035dc8c45d6b1947144121be35436a579cfa443224c2ee6dacd72379cdb8e4672e1ecf88bdbaff731cdb83a48291c25c33a65251e883a4989c1854de73b48674cee17086e47ae40e723cdfb7e16eddd26e7fa85ee5ab6336cde6964c50971ddc8791f634af2efaf0632dd8b5113ef8c47da4ea278efcb6871d42d6bb3fa43a4b85e61719c7ce824030d1f5fb18e8df35a782d24d25095a735cd0e27d215e12cf44cfcf4fa85556fc00b43d752e7d4aa66ab9b5d7b00074170ef89ebf05f22d54c47e061f9b33fa0674ece333d7a05de1696f7da847c10afa3c1715de7fbd8f3764278420800bd22aad748b611e493129b72d65f50340acf5838611402996ebe70a8c81a9540e01b06f8d980df3cf15f44e8b7c0861d190d76bc1ae4e1ba2d725e10c2c4e7eae4ffa48a72f2b924940f876f6530502acd91d7c5739d9eacdf065365029e659a46a4d7e841779c5ae5fd02dc8f2dd1efae0c521a099cd5e240e229748658293dc8dfe814d62a6872195288f5485e4034cc433cc609f086c96e82ab442a513a99d0fce4e0006682a53419848b42245081ef45242211fb977aee52965cf007a8381afd325e179d9899c0150deeb4661561e8b808eb96343598805eeb4e7c1c75342851c4624c49c345440829be5bd345d4e04eb15786fd9d89a0dd4fcba0ad786eb8df3f4a2d85ccf4ea9b3de39a136df91237bc4c4a868deb9ffbce71a560c3173408a8dfd5ffcd6fac93195f4bf279312ec5b7903e06250d2fcf1dda87b9fa1579cb9e45105c63c29998c438c370fc97c5a9332f4cd158d1f7b3119e737b93859924848c1518692d8f7d3575122275e8ae526be63acde4df92ce621bcf84c09f857045e2fe0ef2116e0d6a1c14da852c854b8c387b80091ed2f8be34f4fbc1aa69983b55ec02906dcbe43578133f6268cec03582cb4b5b72e190c3863da8308ffeef513e464904db12a2b8ab47f7d49e87f553f01a48990fd4338467246f62ad66b99d566f1d39af8ca54de1e40a1220cf8b20e9c1a342fb7bb47e0ca7320fbdc01d0983409b840e0cab671d8b5ba77cd8a99ae2cd5db595261432d1d7cc95af1c47e934c62e696b5e77f1673ac2575a5e6a64c6184e37b8a90b99019696b94c566e2566075df518c67ccf76d2d8d17e3f3d781eb2d9cb84602a32bb587ad7314b094fb5bd04d733c3d8b6351728855442e907819724ed61c976040c25962b5675f023b6e3ac1977d8765effc550c846b85033bab793fe5ae5bceeba72616736246eb8eeb3182d87179f740e53c583c6d329950c694674773141e61c394fb47d6e145acb60589cc73005bb226c610ac6b5de0390e52a42e52530bc2c5a6f1b06081104707104aa56dcbdcbb12984740adf724f403e46b2142cd9827ee4349bf522c14b290d9eb3b8e4a7a0d4d8a299216b63005db57b79531f1336a2747ca1c056312e7fd0d807ed1e299609ac218c8ca6bb9de1b315611d0d48e0ca5b1f1eab3c3ea694fbb1484fbe64b01112f874e357ab2124e5736f7f1b03e9a5d0998cec4663001594c928a2a18457f5c92b0d0a0afc26736d735e46919be409c9f014aa083a5e90ccee5722c1c44c2d17ac9add6af40310f9929ed3c3dc72743e21dad8dfb725427ec1fa2bafa33f423acc86c0bbab1d3f4f8daee3dce0860f6fcec98414e9044ae8fea9df5ad73e53a089e3f14f1aa54363b4ea8dbcc9dbb6f0022fc74c2ddd06fdf4ac5cf7890cdc4c155e574f4c80619ded96ed2544800b4982cc3f97b7ef0f5689df9b59fae14d9604d03b06329b1a9ff414853c72153795f436953f3dd5bdf98808db306cf385b4f0daceba64d150ce7ad01fe11b0e1b933407776b8c4095779ac2e79265132c64aa55eaf0c85d07c287244046cd88fd487285fac5f2f8a1a8d858636dffaec7e1bfffa880bec2521fef409b3468317bb2183030007a9a249fdae91ce7dd8f3747859b7068342014734265ae660c34b7879767c01975503aadd752efa0246dd83489b9f18e6ab4d51a97dd202f54829978fee3777cb368d66e8bf9d815bd626711144c92d9e5fd89a7de16e4f2f48b67fa2a7c92aba8fda774be1f5dfa46737c0cdce79c77a04e163c1a7c36e55c22049422b011cc7fd4d0b6023000000000000000106230036e7bf4875605b19a42e93c4c074eb3a13a21d9ed15520a8c08daad7abbe35fcd819020d34ce18954264778dc59bd24a5819fee9c3171bd50b66111b11dc64af6968b9cfed204269bd26b6dee34a37d25bb11b6f1ce60b9fece4efab822657316b5d5ded7d92daa711a3ceb6422469ed92a5d5be76d55cf433da2d6b60971d22cce7d5a4fbe6f0591c12952183491da90d7278efe6d70d3eb1dc89a6123043765ae7744db99dad6302886f2ff0ebfe0b932344b67a9e58dc2e7fc8e812142499a33e5654fd81824040e0cb7476947966c0e2b6e2eaf3633677570c3c865041e8bff0727fb141d7d811e18b71dbe9ca9266b33314e3988abc0980687bbac6a1a4d5d0f5248b667a95dbef5a4a70b11bbffe72092fd31754eb8fc591b7f33814cfc884d9f558b1e348e7e63eda20f7d1e0cf5b92723c64ed769ace62215761036fbbf337380c084123817eed3d89a393a5db5fba2ccdb8a0f28a35b083dfc8ceb47606745cef1d6496494333995a3e71b65441c9f998ed895d08d11a4ce6af124eabf85c682d2ae949a10474487db38a166203ebdc5c71888bd64b639da2abfb54a3255e250680d0be26c604586abebeb92394dbdf17457abd9f5c18938efa4045f3f158c1a0b97a4bfe799daa9b6bb689832fc07f7d27ae8959c063ff568bee8fbbc90e68cabc647575ef1921d0512207a1d9900b5a5a335675c3a974d8f1f817251c49675bd03d507bf5be93e6b24194db24bbcb5be9b1fc7f9be99065e1a7817538d30d199ccab0642351de444aa954ba2e6bd6cec3c486f68f04915055b7b4bbf4fd96f23a4c7478ea88c461ebf6807001edf89cbf63710435225cb1c4b77dbdc89dc336cdb82a7e6ab5c5ae574acc5757241ac9fc673989427520ee4fa8b898cea71ff22248c6924354b4ff4327b612701a48ced4c330fdd95c35be47d6c809fb36dca0a383b73b5b175ce9c9efc1effab0fe1185c14f30456d0609cae85351f8a6ed594a1f28d2f4ca5966c841d308cf414e32d49ee9e4548fe3b6dcfeb752aa8d900d4979641ea80d1506bd44b0cba6b4f6f73c9a3c23542c457419eef6a7e2d57fbd338efc49725f12ae3cee65755c8064da0bc41774cc24d0e7c5422c10dfaf2024c6ebecd7d3592ddd30fca8f9c298e71a6a77990e3e1fdeb970fd440e8c5cf8e2074203c9080aac7834fd612323d7b03be21af3846a8a26be5bf7672884e55f47feec4df1eea077696d7d1db8160d550bf28a30ef263930c316a21b41231132bc11b26519f57366d09124fa0880afdc29079a8ea4fd93c17bb402edb084b181ba3bb7d5a45bcc6e141216a44f6c7e065d5cb4ddf2a6fd166f00c1ba1a09d96947f16a2cf86b6d5f2ceeafbb0bf7c713c1d55b96cb5a697cef9cbc0780e290f10203917930e7b804de3c3cb43b3f5818dff37e163599a574af8a5eb06d9923c27f619eeb86dcbfe19ffd1e3c877a68c67dc132595e4c1c920741680cc163bc0d4ea8c6f731f537a5478e9938aa8499595bd2acdae9ab229d8116c65759c1e3419497fc71309dc48fba98ac712db8aa475b2cf2447eae487d3345acc89906450a5c60203705c7c62e9e7a884d7be8fa8130093203b2d2fddae9cd8727dcec9c2ae00379a6248fd934c11fafe973dadeabe79cd2ee59c2f22978dfe0d29c64bd91b9d62ae93b088c8ac8ff354bf6cbf28eaeb559ca6f474884bac1e93c491cd8dee817d9ba84349ea554bb793897a003e3ea78b690af0cce24ab20bbb6ede040d04b95dfb10a08959732b5bc0e402285bfff7986d9b4e8d386834c9614c4d79edd6845dc869052a592b0d1f1e4928ad16f4efcf1a8479baae96ab45f5fd148dddc364cf1a31a948e1db8906bfee7e2861073a20963a908893399a611dc41e4be0a6adcf3310ec394b139b140c05cadaecc7327cb5d2745dcb7dfa7865b485dcb81f7426d68fcc190367cc53dc3d6e9957341dd66982667449e45607c237a88fc02edadc6b22413866274b0f282adf0919530d1befbd54d89ecb7aabcd8161e3b0dec36075ebd78b07c2ae4edee2b8cf5c6c971e5eb2d0b75c8743819516c924e857be3c3af5475c48bbed98a768e7af5aedf676995e6a2870c1216356298f6d088546e85fbebf61a24895c6375cb19f68649853468213e41b6d7d73be9d11a35db59416c8484833be0885dc89d200a0ad2d0571296e105db9c94092b54c96b8628e41665bf71b9a4ae43d60abd0b573eca1f134d36010404b513063255b299114fac3fe13bb84d02d8ec1cf38f07a6027d8a9987469321037f1f4434355770867191146feb403389f44f9c60aaf308b541150dcc6dcd2cac0fe10e3fb2f23f1cd8342e4c0a81024e3dc45d4c398ce1e4d97cddcada23064d15f3edb9de0917528d4f5f4978617680a8232c27f95188b8a2532b22cc44dd7f208805280698e489e42990c370d4708e15d40cd8fa001b2da4e09afdc8fdf87058e261e0d6f465116bc6e802473172d22e4952953fb892d57614fed262808444a17dfe4204f9e1ec60a0ce0de38b8ddbd48f39959527cae08d453ecc0d9eb5a967b5ffb3f7ce08f054cefadbf19bb4c9ba6e8984fa204e50f8d4426ed8f264a63ae9c583bdfa9f18058c5c45381cc5cf936b87d0ea96a6e31b83f90085ce60b3bb47ae3cdf6b890ca97f80c358eb39ed6ea09a626e28d490d24dcffc8f5d64a51260405ceb0eafa963c2b8a07549b408a9509b6b97b0e76f4db4e50d2dbc8dae56866b00e8ba759d517c13321b362741b10575ba0b20b21fd5c039fc25833b8b45f370bc3133238fd1c1aac6c96fe6f61b4d9371b239cc7722df792122d71623434a863e7bfde09dcbed2f230dd28ce147cd6952d3217f6f61e9914bcfb52918c741e82720f95c89c0467993080c58f19786cdb7999b7e33df01c1fa6e3c90b9b3db5250841a951bf880a448a5db8afddcee2b5e4492cbaa28469a5b09276407e9ff4c0768b330de88c23946b91ae072399bd8033caf13f1ca0195dcf5a8910f7f3144d99ef76323625ef3dc9d5d705b0ba1c2da8a9e8be6d71f6aea20477e7736ca16a448ba95caea2272ca24140e7caec8a2985d5783286a51dafd52e7ddd502547de0d627c183e00f0ad71fbc0cf1d510a4eb35d4a3b5d8f0b7b4fe0169fc48c94e79a2b667f6a6c22b544cfbd227e37261bca438634dd559e0fb931b56da9acad722ec2683367ba8a79ee7e27fa8a30c4a1ffa89f295c315318805f59296edd29a4c1675daf56b887c7cf537fa47ef8252b5bb1b54c667d858faadbd0a55bb976ba40177de4a4e1212d98f53c5f75628919c9f3f3ca8276c3588c5635dcf9b77976ca349a5b3db174ed399959686f800e6670e7b1823725f9eb6b767e818f3cff88b1d9dfca954ded5ac72771965701f907a53c01c619d31d8a7a69ab208c0b09708ef9282b04f34330e17380c915f54c124f08b3ef9c7c94a3f4cfb8d9145b960ea7b970e73f2d836ce45a1cb1580cc86ab3770d4d3cdbbf32d92154f8c1b85a67c0fb8dd378987ed7d66ef2a6452fadad75c372daaecd501599d0080bd5c8752a93994408f9ad99720d2b33d395a2d1d3fe7326687f3c7800a13cbf0b26fea89e352db858ddfa2e75f66917cfc9b6b5151a0395a2aa2fefa454eaffee2178e8225a8c8cab3c891ddad1e4f681fa4d1ee7a6b11d189d0c32ed74b610823b7ea62ae9bd1fff7f0f28edd271d10e83f79d66243ee3093226efae486b4cab7de8f37f8fb0ec8572680558d375d4faba8e8a4f4a29a5d7e198cacd1db931cbe638aa1a091a25c2fe6d3c6fd402de36168d1e2ff4dc5827ee793272163d4044bce0004067cf26530d6cedc776c8fdf980d3585660e2b41144dcb3dea6dd75e45277824d52aced09158a5fc7c64cb81901cb877ec7919221eb847a9e579dfefbcbcd5982fec5300bcd55dfd39001da06ee5f200a164298059e8522eccfc9a2a602459038450602b0cabaf5694cd19ddbb6fa0366890026fffc139387f7b5ee5bc17bf45d06efbd76656239a466353dcd6500ce96e0c28a17a516ae9050e2bb4d971fcbfb82e83030007569bfc47db35fd06995d79fa14f7422fc998db49c1f3e6d93cd21826a55726b772d8229c81c7c25742b59e344976322e89f6065d4431bd0170dc6816fcd3719835f9e6395dd20a723dcd4d98af2aae66067106e17cad7df2838e185013e84c2e6467ced2c738493d7e1d958a73a2997afab742912fa39c03329490e212365fb3fd4d0b60230000000000000001cee0000751f5de0a1f57067d1c02874aefe4b4a0d054e0d6ee9f649b37e2c5067df89ed3ce70cee17fa4f0e3ede7c4ebbbf01ace1b8f53337a867c7e174c31aafc54e57b1822de3f9582f9c8932a2e1470e83bed11e2d028c55e987c1f34648b7140d09f1b205632a08e22d97583643d2c5671f183ead749b0b9da9b90ec7fb2b3e937395a55212b0d3bd96cd959a68a04e19e854cac2992d551e0b1057fa4eb67fd227b3023c80fa423f5566629efda1ae10810bc509affb31922e3569978a028f4e11a45ef21bb688b8c0df9c4836e0578812db7245d41f35c6df29949111fb611c7f7916f7db0760c2cd7481be287db0df80e6f9481f5e51d4f94b6eb30fce60a678be4789dbc4abc7304e31d96462ea31f8978bcb985c5c3e0dd172118d456a31b04edb86ccad2d379e3782b73665d9e5f24bbe904e20201c2548f2f2c1ca4e3482a0178ed266457f2a1f46690c0b6990af59c9498ed100bc709a25bef70eb7209f3380fa0ac1d018b7da5351ecf063879d7e08908e5a03cc843849aacb32658ce384ea7ccef37d7159b2a7de0508d03107e58d74564bf3ee3f6c66e9ee11e2d0cebc6db4da019b659431f1b2bec58a8edb73e35604525f308574c11e683ef9f565a3577c09febcd942d0deeee6a13ce534d0b17d4c935530f0c5e94ceea656f07fe9744bc26621a3421b566e1e23c9226de74bae005a2c46d2f08217d2a12f4aa99d4d631d7ccaa5645939b681c8ab455dfb70e697504afa58a5a1c86d9909f652d3955d1579aa1dcea1ba518aab80f7f8d9a88871b68199a8f1c1a509489a311dd0331983c964512b3ae28b63b68b3660a5ac15305471d749dc6a99906339ab87945a217e1efffe3a8bcd163ba24eb01b73dd59a550a23f5a8f850da2a16658828a685fe7455b1ef8f600b98bc165e8126505e7e366cf7000d14eb32689f29ca2fe6280830509515026d7cc83f7dbb1a0f98144efff49a20000c7697ed1b1ded296bad8e7708ee0db9360e9abb9e464d5e62413df030d078ae8cfbc3e1d104a08923e0146390e4571e66fa38a0f3b3753105874ac7b8f433f51aae390a411482bb5671fb7e334eb41d55ef9884664db6bd0ee9b866a063168c99b6192d41dcd5dd8788f51d52a5ea73c7372457d85eb30aab35ffb8a674cc3399a608505efc290aa46147888296147c83f53eead81ec853ee4c91a81dc6a73f546a141efa922a76e8cadfec4857a892a8533904b5fb52968b70ec9d2646844fc6c7744689c0af13231c97613c415fd83d306041ead4f23d2a8982a675f47d4bd36d35265ac693c240c9b0a888c937984e21642513e93caac543234755bc5970eb7b5b2c1ce924f2e382f5144eb0571c186437fd87e920266e7cb39b26f46b8e0c16cd2cae2b0c36beb5700d5ec62b7d81e8ee49458c713e5deb9160915ac1adaad8f0abc1790a32ad8251c93fba56cc663e0443f9b229ce9d46c9e1709fc434a41ea98c5b06dc69ab8118c4d3826c626b275d86e855b60567a20f24d5407b79c911e3ac671ff394778037b76bd795be5cfadc380a874b653ff1a312f7243108e212ec83fe9625832615221956dd53fc7d6da5abe17280f750c8eca03810a0ab7d14ebff4413b69cf8188ab7cb46bec22d49ea6fc319c71d7b96c374ac1bba3a475c1285644e248e259d8036a4e72ddd18497079f7197c3edeeb7b134c01256122fb1908d78fa43a50855862d61ba6f33be6997e2abb949de0a8f3e653db22e0422923f587eb2de9d95a93bd3467479f8d6edaa4cf7a4917b190df81162fe08088efb840d9bbd23a6b937c726b9bd11470b8e5188c7d55cbed3489e6c2337f4b97af67efe40de04ba56bd34d671b6b58aec775a3088077951ab3536f9ea47d3ac517f40a4f32e596f5971b32e7e1268a73d5d37a418ba9ec76a74ace251f982bf76b3675e8f8c6ccc51d472f24d1116f4ea073beefb1fb33ac310bd7811f461ef7807a91c5948ae39d91a45be7b26b82e2963e49836d4d3a65cda8c8b4eea5b723770cb6c8732b8fbaacb5d157f9ff033eff4d47981b3bcabb83d1cde259f6e07615cbcf139e006d147946e5df54d03419621c86c1d1e398b4201afc1bd0c65dca626bb667a6462f81240f998b3ee2b21e0130c50da16b6474f40b6576291e951b2117e110d0ba8ae02fb24981de51bf5191a199d6421d4c24bcd0ebe7f9cad9af3b72f218a8efb6a56b101a3ea829504644c3b6b0910b039fe783b08247b024d524c201037fe8bc20e0c29efd3dd0fb482bd69f6288320d7a95b2f4f5f4387fd0615d5f1a07817644c1519a9b2c3aa8040c4588395c2bae0252e572ed195f16953b49c90fede311f4b99cbb017293fe74714053dc721a4bdde371d4b1591edd94614c82cf399f7386ba9565f9e186c2b2c9671973c2d0e59df31fd34f67d38194a0932e23d8e9e070ece17dd520e568359c714a9f338fd1bf877b7dabd80f91869fd5d59ccfda235a52f1f32900c50d582a050217e0cbb90f1066dc03e931676e992894c9bf9d96310588c1b3249aef4ebff9d985de7daed9c317467b290bf792ba853d2b6eba2e84c0e994b3c249e1c0bfa3deae700cd40a24ee6a32d95c09a0b35f7d128f49260461ea696772c2b5c7cc079536f232fb66113efda49f4939558ec8ab8d1c8f2363a28bdd4ebce5dd6fd92bedad1a79b5b02a9b524394449e3366aae367b2387baf5c7f15d2b0478c3ef2cea9594045f07da30988306f06b51b2cc95933bb7340c69e8cef96f1b1fd539e8b4b5af8368e254c76acdb967de56bf042d64fc69b60046d7bd11a4ca47f8b470efa2286bc4b840511ce3dfa1aa2c8ccf9312739fd4685b8ba10997c15fc0b6b6ef5cdc2ce596ac4533adfeb2fe4debd02701d49e8c88cf9cf608f764bbebcac9e98d652f7f2c6a2166a304a8bd947353784a668ff5d5c61773280b31d204927b7b861828c8cc7a57911b1d659d67147725c1be28a8797606133d58ae91176e0986da04eaa7be12251c6318abd98d9b3bfc055395722c099fbe6456d013a7afc6e3e0dc7ff004ae0acbfe3f985ce44e1b4d2a83a272aa6428753d5a9f7c75a0c8be62078bd6ff88069cfbeb80cac96af403d31fbaf2bf72bb5000f3d23ae0ca254a72d9cfcea75f38fdbcd9610951a4d17b778701984c55797a2d9c0a33c2de145517426b7059cd41bab574fb75ceeadbcc2fa1a52050639b40e771fef2b2728e4afc27553644d4ceaeca0a6c2f7f7ba466634ae671f6908a63ee52f7c178c93616ff76aa04e0057bb989e33af493c0927abadccd14e0f5f75b5bc0c51537625b87d59b7a71620e9147e3474662959c26397b52419414572eff4adc8b9cc0f0ed2b973e54cd9854777ecb291e2f7e2f42a5dfc6674a098b126897217616496cc7a3630fba8206243865cf204688a25c8dcdf4433e591493fbd348adc10097a36a593466627d9498f86afaa694d072842be23a0a5f2ab85bf3cff955aac08fd260d1355518551307078d44115982ee78c882364c5457e97f37feb5a5b35f62aaa8938bf2d6a083ea3e9462519d7efde091eddb2b32f538aeb1a7d6190757384a0463e9d2d344185e69693fbbf8ef45bcaf1e8c1ede3a37b4e26e36f0ecf9bdf1636819e13580b39178f34f4af6fa605431724345478a4c021909c02fa2b567910bf047497c319a945c8a05ee47cf23946b1ce7305f398535cded4d915b7b217133c61b1f23a407e93e135296e9506ce56fb04fed53624b51db5e352eb6d509e0600ed7bf425588e28cb844a638d24a22428067e1026ec11db612d931dd5705b03b81b82acdf3952a08cd5e224ba5998af604fd467fc3f3b9ebca17fad785c396db6a9990dd863b7d1a5ca4dd4666d56fb02cd318d6723e697959671ff11af9035475d4c9f04db6e3de1daecea268f5290b650cc6726946cafb8f0ca11b50785091b8f87f12b64cc8d690ec806f216074c7403a67226a390998fcce839a597f3fda3ee02b2d9da39488b4c12efa8ffa2dca1a0a52c0481ca947a04e5c32d00e84d270386e1bd6272c53462519775abb92369fd4009c783030007a1ef6b40d8c489e7e65fe956cb555097e455011cfa839ab3b3f455ec6a3cf90277856700c002dedde94278667cff9a241df91b581cf3bd6dd9318de81566a114b7101a9f201d6757206106e736e4b1cc5c5b5c530c24e9be88f3c102dd35b79e994473f8b29a1967aecbd55aafe39e23d9eeb22ceed4ed543a1a660e18818d4dfd4d0b60230000000000000001c49601466e87efabf979d1cf6f4beab0f5d24fbb3d3d3adae2697490f668a943517757687960c685a448bdec5ae26e669ca8565269e0b954c0a4eb50f80baeb118b5ce21328e909c984edc637f7d62e20f0d27d5eee73a78ed82f95b2ddc37d85dbd7814c5d0366340a4d99456a6125fdfde5f85abbd7e0ec1f85826491d168d16adfedad2551abe8ab5667bcac3b183fb9999eaeb292de3a9b763d5bf3d4a07c00948849940b0ae43a5b8777d69d34582514ce655013e747bc85889583d8c0d2c261c03f4dadf0272382e06379155c4898e533d6ccbf26fce8dccb80a688f8f4623372eb397f50fba231d7eb5c3c3d40b30f49ed576d9986685f8794802390f14554db9af2f303df312536c27bbcbb72ba75160c49b5b93a871880992f76c6f02753d963d2cb8d3a06e65b8e75cbc6d499384f815c1347a4119ba479c6a7e8239890b89cd73558c4d73a284f2c00418b14bf5ed666874120aff8f7633676eef775f182725522c5c1750800549428c93cef49524234cac19144e9c3a9a8a71ff0335a83f1a59c850fb4606e141ee828a7b48031e60696b0fd94cd8bc2300f4db64d616f23fee17dc172448b7658d748fb63bde8b29aee083cd2132f29c5a36d8a0a2b68c1118cce64930f6be214e50d17093ec7b8533be99502db6ba7843078cc09992ba80a8f35e7e362dea0f521a98615948e6034e92bd70d859f58e2839725aac08ec2701b0b668893e42fd0140e0ec95e442c7b78ea3b3b45574b14d71fb12c0cd8860fff6d93bd469410b66750f30625fda57b5e5f821ddd3b9c015103488a3a0f742e107b1011e88112ed2794d7f3cab3a8be7cd495aa6dc9d68aeb954778dd165438d881aaf41687b7e836ec561316e0e9c2e427e4f7d2adfe52cd1875b103c064b888e7e3747e4abde5313616ed5edbf9ad8ab0f524758fc1b4b8f8f73c994db943ab8ec2d0c5529b0a7fd05273fa7e48052d5278103d51320ecef1d599b6aa497bebfd2a843f1995be60ade35529bd0c2c7fc3615e8059d2fa08c6dc0e214e1d356d02816d365511ef724db6189e19289e0b67f05574a1a19e095881603b684a7655c31bc6857f0145e47205affd811f30060d663ddb750ccccca804b2485a764a3c0cd668ed75e9068b698c7fb827722fd1b5e1f299b45cbc2c66beacc16d853db40f9ff2824e13ef3f118ee90ea47c90b26795628d394a3f32ef7175d8b7c60fffc41baeec2d6e51509317b9df097db8adc29a0c40ad29ad823e0c9800c3fd7f7fba6023f01dcc074f65bc85d69e5e9441aca18123779bfd1d9dc5c616ed4bf6b19fe81c56e0ae81a6411dd1c1a924d5a2e740778878d555b94ccfb7a43dc670f1eb258ec493f50804e2cf0a3215a8e91996039f721937b9e6d4f5778b270feb65f611ac45353f158b2cfdd569b683b160a50a1d071cadbad7d78084a7267412d6c4cf115d31691b4ed3835b6a2b07dc7516bacc0a5c31f2e05785c563d4a0ca4f28c0b89361985993e2f9430beb14e9f72e602d430d73433ad881b4fabf13fd939b45cb523f7f630a585cb67b6f92ba0a6763870fe3c3eabc6b61daf1686974eb182bc79bf9ed9c2513a135da8e5b32ef1f9b3b7d430f41eed1a8a9442b88fd7290c098fb346997ebdd002df4640e9c9cd655e293041f38aea9a031a1282cb87e49ca6f2ba4838af43b54879ad22a27d72d1a3c7fc94f9f1ba84244c48aa131d9e8529a52df672125e77c78ab8457bb1b88137303fd2a5fca84372eabe072a8a1baf8b84997382e5fa156a4df37b2cb01961ef3a52745412e378e2d954aee3a094dc497926918fca99764feef0a631b472d3a0e38630ed2b4ef23066d63cc9c1f7049c7f31c8ccdff25a0cd5afeee0a47df70c490c66ef0d90ec5414a060d879f21812c69116fcc8512bc692bd43898151a0dbd7a10fd549c696939a7e4d443f07be5289c44cd717d7a1c32b16a7fcd1a33a42202014ad7d6d0f5859a067fd0b7ebd3e030a20132e73b83fbb6fb98ecb2f932381b8379e887e1ecdaec2a561ea82617a9fb57d48bf1d4caed69a138af7bfb4d2ec3c5b7f9aad6cdedeb195873c9f2054172dec4f5188cbae7cbaa0266add085525c489d2f19e58213dc7101de2751db59c4db5589856d0e315023704b61661c4c3e62f8001ee1cbf2905997dc4d06abe49186ff84baefa7d9d71c0cf1e65f77d8ed2c8b6dac65b0795851cf1aa704e43e151e91159442279e8529249a5eafb6336524b12096040206c5b799036ab50cd4c01c4492ab6238c3feffb912506bf277e83962600af867761bf4b7e5e0018f32bd4e32c17c7cf2ec0a7630c9e0f589798cae5a886564261ae8d993420f6693db4088dab25eb34fc5efd4f5923f5c62ce57a0f0dd992b19acb39811e06cf3c2a5e72e7a9c65feab0a4574ad427c821f1f3125f36ba307126754b78b10a50b6f1614ecaf3f15953133bbe5b8992c08a60a6b994635ff0caf02cece81c8c3b3ac6dbfdde7185cf5b2efe21653d1e2ac83302ffd76c279f84de41a769eb7140e46c2941bf874cb7f4ab41292f18f166f58a308b56ca616d9e0d144e5d8aed300adc048ed76e2dbc8b2cc30691c640e599f128b9eff856252dc6fea8ad16e1c7a99dba7259dd593f630a6dc95fac6d3514f4fe0bbd5d21fc67d3829312cc9a4c81e7d6c88a9a6106f979c6b23e6cbe5402f154e14b3bcfe22ed6a660b31049b1693a530236fdb7d957e95c01ca3f6d7e4c9ffa5a599fd6fbe0e594985ad58e24267c29f9c951fdebc6c14b1a94e43ec9656a260fc125962b0fcc3511ffa860ba467bbf034ed22540ae5133bc8348070fcd62275130632caebcebeddf37c26c019fdefa61a75df680fa01bc36af67e929cdce0dbe6279523feac74d2558155c98a66aba7c3dc142eee83e0f55ac574be9368e80691788ade1c7fc9bc81a4618d18922086675d23330b17661646c4d196b423525816ccdb9e89db682705df5a31c2f6401df3444a8c621de23e686eae2566041beafdd9c481fc5f363d1d67a5687523451470088202284893ce68bfe15c757443ee1195f5cad610f82f146fd46cbdb161760362a2d0fdc21319e3925fe55765ee733640cb6c068c92039437c67ae97ce0aa91934a41c64e3aedb6090f46b19b07adf0d45f41e233fb49a509d86b731c6638d3f93ca25e01ad8cf8348718f6b7b4cedf62931127af7e9d92664df0825570651af6fc7e64932c0e206b7da75520f0542b95e8770766bfb523c3609178941c1603cf0695d668ee964178c7fd24f93feee9500e8ba93bbbd42e2b986609bed9ed9ad2a43468bd40c101e2237bbf932448b3bfa6995c13359d22075c9a9494af4b0299b13081cf39f8f02fcb6c934c8cf0959bc78eeb9fcb08d6eb04c3817954b9d6e3856ccd5d644719cfbc0d9a8f1de808d980e7c020333be9c643378c8ae68e96717a04b8d6324137ee3470811cb060890b9d5e0a30c8d5d7d45694915df0c68bb848d10a0656be6af5a24c2ed351b4b10249d1450ee2eecd0df4617fa67685f2cbec2f46827f791de5b095d1d86cfdfc25ea2616422497cda60cf1ce164ccfafa83c56b6e55142bfdb13cbe8c9d7f0c0a8723b3c3fa88b366c287413dc09d50fa0fb2bd4aab102b95b2ab9a85c3d7d94aad5de8a298f7f0ad82ed0dddb7f45b7c037f95ad2263b2fd99f9467620f46ea9011fe71b2a793629d67d14d7c41b1a0c5570ee9d6b3e5ac813986de2cb10e59ecd49483d7a7ffa1525d09e9d5e3bfe1e311f495358c7809f119148ce65a03ae98cd8b14aa74c4143ed4cfce024d4e3027bfab91061b241630004e0b90368a9142a597caabd4e3da7b0caace7f85e26399919ce076cbfb0e64e62fc5b54c60f4245243a407d2c97cbc13e464569e03cff8ae36c9ed2e94b47d7e9c91df88274180d331cea6b83390d0bc599e99973b34e28b0bec9caf96e0187b8c48d3f3077e9232145f3c9fcf23cd5be42d7185d6e520e19c0ad450b99c9b76192e884e0101c221534e00929dbea3fdb460c62fe66e4dd678159fe993c6a5c1da53b2660e896d888e83dea3fab83030007c275e0116dfb6df0066897e513b4b5af69ed924497bde52ff8be22febc3c4b731b8c097c7c1cb6e7102f465813bcdc2bb5493a9e8cf82d07fb44400cc533af521076582551a4cd8112e104a9a63be5eaa1b79a5918f3534126b8ab09c76eab2b31d4bd9882bc237d54c4f24e8c97e0569e686dafbce914b0fca79a4f0de8ca1afd4d0b6023000000000000000120a401d525867beb6c5f26dacbc058686da8c56580580e03033534ebcba64234e0ef5d78a252d37c22687ea2609a1067e43b1918bd3e69005ba544eb75cb7d0b5e7ce78abf8ec8a00373ecf1be7432a9e6a52e48b34efcd7d0a0bcded416168fbfb95889a45a6aace93c726a5403b8acb0f07a8e6e277d0c0e52e66e500851f1d141dd792e299c0ddfe48abdc58a7bae0a481a1e58b13e095fc9ad0c223df2b68102885399221abf42de33878eb291a26b6352bfa7e3fbcfa02e8f9e459e98436deab7bf2c782db50377657d1331b149796587288533866a0298f1b9bb5b2729d17b90d0a0eed7f7e19dae40aaea6dac2092022145117db3d5850167e34d1f7e27c88d32a5b0a53a2d3817c709d9bd30fae5a277b8d1f2f81ff0013fa5233dacf6160af048347decb8891b142df02158a385aa95bfb8b8919f59e725409d13ee09546f1a7c3242b3c42404ecdee2fc67b56dc82f76c3535d3fb88ba336344b670e2cbae1c9c76920a099a4a469286b3ccb5eb72f1eb1d3924c12e83b1676a110a6ef5e7184b09ead82d8a75be938f1be421e61061645db6143cf83e34f206321c67851b5101bc2d22adea8da5d99507f6ce1a42f54cf1543ffe4bb90e44e0ab70162dbff482abb63ef413b98ab39540ce519e986d75a2c8ddefaa708a3d71454e6fcdbe07846b20e6c879a0074c53c8483a03c7a375d035665732c63a4e7b9826bd07caee3d4be68225a6e2fa315ad4492e30b45be3539fdf89c5e3c579854a396fdabb1500531210b3666af81404bbadc76638f1adce1507950120f782ec69c02daab69dbe65d192ed4f57983786c2feaa456712944b8cc1bbd8ea2350f385d12d60bdb368c6658c4cc204a85ebd8b6ff2155efa055913498b01686765dce2c9418d87c653838d92d5674d96436b47fcad9cedb8b346aec4bde3b22997ef9c7ae7f84f98c76024af5f333b380559a95b6b00ec9281ee345399f4cf691c629e089f8260ef67279a6e4e648fb8dcf5d821c1743ce7ca2ea3d50328c4520f57657b0ef3af05ce1b6f9001961cfde93f5d4316bbe5b7bc5baf5dd7c0a96fadad2ddb27f8673dd9d92d189c4d211d0c304bf5eef0fbffc7381b254d522a5cc98c611c7ea3fc7733d750c7522d2ee95b94b92b7d899186e81c897074a131281b2afe6136a022a34dfebbf982665539d71ec4ed033ad38d077c4646b01eb4cfa7c32228d181e634898bfe5af34594cf4bd1b772dde9ea0247d2a69b4afe35ab8d27f9df8ab4f32c0eb33305484605bf5860763301eeb30acccafb8f6c2b0e57186c945c1c42bc2f908283e863786cd7f11fe06d1f67add1adadabf86c422a721edda45384cc29634e2937e7c454f1374094cf7731f42509dacc5e599e6640d111629088e9cb618ced96befdbac4c708bdc84e401b54064b2d5f02aac964962909b0a44cdfdc1964f4457534cf6d9712bb4a2f14b175dae717ef02ab7b185c5a14eb2a28ddddfbe52d640fc3ad3c7a723d92c14c0a6b8d25203bb4a14bf775db7d36f45f6c0fee200b9239354f188aef97dbd9d16ff97a1a5eaf136ee6e1b9eb1806e57a50aa14ac7895644b29a781961abf3f1f80a2f982d4f63e86ee848ea1fc97075af4a849199199a436142f835d8dc4a4741a3bb33f55d9fadabf2087b35a9349ff66dcf719141eef8b037452980e445f13bda04ec1a86d68884d9774e2ca8e1f3ef58b726620509cfecfd9d967d026b7ba26d4163567a0e711b43f843cdedb9ea180f6b34ed4503196c5115a345ad2594f5a81babac028ab717fbc0f7d14e30735b6b15b1f23a8cf71f6fbdfbf8030408c683ff7a828cd4c88a5b25aa68fc6cc8c9a327c18e260c91e35515cc7e0cfcd5e729dd8396b06ecedafb9fac120ac1e61c23a4568dd5931e57478736989b10c0f00fe0929811d1d10281a355fe5c0294880424253c53890126b17606d6d51d3949f6248a87873346b13a33d1f40bca0a0aa9edbcfa54c7f7fa662ad8db73d8a4833a195f545e1d59ef1bc61411272722309e8677d9faaa04ba5d8a1bd0c57cdee05cf99d017dfa01ce6389133425869f487c0fa3d77fd8daaa356f9431186d2e14bf76db73f5200edfe9e24023fbda00f72315f67e5ade6348d1e36bdda83c91e80392752a27bb77e1a48d5c094ba85a6e7582ef96a38d6c39ebd19d1121e7b26a4eb5ba984f67974b8c1212516ce021d13554687398e5d3b012798460fb663eec0dc9905582bb7cc8f23c1c8ee402daa3a18cde615901b3b03e068aac16a464527d73264a0d46ef47f02ddc22f60de0e04d88fa0bf761be9efee30cf711c9b35e7512d09dfb49808840a33ab2a3ec3a0d8f96434e677ee3ac4c205845cebabe96866776419b2f0ef573cd4704ab22261b5adaaeabdd9b6e32c98d9902072d73519dcabf1ca0be840faf470aa016259400d74e4a9a5ea692fbb50e73490dd0ef16293b93388d606d718080abd2c8fb1ce50fb0dbe448d0485d1e13297458bc7cba0ca49fd251cc6917d8c897b6308ffdf89545f50f92b5be55e52fc39e226e6a182b410843648f97aee31590465ec16f4f66e816b434073344fc8fd297603ee5f642247d61eac08bb2a3b7e4c32006e549419b7344e23a8ed89164340640a607a352f6a4139fda9e33d02a66006813822c3c2a5edabc588628da14867f6990f4efdc3421ea9710988a9d66b2abbb69d28b194032338f717e1503fb2607dd7e43080e089938767c8f83a919d0fb1b8b8f7e2a2a659f3a81ce6e513f3618871b2e3a81f0e1f03b55902ca832ba9f3d24163675f4d565b0687d05c9e5fca7e344056d0f4104a0ddd38e8b91968c649efa84c09172ae8c77ca93e47c3090d9f3496e70be7197231ed5a173fa6ecb4ac2c4924d248cb803709759a776413b90888604526d47fbbdfdfd3a4defc75c5a8be39d8aa93ea331506235c9c80f11ef7047e0bbc9db8ca9b42399159f2023c3172bcf299faba0e27de6f77fc02cee8666ed6a223affb6c2b258bac486ba905eb4b588aca81f86ee0d294f0ac8c1fb5616ceb6e2783ed4d1a227ebc1edd376eccfaa5f76625e21ee934765415920505980847f55f5005bc8a8785c1aebdc219c92e2fcc6f16eb91481a1ab309881a56a900ffef1e60ee920ad4625ff37ad0fd5d19e4ebeabdf1d818a822bf45e44b8c86421c744c3f81699c3cc3d2525d86a9529fe47b70fe3fce31a53d66376319ba0e7e831d72b690d54198a98f5c5a97e3cf1f24ea4cfd9f28ff95d68ced12b83687616ac32be4a28ad208a7593dfd998e60d3215f08bab948605a2c13f2c4a38a4003bc17bfe08c6362e4c75e318a5224800f28f0f29bc856cb285ad2d46913f010f75f11eacd48b156be13045956a4aba4092315e66cd96d043e3c0035aeaf90062f9a858b07b5e0e9b275719d09efc41d4525bfa044ad30b8d62dbcd32d854a3dbe9f44d3523abd7054bec8049451025965fd57bd9e3c77bdcf0232d5554ff292b00fd08a70918df64125d420e5effc386c10d0533178c2600e7961c2c0cdafbd07542fdc108e7d46517f5de369f9720da520d1e8575e3abf2c1e42fb6194e49f2b4e15f5d6baf5caf361872cc6b96bf177bf311102de5fec0489090cff33a695091372f876a37d82c2e9a587e8b38064befb9df8446f01c21fa4bcd790bdbb76c62bd6b98e5c4ec1c9e8869d44475b21b9581d58b59419d478e8d0f65e7f50cc9897f83060ca732fa79de10a824fe2c7e4a3956bc21b8e883a715062249aef8a4439dad836ad9f102a0a889ede348bfb3a8e2d19d4be917041b21b9713fa8be8cf3093fd3b173d9c1b24c12b68778ebb47495f5afb19db461fe15c48f61ac308680314262b5b587204a1e5e535e7253d08635d2c4314467b13bf21c927f257e406cff54d84ba1a91988d20f28a2a443a9d9ad1b8b001cd734b62a313f27ef34115ad0a0bcb362eb248b23ad61784b70e29d4cc8eb0a6a6f5f308ca684af6d672b491a6c5419befa9431190c70ec4670dac5f7778c8aa960666bcfe1eb504fe591ea6804e21ebae7c1abb996c507c0dc7e5b6ec4b2a88303000718ea525dd30c990d2b1e09a9cc51ead130131c9bf615072d5a86ce3b4ebdae6543fbe4640e9bbb32e06aeff974ed05b9b35ae8affa8c1357427ba78db69d129834e63a1616db8163e4bf75ffa1f23d329d836e114455131eef3671006049d8a28c4e38e36b5cd1538f586096a613f2cd1356a1233a6330e3756192f4a6b39fc6fd4d0b60230000000000000001d35c0090c4cb75327d8b8f8adf9752ca26d1dc7d7d92e3ddc87078dbea10b7bcbfd62dcf81b4d881e51bedce6d6701c85a726ad7f46283eac85d236f8d7df34bb59c1b41cacc79c411ad8cb1dcaa2078c2aef06a0c59bac03b07265e4f787858b2640e9bb1cf40f3f26198b595fad9c4fbe091a285caa4921cc50b9cf013767e62df0579acf2fee295e60829912a2a37739004171f1c851870327ebeaf6fa851d80cbc3ee612d4343dcfb10385e097c6a213359dfc22d77170e9f8aec8356e9eb223c742f2e58a8ad537740467a7f15d4142318559d438916dba51c2d42c8663376d5830a5edbd5c57fc6429b0023ab93b21d1e884473fea8c49956d093c40416a8ea8bc26784e672be1f0eedcd38d972209bc0e3790d5be90884ffe656a7fba5b75fc3039dc00eabe939a8b7e5431267ebed713af544c0632b7599765d4721bff005a005a683934de4dc971efa291208e2d5869a6335c2a7cddd1ec6c5cb69b6a00b25c0fb0357afb48c660d3444ac7c0765ebc715ff58d71a3c0c3436abafc5dc5037b69cb62785c7fb2134479fab38987b947e85e2d1371c42297b937e558110cbb975120206b079f8ba880c74fc98b3d82c672b8c23ec3fe04dfb094ccbc553491cc74bd3be0d97f55c87076892dbd586e45133dffaf0a9ccee9d4a2571ec23afeee37ee6fc2e552dce7b555b8cd402840a68469ce416561e7f6241a988821adcdcd80fb13e552edfc9929921980539c6f787ae92f8b6e692e0fc9bd108210b9f2ce36bed700379a360e846f1a679bb2dce1fc35bd1c5684d2f90edb1874b0f0d27f45a18be89ca53376a04f044042a90821dfc6e992b0b5705b88a712c0d1f6f5cffe9c1eba850a3472a6a549457b7bbf91a04b5d684c697a4dfce4aae2fcf50a564238ebe10f25cd360c392c4089326ac6323ccbd75a708942ddc756a1d65d9eb771e0f1d28bdf703bd91a35e8f3dbfa1c436de33b19dbe0fdd60848658e7cff6518a02e56ae894ba256037826949b592f5bdb1e3d847f0e3c5a8e590d3e9ca111e3aa6a5b8500a42f401211b3e95397dbeda686984852cfd2e5c32e32c213940aa5ccb174748fbf8f37a49e0fd4b34c7291db13e6e2bfd5411990f5d839d821865a4dedf2337ef35cffa8fbe1fc9c462427383d3f28f6accecf0bd329eeeac0873cd15540483e3e920d7ac00b984fde444388b282762a38ea6b854fd99e6fff04401bc88591a939f399d297c57a3f22f60cbc77c5e9a7ff33cc3d3fe7bd5206241660978170bb06b75b869f208b4e9c809d84f2f0f8788d1c5648715eabfeec68844ac28ccf5b6eae8a5d13928266468731df3ba17e76757b42bf4c1be811f3fbc941d156e0f079f96ac8f9449dfbbb224c536b064d267c4df8dc51d16c6ae46eeda4b48a0300c287e1e5fea167047bd8713764bc21f04ae647cc2681d871a2b79ce4d4028e0bdbab732fe235367eb7872c35ac75344ca5dc1361c7ec5b9bfd7dfc962c008b96d1cdd3cf641bb6dc7b48c6c083e29f133bead27eb809a492f8e299429800070ca91769b1cded7a769b2e10d24151824982469d5c3667e084edc18ea68ad09913873adfde579f2d7dea9bae299beb04a42e423d95f03e71747520d89bb310209457d826b931c63fc5b0c0247934a9862ab107505c37db16e2945b9313f6512bce062dcc2859132051610b807d401ec72ee0d747f499770248f4221a19f4b4cf6f7b50af43e4383e0cc25133bfa5fee86ecd437177b95669e5fa96819b3bf7dca2b74ce721fcca16d0a9d17b5152b5d922e23bc2ffdaf828248ef3b70917775485ae1a4ad7b71cafdc4633450823ce1baf943bb9725a4bb27e3ecec0aa4378f5fbfee201f356b5045befdc054ae9f25111223233964c58add28c1388880f21a23835b55895a6668fe5bd3baeed32f99134fd453701d049db8fb6d59ede889a514fc896ea537d1c7aea2718fe3cdb15eb23e2d38667501e53d908515e0ebd195c9233985d3733f11ddd385f71ed6d552ee2624746ffb07843fa77ecce3b81e99aeadb0d61272680977f69b1d5da9218b7f85dae7b9782b156300ee13b21d5030644f5ef425bd93db583fadf00fbd37b4333607e536285d65a3a6dd9281a7c88a829d0d1cae940517224142a4e5588a415068abe70be39d528ceabf112208882a18ec34ed89f8e3f854cc9817641b64f9de4e3e291ce59d849aac265f289c9cad833f205911e93fe899fe86fa61e0fb1ce329d4f4fbd2699446298750a212ef00c67d6c4238df9cb76b2db80b9f15d1d9aff70d960154c39da67c0ba02fee14a32d76cbe38e62f2ee43708fffc7a516f04a41084dac4210f903cbc984b508f2f151f7acb6581d20099cdd43d86cabb4a7d93a67c4fe39c9c0e7267f47c508e24c3ef131185fdc55717e7421c6650ca5a2db2326e08abb218f9897b86f24be7d454988279c0696646f1b9241213a1c1bec74b722534e5282a851371f5e9c55a7eab5837bbebbe7b97f94e9b612d8a33271ddd20f4b30125281a2ad344eee5546c969042cf9cb845045fa886f42a1dc0cf8e7de4e405b10cfa4acc9f456984fa2cac391922bb5a1fcf4363f08b8d9b6f60c574bf5bf59cfc7a31fdb529bc69d7dc87afcb8005c59ef718b49afa551cb55197a22c5a7d22adcefabe88bf413adffb3fffd79b526d9de64040c496e628f13b8ae58d9c80e6479b3a6c650b0d2e43e54eab16572e678bc072f2cc23becab9a03bd04b2c98b60629ae23482a2a107f69e632c6d87b7d55a5c38dcefad988af127e7262d80ed96795343d36eb10aebd1897db98b27d4c272f3a474d86484fbcfeb8da7163420949a314e8f17fbcf68a9b1a023b0b0b844719c56f3db9cc6ea2d9703d91f68724c8b14a2eca71b1079a08fd07a1e436046bc8ca893ab9e8c55b2f987b24bd3f43f6186117e3a9fe826950107b015d0211260fe748d05384c568a46460bded61c9451030db7ea093b665947ac76e9873891e0e56d2939d095702a84da51e03578eb6999be618417f4503f8a66212c13a896f4dd64cd469f2a21a10b1fceda43b9f7a1e925034bd90c7833db12c2fdee49b2a16f19763a8fc43b29659ea82a3627da2e5466e49a8807303e1fa6f25b40c9ebb6890a0e9360e07d8311b87a9a69f6fcbb66738c95f02124f72338e24f49c31fbc5f873c582734e14c4f881b11d9a398f78bbcc3524ccc2902cd460b87b78bc61cf1ec1b8c50e043fa109e6fec5961a19f9977f3a73ebe83b20a7a371e38a25b924a2623c7fef0e4674e77f94b569447b11a26d641194bf554ff79f8c50b2b992123f96f5d72ac429c152310ce600023068f128f9f7be961a3fc454cdd73ab88b348a501fd3e79ac2e0e8f99ddb943df0f3869891cc2240c6cf55515859f79a5103a0bdc6bfc3cbde5d0893288a379bd24fe102e4c907e521a7fd9158295b87724988c7dee5dc726e2019387ee3eb84696547de0df13dd8a082615a898be4ec85e7fe594bf3bc54384794d08fd17da1e14ae67346c03402533caee0fa4567313393e83162d039ac53f732c9a2a8701a5e30756e419a5f70951b4a86d4c1dcc002be0540202f291c441e9c90f5eb4f94f82bf188c854c0d2233905af75334737dd014a3f7e7ee4aed8698874e372a297e64a1718d1a136c1c460e951b13fa83a7bcd435ab2e51d324c86cd5f2a234fc678a31ee469f4dda4876703574e2d13f6a74373317258e236018de0dcbdb88c08caa7a6d18b97d26aed8700d61456a92344228a3b66eca99a9b6d9e9e8feb21a0bd9e6cee4305b372c0e8ec6d3f2ecf6a115859b9c48b14063ed49ccfd98ae4808533cea7e0cab64d9ecf8b966925fe015500bafa50217bc4288d20948f0fcc7c80e774414a10de7f7599b928a435ba6d3451d87c4e989262035915a4171c9aff3e355e0c1ae4f5f52a1aab10b37d26bd26e5dbbebd1674e71cdadc4e2e8f4e4efae933f42fbf1b4edb43e2098fad96639f30b186c7fed9ee2617607f5684a8d7634ba814625076e0935d7f6ea2a1cc877fa1d0e3317deba6b10fcdac3f43a75a9ab8d27d2c0000';

async function execFixedTest() {
  const txHex = fixTxHex;
  const txHex0 = '020000000104b716647dcad588b5957dd8e560c15c57074a5fffad4fa00101ecad9ed46fedb60300000000ffffffff3a961119251ab3faa675ab8161cfba1206f0b2d440d95f7bc3397cbc679ff10b0400000000ffffffff3a961119251ab3faa675ab8161cfba1206f0b2d440d95f7bc3397cbc679ff10b0200000000ffffffff425f70b688749726dcc251a8bdcb905efe150d281a365b013525e0ee012d921d0000000000ffffffff080ba7acb13b554a07d97afbc57e2a0d8ee3d28b8f40735d1a40f68b7e159949c13808185f95ae7c5b080c9cc4b484d3947165f43e12897aecbbe90e91d89ef6e81bc902258dc6303f09e65627d5632cbc879447e7381cf2f100b25893f07c42698e6ab316001445260ac2cf5ee003fc6babbae62772edfb4ee6340b3d15b06011d87c13a817a09ec2e70e135b0c57fefb165fb5a5be4d79525205000842ef87fc2f49bfd008273966a1e1080e5ec2bf6d160fd0c1fff8ce4bafa652e802d636814c023633544a10ee09dbcf021b831ed5fc3f8d12d2026ab3a558ce5fe1220020fdb59feaca9cb25fd3c3dda18e1bbfd1d8cf734d3a3c23b7fd59995610241d0b0beb629b3a0c73ff62eaf0f831a7eac6e6276078be0bc163ecf17061ed9c2899ec0909c2c58a57d1a7f3122df3a6a294401c5e9c45060ce43208403a6cac61ec0ce402ac597abdae972eec381d5c706bc1e669899271adeb0fe94537ae50a9e3144b96160014c8c8e330142baa76acb66324f8ebb7a7f1c684f80a772eb4223c43da1490e0250d9411c860641c9851fa9f3c84066323c437b8c882099ae87a37ba4a5848b3ab20af64cad62cec3dc18c033969f535508d85482ecbc0036b4ba72ae6d16755de9e543c5f2dd4ddf2be49532d651eee0df67be534d2bd00220020099e7a0de62c55bfb7ccfe8522e938049d0175c0901ede4bc4758a29df5f64870a0c24e1ce3b372bad96ef583da3d958c79861e89cf38e52ef9c25eed0b5f20bbd080362436b02e78c6ca5ad6098c1dcbd1efa39440b43b66fbc30a4d3169574109803ad3f6a1d1076b3d8af0936918d63e0e78987c6df8893d92435c70072f2744afd160014f72d2aee467dcee1825b026a916791b7526eefae0a4ff1683481c1f79d5364bf4a39a98cd928110acbc36e47fb0e3311b349deb65509250754a7b0f337a9ff24d6988fe70703bc73700da65b33869d3c9fecbd1e4fe4021d26a18c949064610854b8ebe3a31f02b51f11f8c45b68e90120a19b1aa43db01976a914669951ec1e19537d5c8046b8762b038ae096de7288ac0b96338eb2168f6d086f683aefc427581231b6014fd6a7b790d60e03b082993b8e0816004f755e006314f7cfe4cd0e35467b6c1c5ea3db8d4c5a768786da001c458403100607becd5c82d9513b796f1d7d646101b1705d79c3f93047cac470b7fa005c1976a9146eb7965a850f7a094442e756d0505cd433a88efd88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000209c0000000000000000000000000000000000000000000083040007d3cf057e80feacf15aab85666a69382a0ab0faf75a0ae01f0ec8f13aae97da858bed098e9a4a1464dbdd6d8b12c1a132325b40d5af6a6486809ff13114a6a33853f38019af5b7613d986477135881af63ca8fe595a76f2fee981932d276ca9d09bdd690151dba542c3b0badc02eefc5d4d1707de2d6d151e21c8a0cd243f90fcfd4d0b602300000000000000017a4e01409a1822a2dc35aae3e63dd5d5ad99d8c0bc01343ebe4c1623e63261d5ada9d5a1b101f4d3fc308b1369bdbc99cec275c70b5c3c43c766c7b82cce32d6aee59226b3251177d34e5c52f4f84771013597e7e70c5b9e53367e3923cf6d3eabd085b5ee6c1e8cb2ff1eff65d220b7012be5288d998af4721dd4b19d08d6a34a3aac89806aab01aecba3cf82b2a58a4fd1f8010588bea5918f783644fe8e94dd1fe1cac50b6cc4897fb61c6b12c4498f7e41185f8165319f0f2659b061700fdda9ba9688df3dde4744ce24e3f5460130a1aeb6fcb3f2b43b47b0e6efaaadeb3836c2ec7439571f18988eaa44a4368e920dceceb7507eecffc0efa8f231c3c51076556920155b19b88e493ae5c4be2e1f778becee922f10d262e2c3f033a36aa4bde91ca10e05a0fa48d78e438d8b732836fc9a414c14a5931d317fa868f23680d7a995b80a2b831366d04e18791ad18dc4413138ba060a44c88bab7d843f27e3b83b55a87d6213a872f0b523fef7311d3d56233fa737533fd605e260fb1cc58de4ecaed2cf700940b2bcf444669deeea4e4e150dbdcdb9f7aae0ed170ef51c377451a2ea27618b7d4240ecfe8c28fe3bef8b14fe2662291166be06a4658e6045ea7e82f83798ff9af75003fed7fa792e95ab4b566db09b5ccac180708da1cb0e77246f44c47a3aa74c5a51eae81accfb3338917d63aa0cde94a11b7a110b06b77d387c4b03b89be99fa240419f4b03714f9654dd6ed48dd79011199b00f97abf5f2a374112dfef04530a7a3323ed2b2f5a5ba77b2d9479a8908c272db1cfa5e7c4d148c6c4eb73d62501e231736d3c06f3c40a9e9b7b8360b1fea7b732d10381c743f983305cf1d10eb7d25d00aa5153f89ce619c0e4ca4874d75b4b7a1685281b0337828cc33df7613e599f00238c56af98f28178553b02a97d20fca7968cd8bc627b5bc0e1f27d7a5db6d29e5e4a416e47bce5b57439fb7b56634d9882498431dd249eed7f35ba83506934640d0676b53099e0c03dae3ad6035be6e3008a46c0fac6ffdce82c5524fb32ec8f3a86b676c90c03830f23adf85482be4327575603c7be457a599bcd0a9e360300326316123b611334fe9b7bfe1d151e4d191fcc67c80b988ca2ec0d75b944be0c88f31e78a3b516e6f1b5ce95b1458a2d2fb17407494e97c40edd8e1e5d414718212173f54f4a85789303cb668f77feafd1b46070b1d1955c83d585e8b233c3e95b2ea2f58dd802daa8de5f599ad73a7e5b8f5b10f4e15bb800670e500bedb4277f671bda9cf67c5fdda0c5ae7606000419139999734466cad295c1096ab87c1b40d84273109af270348dfe0805029341e4846bf078f41419bf22eb890ffc27322345442af7c7440fbdc9a52b2e47e47cd92a902d4488c71898daea345631786f1c853d6a672ed58f1f5b4e2de1150cdbd3111bf2fb460d82d2edcef9173daec12d1308247e6abdcd7f3fe99fb471b22c11df0e038917a77212b63fc108f94b062ca6198cbf80b5c10f72617c1f71fd12866b66e643fa18c8e7aad8b406b362a493be745f3d60a97cf13f64b3d83eff6b744e16f825f4f01ca036ee52045da21ad874c09d52860ab138e1e84aab6f06744205b14f799679bcacda7fd3452b74bcadcaa481acedcc83570dddc2e2594042b198a2c9d996f4d31e23759b001459e0211be608389f1e57c243afa6bbe80cbf517d3c841c16548a579c258f0151b3c99ec3c326de49525c4ed33cdc5a670facb135e404e0f2decd9807760218cc2997f9cebd46f3e4d80cc392540ec405d916b9ef8371221bda2c8e0063266ee6e51478701e67a1e29147cda05b608ff31259c37f4cc4048a92cb880300ed9a0d48a065a0cd7b1497eacf78baace706d19b1a7946d7c247366811e74b1362c87937241cee4bb683188e652b0e13643d477f0aabfef465cec72f95d52fd235557147360dd926b93f0715e86d17217c9b4a8db7d16b895d1a70b6e69e381b19a65fabe76839592bcd4d609cc2bb053650b25a60e5a2c06455d83fdd3bb9bd224f36e7b53466289034be81e5441e380ecbdb6e62239b847a4309c5213471318f18ab96ad17b6f63a05999f291d1e607d27d08c96ea4e13daf482a85aa2f718b824b5f24424cf2950fa5a0a001d1051aa4b30ea3c36387a01a9e1f7425de95836b623a3997e39ef2b00f9229a77c75387db35a23f36dac421b3fd2e47fc92d1e982bc3a30be78e13d75758a55d81c246e560ca53b9e7e172c3b398b80777716a88bbd70e2df4e060752979e81d3b7814b2bf8f02f1b2f2607a21d77a25847259549988274d0278791ca48541c0022094c375cf82ed138150f1c9165063b691087c0a4585db07b0784381841f6077555f566dc9baf25244481ca99687da4381984c7a3e124007a713a1d349494ce044cedc5d9c63ff405c011dc2df28afdac46d1c0969fe67f870ec0c7efd5760c87013cbffb3e7255df5de40ceaca5b53428e84820def3b0d12592ca6aaedddc14afca20f9089bccde246061c443d5c8837d292b943709f85e2a1ecde3c48b15cd9a6c4f82b60b13359a12c6c9b6cfc0b6121690401f47820f36142493996aaf53bb487d9c097f8cc5e1fff19b6f73df9bf3f33b31c82530cf7032b3ebd38bba8e4a97c9798b5521236f615d7f920d3f01b4d3bae058339c01d9f7967d941876f2fa86d803dcb65a10f4699f623b792011e341be368f3b3bb17202ce0bf777cf4a9b0bbce844c1c3144ee4f4b74458a39856d1ef381d674996e5843a1d796fa2b3a6c7cd4f4957b04561e9bda2659174388e195a7e1ea01bf4f16bd2779c2526a1141206b988b39487377275b1530617e7d70c6c62ced444243c70673b1036a1b164b6ce6469e5c328fb14e66941973e0003a868353d2192c2d59a04ed05b5ec175ebfd693f67bbf1961bda1c2abdc37d35d616460471337297ef1ce7ba87b01d65da9395055430e391de5ae6a838a3f355f957be228bdb7bc70165db416208b49d712763e16875fbfd92969d00b9b84b14bca4783138ac62707802165d29da48892326e06e03478aeac7a986a8fac91e650ec1c9e410b59e24e3a20faa788791c752c41b6a33e16fe2707d0d4552b2604f568a9410b8d18e00a6723ed58f2060295881e42ab546ae781ec0a6cb8b43601443f4d34707261fce29d99f70e3664afad106355213d8453cfe8863afb68c359395755c692d71954db359337d587684f28744cac109c75f39fa0fe7a43e213a06c445c0bdf49a0ebf879183f94ff5767f22b24ccf9a8d339561b1462b05fe05b7c9d97f1c85ef9bbec56957d6eaa1a199e286d289227e0efb1108561cfef13bade4a7d659f20b179bd178b6aa03dfea9516d4d6ae4410cb0651f821c9ec728d801b60dc9c36574eedb978ee34b87c6a27d1d8ffa12fb3f9cf2350bb07dc23ff24be5a0a9d075772a1e7b4a50ae7556043936d8c388d09114310d77f67127ff6b4b6d464c40b678d8a8cb8aa656fb5ff82bf4375bfddb68465bf44ce8d2474075ba8e92e9465a9274ff60927b4085382e527e0aa3c8230c860da510dd537e4b2726affe5472549a803c0cea7cfd2e76a948cb31d4b436c0aa4750275e4aafd322dd054c4eb26e67ab3157ac0c5183b2122b9658a898917940decc402a2d839331d00f38dcb66164b6e82346805b2796fde4c878953d674138ae8bbcbe614fe81dbc9220db5e7fce88cd65591c7e49faf2ef60eda7eea2ebcdb54f98ab74a4f4fac2e7deb274c3e07ec0fbd7b1e045653b8bb4e5a6c3c169b2bdaafe698578aa062c4cbbdd6d5bcfc32403dcced0bfe7d1f786c3ea81d03c43c03cbd07b43ec0f33f6208469df65b5837d049e050dddcd07eee0012b07d0f043f17766f8779e70dea9c8022255b842642b98977e521df1b2cb8a93c2537da7fe8367a2ad1028520b4416a40ae2f9050d90437d7bd8ab0b6795dcddc542bcc7d573dd2a8431821c2fd8f87d96b0163aebff96ea8954d67008b7118b5657eb0a1af12f65fca7c8afd7dc0161fd1634acfacc84d59d03f41bcfb2fe2bbf64256cc1f6ad8583040007142df6fd0a214edd8ab06a03f075a1f26587a72cc9fa7e8edddb247896a21707daf52083abead224a04471adb20fcae817fad6bd280bc6d5a1a7a0bfddf953e1ff2adcad12631909125515d54b1340f12c1f0144139d60a790ec9d0b53d933eb39c3e6d2295da1ae186e54af3bbd3904da67476deeb1a8d33344567dab55d89efd4d0b60230000000000000001e3b900324dcd6c046d691df057a8f65fadc6539cb883ba4fe5740dbb2f8a8849937998fd90db6fb2bb6e53f3422dbc3e3af6f6ef28b3aff40b1393de58ce5dc067662c52b52cd81a2222dda967e607f79e3e34d266b3585766e89586a9b9d688632063d319c4c49a33549e4d132e1ff93f1a0de7fe0d2dfe33b4cd50ad06de763f7a7467682cb9f1a3b0cbe8edac07be2c4dedb0a18046d283d36d73d11b4a65696905618aa5926e7b7a95243b5884b0c4b2af40a5e667dd6884c379ad508e5dbe945d77d458f7a5a643594126806bfdb93c0df97ac49d7d8e008f4614ed5efb8a66b562d02c1a7c1aa3d244fb53c10f2f4f25f72a3bd7dd47259317592cbecb2c9b323b9d409f59ff2c60ceebaff9ceaf5b9ef84a14e83d111c904ece8805f7b701ac80ccb4ad09cf261b3a14e6e23aa5e020101dbba3c13baf1dd899ff3cce461810769697636f3b64a07e38c4e3a98772253d8a9455668be31248f5ec0b10fea68114e824175e0f638f6259972e97bead1bf932749f67d0654d8d621b45fd4e3f8a58e49ab4d693a454bdb4724d336cb5423377006b8be52d59a4790ebd3a0c30b43e1627ad8bda3192c0dc5410fc3727695a5f85a588752813e6b0a7db9aa2c99c1da8f276b9c558d095971ad44e0c9fc1759a220f4039af3477f9b76de7f88c176d9cbeaf166c5e75754f2989de041740f9a97ee0a11d04af874626efcafe782c2d2624d67eb55079606e0c31772da2981a784f09f00a1e51296d300662ac538b1a431e189040c3b30af4ccd959383fe1e18c11cd940d970d2b30afe79f1ad30a617e9302d77ed0878a9cd9d58c8a8b0552ca81b1c73a0487c8ca65ee4b58ff189c44bd6568587bc5035484c648ce472d95de8f5ebe9112bd55e44ff6df843a1f3b6c41ca474561e318236db69ca89c869e0c0055c808ef090457cd30f831fdaec7c67a581a778aa99499c4c14bba0198a13079c9b3f95ce48721ca2a6285da79d1383ed8f8c10fe11b478d6925072899ad3aa7fc846e9b8d50c1ab86622a3f49a49407adf4393e9b82903bca9c10b7dcd9939086fbe16417faa86ee375f792cdc38b61b7705720f33a0658ef7031f92c45a60b00ea37a91d70655041098fbd23ab2794f0400702342842145e6eb4061ed8ccc47142afa9bd0984345c125c402001d8f22add32bfdb4302cea4b8a2264fdfa7271130e9d52eaf9977b8cd20bd067131521858e43fba605a9596fb735eb0a0f9c9bf6c0db28f37e50b4ae12d4d33d26bd148004e2b5c74f0221d742b3336e6d142ae78a995d7595549bf5bf982b2f4d71923ea892f83aaa8f34db2138e4d950618989c50d372c6855e87ef587088e7ab23b01f5101fee6fbd4e583a5300c8a1593b217bd38339d7fbd2102c94574fbdc910847309ab220734268b3b4fa9b8b5e75f13219a5655454bc8fb4a7b82ff3dc42770b6cb6d3cf57a3b6536366dc7d274e32acd5b1c0d2323abc9af0e54d57e332e834ceffcd5f77a7584c6d966bcac98bb771b4b9e9e8cb02ee77555ff038a9495ffc5a91ec42ad62d13598e2c61ef9f4ee2b904f2cedd85de05b4ea78e174483f6b54b1e352a5aa6b2755a739b6082384585dd1d7169e237ef5bd5afef957b162fdd5aa87bf622340046d5544ccb7ed768fa1954d1f1de10693ba2cbb595c7fff92192306aff1841e5a9be559f1e38eee12601f98ccfaa662b31ccbf051a7c959f5b08054d78dec7d3a9da028e29de4c2b0deb1098d8f15beab032ee0098f23fca8d5ac6515fa2bf8893f98b5692c8f352747d9fbba1b3ef3f9ab2b16ac21d5d90687f8428ea7e7999a97cdefa59e4ae4999778d1c824d295e04cb9ce99a0e12a9c77f8e844f8e89e2cf29652df730f02bbee422cb232e7c78bddac42f28b7d2db14d2bf668d2bf22359e4e1b260af7476542d8d7223b4cc732e3f5b039455609c442f017e4312600e31e1f83167db0820f6954346105563a7ee61b6da274422c8b518daa79c2c0a6dd046e40dceb69d46b74cbc246b707606024f7c39978b64dc5db7f0cb4eafe6c7c91c3f24c6810a709dc5af07d158eba3072ff0e9015bcad38fcb6d2ae37cd4e7959a8b1d21d8d6a76815a9bbabbc65f2e093a38d529b5228a05c53e8c04cb5af5d91bbf7493d3d5e4e1f4219f228c6d78ccfd30e40c6ad5a08fff6be972cb6dfd5a0b4038ccab6736acbbb5fadeea4f558130b35e63d314177dc5e8d62391465496b2a1781d268ce23b0fd630125e222e1e5c343ccac192dd2c0feca74661b67cbd8568bfc8e4291d05f3ee61f92d104fd0c114f0ebed58566e5893180e1feca0f2c1080265d7eb5508cedfb4e73001ec09c40d67a36eee876acb2083c148415f74a3b4145e9c9a4ad0de6402e47a347ea3934e6832e7d2d90eddc8399de35b8e50d78b8fa26689d2bb326ec7c037338ac69664d4ca98037ae14877c5e3a8998a9d4e80d0cf71447a13114399427fb61bcee9dc8b6dcbb7b4945414089861db52d6352094fd38f3580e8aabe5a1f5cb384d2533d93690f51fab7519317622d90475c282dbd8f384518028b71c6e313838c4b85226220c70e46073024ed4eb8dc651e88b3c42219f54f9b1773bbcd98342f113d9245a3c36eebea1ebbd3729f712f7bfd2d5c6ed4b917efe676810070d8046a90df8609685749005ab1da1db654af423eb8ba136763331c1a698118f7ee3f6f7e4a09d4bbc1a901db92a138a72a207a7aaf4d6cbc2902bfabed3c9d859797b69b35c12637a347a3e1720db0fb406a89f6ad2deecbb90184233fb530ca4db988ff287045c2b0f9c9081cb3a8f5bc996599d9978090f31124a4c18c9effbe919e69af1303a8358a68fd9b722b3b60f946266e98a37570f2de5d1c8ca15d238c8ae2c8254e360ed8b0fa5373cac1fd014a7633075c5926ed58427500bb35371c75a6740aba4faf84bf653f00652b656af7df30008994a0a7a0724d9c783e2f7f7c653ad0f5f016620b7d5d7221eb15f5588d7fa353f90dc01da9db4b133883d07c19d6be3116f9dde14ebf844819f838f979673dfcd364ce3b9c39c27201e5459429ea3c5e6f24fe309989b1bd56f5f1bf7f0aa7aa65cffa70801449d627e640f29004d05fc0d3a5c5298c0b7d12e7f2b23d2199cabaa6b98edd96597c2c68f34b95ac9900f8fcacf4d87ad98c0dae079567b13645903986af44f2e172da90165aadc8a90bac1d714a8891e64174da16fa0e0fa558e09706956b8b20dd8bd387776a25aa607c59713e60f4184492835bd8229feea43c9c5d99c0a68075b8e8c47175955c2ee628697cb3874cf10275019fd8af8387ff4ca223f2eff9feb15c902358e8170ebcf61324daa07271ef679fc2b23e1aeabbb616d437af9f408cee5106b5a792b9d9c4d56058ed89e9bbd23077d0a93a87d45838526fd9d88ce4828ec43de0a2ed5d174ba6d8917af1cefcf8b922ec91265f8cc9b2a16d1d7f8fefff74c397292a4b52c879c3ad2252ca4d687bbc533d2105179b461b9964035a48d8917e735fbf3aa03ddab63f586df424ac3470668c9ea6e50b8aa2c3cd98cb14cb356cdce5a08cefde15a16e414f5210e699939bd1f411ce5607878bc0fa5e2b66694133f2abbdf6b0b3a223a2a1d8b1980834b90bf65fbdd01061ceaa1e5cd9779352c950a528348511dd0019eed2a230c14b484a35c1a5524c456fb51258c37d18a5b5fdf21fb57819f9b76ec7d6917fdf5015cfa6af475f07f01346b66096428671c70fe83e1502c55c443daace4686757aece08f831368547890e0037e035005ef331ad13c805c6e46274ffe5321ab895f3f3f7356c1c1a11e7a67d953f1f0ac49b2ead46b5ab505f4044c847fa6ca0b5ccaac7fefda636b1eecd8d072cb1bbf54b0707eabe8570f1939a4e56eb6e3e3b7a52e52b65819c51bb512d1d0e4ee57b502bcb80c2d435a23d6d3d9c313fc5069925d7073e93fd1bcc0d34df7f165b80369807e22bd83abfa18bb0b8854a14ad70de5756278cce6b46b64eda2bfc1620b99aa666758193420fa673c7f40b897c2c9c97e641eb9640f022a5a1230ce35605a8304000b7c727eb57dee171bb6b7a34ea4acdb462dde508e0c9694aa5dc3b6db43ffd15808490a7bfa1b6f25641ac56925698bb46bde643a9ce33dd26f200c5e10a774f742a776b3f25ad7ebc1337580694bfdf24cab914255a072bd3a83aec03ac90563d9f0f6e6d59b467f39e82080f48d89ff38c56d6cb899202aed5632d22165b99ffd4d0b602300000000000000013e4001569223f8a2c801505ec0e10991e59f24170019bff90a479ee97e2ff7c3a64f85af1cc8faaea3e7c74f4b866d593dd592b61fd7d2abf7db07569425bcc80e12b0bf9f972d2ce0f59a32046223d0898a5f52a0a4b5bd6714253a3d07d573b029f448a549ca1deec51384d3a97bb286524c8170ec99555e373cda96ba80a199c0cef7e3ffc12d664bdc3f95d339cd49b7f0516a1accd066426a9c99b774878fc3360940132508f70080ac6ba7404a90ecd758514193af25fdc92ddbaba448decc4482f102a4c7f24de4b7603eab725dd7d6495c3b71c144e7abefa4e3f198d85199f40abb809afba72a09f20d10a1fa0b955c7ff9f8b39bcb732237967da6cdd0667e2c48e3096f1d85f4bc752452674d83c516d158a668441daa1e82e423c1e955807c5388645adb03726191faa5874072b3a9bb863fdcf9575813b6a460a4cea0663491ea15eb5e2e6f34d8e09d24755fc46db48d5556c99a5c1dae016b7a5492a488991c4b6c6b39311d408c10720abaa3666c38bbe7c23d2a141473d14fd8f8c53deb7503a62fe03296f0df805b33505525d719e276866cdef04b866ccfc1bdc8d8988dbf8ba1c679b0a4a27d043593c08c0029ef7aa989003e9a0fcf00b1e314963ae80d794c7ddf6ad68de321653ee062b51132078c95aaa97dc2e7937b5fb62058f7c376989281fa77007fd4639764adfafdf056dfd7ea45a62997195effb74ba31a715d4beb9f5dae13b984bd1b50eaca2764a2e93626a1a86a9d8c853628f743c50e62c8bcdc71abf5d79661c7c0beff8722812e6ba37eaa0e2a631cea876bf4b00c9ae1d41bbdee38597bdbde12c120734c89cced0166de02b1287737b7ac427eeb7034836dcffc9af69ce5e7ef9f99a50ffe831ff4a989420aa06a5034f28984d795b4bc643cf418cb60abb6ed3a9806dc3b8be19922a375a55e5b7a707788c063a41070dd9485591dfd21df48cf6b8c58b3ea9bbf8fda0e628ed60863d402acacc5a8939364b93c917017060bafd1e1a6ede6c5af2f5f2ba235426beb4f359e31b586443524c839a57a28666347018de9796562aa2da3d95517226db539afb389eee8ade40750ef1e1264451db3ed56e21ba9531d5885509bba16387e26e3bf226ec4dec4287c77066f71e83bb4e998feda60c269f20ad4f78492adbc1337ace2c4083a7bc50d0b60f4660cab3a315b185679ecdebadca404f193229cbcb2582be40c260f1d2ab0bde454297b9d0bd9532272b3acd2eef0c44fe9ee0caae0c8ebe88d4dbe319fed6a82416c94b74b889a67850961f9a1addd3236abf661988321f2e00dcb9253d67bb66e54e8f0f6f3f95a06960ca98c7b4bac2c7482e0c85f3936cd3d7f16cb94472433226d932ff1afe9604add4d4c1fc8876434abddbc54537e7f2d6e8f80d17c3be7a40cfedefc6e02c0ccfba4d19f6029671d8e4ae6f94e8e7108f6b07221b50e04316b6bc998e309a781346b46c1b5396e199d9c8867ee4bc9be0679ea19b6c7eef3a30bdf7083f2a9a1c4ffad3d861bfbde872f43c5524c9d32e7d7b3639ae60b1a552e6ae6ce1652a1f3b39da75c307be01ff10b4ff6fbbff9ee4cbf48f02809ddcb100ecbba23833174380dcfd7cd6dc5f46e74ec5836f7021cfaca5ff29d9b150e35e7f8d24a81b2687ebdabbde02a6f6b3f8fa46e81d03fab427d0930748857807ef79119bafefb6e67cdb743692c9bd61500d8e7a8848d6ee3ff001e26ddbd50a576c42fd88647a41aa4935a5eb1c5ae6c6c2cb9095966781fac3b363008d0381d035e3affc9b9de38d2d8eac45f94443723fa804be959e2fa93b775e5394678e130510f57d3dfb877729fef07b6d82b620d52a8b957895bcf30de1aa929d5a56fce6c79ba22ec31e869c62d11a77dd9b44fa9fd3be445e94a9624d3dc2fc6be96f1796181bf212f4afa80c8a36129e35a66e548acf4fe7f93d6bc1446de10870c571fbc467f433b985faaf605fa6b79763bed5cc6d7837cd2d231e3ebdcb1b477ca122f17a33f541695840297a6964341b6a58753ef181052c44fe12cdde2107e88a14b1b2e33cc089b601e5d664c98549f3a4911c10080672555b8322740f69e7c88ff2fdb7299d5ecac166a6276048ec287a84c8846653cde6d63e123cd54d366976bca1accd120af24ebb496e0e01f34d462a7891378661bf68c4a5bcd00099f91e9ec7612e30467b3828820413460cb94e3ccf8711861c5a6a7391ea13d73840ea36c084ea2a1ad6112de0f2b638e91450b46d9c02115bc1ac72fcc0ffcface863849c01d1618b01433b0ba1c9be2d386b68b27a92dc2c0cb13689fa63f58a16eae9c63f0d818ad35b7f914a1620af5357c60de0a7e1b2f0b99b3a779b687a1a277a2d9c856818ed33854d16bed3a02a5a51bf7c01a66a762b7bb11e4cce5db6d3bf3c38959c2d3d32e4354483c19c216f2f9fbe3deed66a028349cefa421c9f6d6e35c51349c4106c97cda51b9e4459c208445c51d912d1106b3f08503d7641f5f8180b8d6723cfddb27199397ebf009533d1a4c4e85df396cc007db365a86667a1390c89a101ba7165cc5b6bd32e32d83f0329518a1a2cf9e175319a0efafb910d05a303ca68963034d15766e56e3951570acfa493fe1d6c6525b3d127adf2d15b3304bfe9930047ada3d76d8ded04df362a1b470c4286b6044a53f4c17046f57b2210e11fe1589fcfe7f5787af09294bd0e96967333a57d1a2bb416d5a275507ebec8ab06a0a2b105a66707a55753786c0abfa3b9a02a39bea846f4822e0f0dfcefc92c8a33a368a2e9c06b36f419a4326a34b34be23cdd953282af828f9ea2891ce5f773a621727317135515c672159433fd4fc27013b296ab32cfa2233a10f38ca4770a5b975db29cd2f5bbb10be3caa7075c80ba60c7ef13c40fc9e99afb13338678c1793f5c8b68a76cd22792e1e3943f93d157f726804f9a86c198c26447d1755cf3be3474946b21566b7011d69da517ae14dd503a7447f83fbb13ed5d2be727e53969b19e50ab635314f478265e6c8be00880f72d486da7c125b0f2aa99e2ba1db6cb591db887734b96e5342b0c3c7e10932fd9035d4ab3ddecb9722e27a8985f4190f886e52947c61b64420b6e60411188ab23ca33b9815483b4d33487ebde0b9979e327823eed6b9bfdd2dc3c622060a8ad1f54548cdf53cb43e2780a0ab4b89f8a0d45836412f16dd8374c26b8b85c0c546946f4b100d7663e0e6d472253308cd5b54eba1b82c45da9e4407577a4a27a49383c8efe8a5aa3fc65d5506cbec17c43b97cd3f5adc67c380396808545c912b4e24f58e436e6ce27a4fa74c3c32eb57362d1ab075f96f874d4f0ae234a1fb645fefe3d939efa78186e18f12f7e05fdd4109daaa814303f3ef1d4ec239a0b04c5199b08b364734e577a38dc14d5eb4a6b3743a333108400e752378ecfb7e94bc8d7f28cd0699f1b4046e00f3fb84ea9df61479211bc650a53c6847c1aa73a376ef029399ad8985068e16f2dee0b3e155da5d7f629de7448803d8abc442e180f51956cb82de63e8aa4f1f699650930bf066cbcab073b3ef7da06cef4e2d2315667404fa9e465c8c09e57b97cf3cc2b9893a7f9d6c4b22a9f84a3a4d5ab93c5fcb1ee041312460bdc15d9b1c878ad5bb2619ed4a5e63491b27ac2d756cb9e42c4bd31e0423b680e6c190c2e6688b4b95557c0e53648b51f153ed07784efef9cc4d7c2581fc85439498f1cee29830e8cb821e30852374981e35f0ac3434cde26cb9b1819f42e76c702086e9251ab091a476092a6d8d42a09f131a70ec568c64a1817e4ec63326503f31197abc65f8b405b1f89aa011e86752abe821721cf29c45c440dd692e9ac46437dfb93f89fc0c644d4a9aa64a5e1ff80941346b3183130257c51c39a79041ffff86a893d0193474094438444ed7bc6ad2d864e7602381e902a491341a7bf3fc7c8528936a7a0fe01a19dbea2551b7c8624ca7531a59118d5a3b299e41d000296847a2939219af9d8b5a20eb041baaf24809dcde22f2a4064cbae2aff887afd5a053ff5ea4cb943ab4e270066ec3ee8304000dd9aa1e2afe7bf149610ed6763494d822087426079376a6d92a012c39c893b1070ead31c49a821db04ded46df2332f7b67e8c6dfaa6ff51565f89085b8e6da2e4cc9bbbe4fec1f28efc4c9a2c1e9cdc7f8079d6fcc37a2bde76f54bd4e7958c46382c55b9911d2347253cbfcccf1200a3b7233d91c19e0f2b35a66c6b09a4e6cefd4d0b602300000000000000019a7d0175f5d4f76289cb7122c516db9379f2f4b83607763b6d2283871a4b41d6780d1a60c2a86dc12aedc4f79f5fa9cdaa3382f1e2fc88383be9f29b7b183d78269ae7d3bcc305b593a579b4934df0084dc982434995905d04692b00e4eb08284c139480db938baab02980a52ee917870c346575077e4c0fbe0cdc9e3ae8d02b728274dc77ed0d519a8ed280a00e550ac64de7c9bf42b800fc0b46090ed02c4b8e0881ba866ea8ccb438cdb1449445c74b0a14f3d276f4f9fc797ddb3978eecab3a42ba9c6b5f36b4c29ef375f03783dc2803333a845489e438279cfb8b8665e4a5c29d53a7d28427266ed83bba351a2beb16b3fd7c35c1ba065fdeebda15c4d734914ac9162946b2bedff41f3f6fbadb6ab559fc5092c6a9ce70a587051df3bd47fbe667e1e54bcabef8dc5307e3b298f3cbb44f96fba1a2e8ec7d01226e475afe2ca30ab88c46a2c031cb54a8cf990fe7fb56990b086e3e40eb6ea9a894e841b1716917e2aa6d800eea8484a977a7497a05757b20946ca3a0b72c1c67e74cf259d0a22318888079a01ed429cda4a076ebd93e56fac4b11c6acd1026f86f785f86308615b022a573c191f92a3742f6ce934bc94d33380b5d49f9da0933cdf5ea865ef96658865bf65595508bd6cef14b5716ebe0841583591dedb61e65d2790cead0f8fba931a1d423302727f8de00afedcb4228d8dd520ee5aef2a66620e0f8bfb412e9760f948a129f5a4686197f70470306b5f79a7e68c032969a84da2d71792596c3225251759956a4f1be2a04c0fc31cb9725267df4a5529e5a5a80b2f28ae154bcde8a0cbd21b476f67fa3a578ad27ce510f6b6ee17b74117e8d604640103f69a7c5ae23c2f9ce935dd4518c8d82b0b9e2ccc7c4148c323a26d22111b44e2d25eb3d42544f0a4ced00406e7cba4ede189f1461428e0766c396a76cb545b903d9b63cc3b7fe0220d18d433a024d90fd0de3cf6a48e902c2eb5627003eb880a4c91ee0a7c11efbd46c60afa45ba4e439e2e5d845baa0148393db5094414b61f2889c7aa27a1288abc46650c41d52e4ef9b62cd9ced77288eb48a45dee06f6f48d26691201d0f47e4b9cd2af46c96f5af747d0ec8d02cb47003e6ed75b7b1aea92b5e53174b4057bab06b5aad3086eff94987c3308bd802f6229d93e9b46477f464b2fc18d44d09a0778aa1d6f2bf46a1de88f492644f8e17d64b1c3a8a1839bf1423128d675d3c4167591f29a64e3b8749ea49a87950767fad8fdfce9b7e59cd1d65be2a4d5d39207f79dd466a0c363a6262a5a2c5dda413ab79b22a57cf768c2dbe2f8f02ae3efdec483e233cf355508752f59cd5793ea9ad319ada1774151bba0c5d21a098d9416d90e60eba1d5db39a90d97668a225e037fcacfaab1e9d2bc128c3824300c1ddecf5c911cfd31b440b8a216856627213ba144482130e57e7be8a5d257b31199b74da505e0933a15234cc069d2521665b09dd336764eeb51157aa0917cb72cb446da2faaf5e06b12b76da35db6610de955808c9199a4c372d42ca22b93f37ee155700b7d8ceecf789996b30cfa26318d1950e86eead810345e50cd0c7cafa1ab3b3973eaf3d6a53b17b5b87c6a73d2402852eecc8f0566ecad97ccd3c8c6db35be0e3e8d635fbff1166683cc3e74c3d240a1d90623c0acd8d56f501a04f3ec1ac7670a66f0612731080cdef26e3570b6a96cd2c6e7fc681034e7dddb2516c71d1dc103d6efc90d452fe7cb056ae2199776d5fb016a447b5055e65913467f134f9e28ee5ded033eca70db6e65aee4c419c5904a01a2c272f96562d9e016b506af1045ffdeed8b15a235f75a07a03e5f9f678115c58150ae8efc7e1fc9f8c21654d8cd425384d382e54baff59a6be0b81e93db007b02d5158d053f33178e5189c91a7f3c1293cd0c45316f20a311c9d516984f746fe89ef0684a6747d8767c75a95f85441263a4f8531b51b7b113ad782ad2d059990357ddeeabff3e993cb3493061f696e9f6185fe0920ed685b37f3e086664260c35d3ed8dc15719a310f10d8858fc03e6df450681261ac83d5690196b37484309fb27b504c4f1f3a8689d69625fce32e46325e572577f56f6c6c5e3321973ebececd9c5c6b08be9bb63ce3693b8f600460d23ab745a95e94f676aa9e12ca046a1c1d7c06e992ac1a8fd427384191c1463ebb569a07a79a9c6d629921fa8bec62c777cc04e7f825e1bf504afec47af6202ff0c4492e112963b2fd4d4e7a040761a7043e7b857ceb65530ae79332e169df43b0cdbda6c6621866c0f161f0a88d5aea0e2ce63e37581e8acbdfb2642e43d04df7a19aa26346b6efd91d8ecbd63ce6933239b37c4d70b8530825e2b63ab1d525bb6f29c3d72c7823b140d36d1e2d2c136732417d91a3fbfc64e8fcc1aadcc4a892352784fb98b3e72745949e86b27e6b5a08481c5a1e41cc32f18a36c5ed5af6a717c8df5b8420f118cc85fc8657e92b7476308d585eea8a94d26464927aa53e414db9dd2ff67175be02b43562f464680454bb59777f64955c8154719bd2a277b68f33b8ae0f5002edf15f278b6e28bd74a991f22807835fcba0cb18d984897ecff2001b1424b67981989d5fc1730dbfe4561aa7a74be0b671f27b7689c1bf70248df78a3d2dfaf9622c224de020a273045fc95619be991abedec954fcc524ecbe61c32ac050ff2534463762edfb2b566fcca397f28be3f52ad07312ef130cef57527ddf3f6253b6d39ef0703474fe42e19ec79d9d9bfd801a0f11d3c40657c76f038095ff8393bc9cc07bc32d55ec0622a2f1162321339fd147470ff2b0139dec0f864c67bdd0dd40b371b0da3ba1451eff29d23be29f5fc9f78ae739417991c4dca759bdbfe8a3716c18892edd4bbe701da393608c2de70b3ca6be7097af5e000aff45763b8b091dbef5dac4b1f460d471146bacc5197b454838c9423e52881b32f791ce25d7c931b616af39e97adf4748fec2278aff12012e8c3dc64408eb448bdf6b69578900c1a032624bff10f65b3a1e64ba256d4293f7b9c72f3379aa0d3c7b984c72ca21462cc308a7ae2698ac1360b7ed0c243a758a18ecc732c95316b517ba26443b9f3ae91cae5c63646e46f393a9337c83f2639d9bbc48bb7e17825623069f902008cec5d0205aeb6a48ef60c783578059a93aa9d203c1613c78340d7533d0745c5275a9f1ac619d93b9794a3d6cdad47ed9e0a79edadc31195d64846e6855568b84931b07a7e5961ea1535f23f22c7f68729520e0f03be5cf90c4f62ffb57a5467bb06bf70ba74689014ed6c35efb70c8ce517911cba60e95a2d86a77d1eb38fda134508c560933030ca69fd49d90917034f6c2f94fb28aa508d98602b31aa75e04b92290330110ac07bc412caf984eea7f0106d4717325ffb716a4d6fcc0f2e7e550f57e63c880773280c52baab969b9ab6ae78170fefa76cf3a5d4344093a4d4dc2b95aede64f1d78c604a6c6b7e1b0ec547f46dcb8510df28fe94eff2c09b8d8da07da67e84287ca5112d8f317f157d381d09f588ac42e257ba76e29df52ff8efe844b8a8bcac8e9f844e69cf323a495e70cb730b228907fa1a655ae554d983008536a1170c6ff71fe81de70ceae52f284ec0f7bbe164ae656f145cfcd8748c3bd495bc1c0ec9d9ada640d493a955d6d89e994747204ed87631e7a41eab5c64acbb10663bba94aac82fe63df0f3d14dc5b5e040394e41c2c2c71b86c36a24d6a17ddf4a036a3e3a12f7a4211a91c9eca6c6be79ecef83090a9c0d0e53b8240f739dc68abbc2d0cf3a634eb6cdce6dce0bc27673ff05bd00b871eb7ac122afa1547e7b6de30684cfe1bb1ad4dfa4ff06003172d614e26ad3210550608a519e427aca03b0dc3efcfbd56b5b16c1dc168971071b9eca89ed5974a5b4104089ab2876f08474b0fa63792c5b435b7e01a107890ee5f720ea0f6ff19a8893d2784445f24ac6b569cb48d10efea60e5e4a85d4541266b0e36b17a7a3c1d4150498206d1b18914cad27092226b74b2820c554cb4166dace5f7b53dedeee47aea9bd0a78d3e143838f07b11b4124c23ffe8304000db52741699f630dfdcf79b1d117edb05db79f6b7a97cdabf1372c31d44224b2178fd2aaf18e3934ef5ce7a642e6818d59e9d20b1be5e6ea5ce1014ff03bb9dd61e0f098f6eff8073d65fc0ab1df02836d2e5c5614f642431b308b632d6605bd3c70fe336f27020280610e3d01657449150d8a5e135f6c1114351d753ab702663efd4d0b60230000000000000001e22c00a90ed6d1f0a39bdddfb752b6edb5e45d0b15c495916941538eb880b2e27779938582fd2d693f8687e8edd39c3b4fdf6fce6f704268e771364721c153af2ebe80b62be2747b040b2be283f3c21d5dd17d2665a16603f07776ef7cd4a5088b2c84e821d662a533ee660e6ab2808bab306a7ea84ed4d5ca6ac9d37da790f9300bafcd9107060f30c7d095e6c9f7c98ce2213e94c2f86b53bda43a2d9f80ea63757a4a0ac018623236657c30d2c97d6efc7842536ee2da497953c2065a861bfc54304b182cbe0ecff7e41661334a94e0771d6732533000b37e47cdd49a00587bda4388ddf0a9778d245d9ce2ea95f43621893eb6df39df695884b8ce23dd5347b83a6d19cc5a308d76b2c0e6518d27dde60e32fa84ee537dfbe38d918b07b3309c0737c390349c19f60bfa51f33737ca78fc2d1ea5524c7a68fb9ebbdb93f3ad0f56227cf3cdb489d41a5e0093e50955a04cf2f0fd45664f8d4eb5f155980f8a9694a9c7d5015980ce018d16d83706b52663457feb715470b9638dec937b4df4931804bac5ca3cd54df1311abe6a4842a5a967fb09448bef589ac8eea0f7ffca4cab5313bb86e48f3439e5695d13a9b14fbccff80f607d28b1299f47dd7e672f5ea1900fba11cc5653900a6558272dce476d67e331837a84901a8820dcb2172e5eacf61eb1636e12452b24fe9ae8f8e9bea8d009fed9d93a3e256bc1ea5583ef3593880a27eb2de37cb3c89a7c34ffe202bbcf681564823ab12102faa50931063909ade938005cf24de06fdb89dbae2c5f3090366ae1441949b79906e677f4d3c88afeed08605e8a7b79e5b88f5c30a456193bf666a3e41b9a458eebac8a89c97049750ec1ccb9489215961a7377acd8d73c50df07b5ad8dde521bac2bf1b274b3c9c0ae330843e8b60717aa044159e859cc7dd3cbc91c8702a10dd5f1ecd6f171a061f4ab227625e2fbce01ab88e6ff5bf6bf7c097add48ed5a540f7f9f17551bb44d54502ffcdca918e574338fc2af98c83d3ca3b960295196b0fc74369b785f2372992794bb12cd0266a7cb8429c2a4bc58bf62e2663d3d562602386127f21256f8910b469f451d5aefa58cc7a9e7622326c26c61dc34e670ede78fa5a87ede8c66bd51933c5f93d3124304e3bdaf9e82a512962ce994399a1e2f7c4cecc9896d7d70379ed5eeee5371c5a830dcab92520b70bea4642991cfe1c51d6efc7e54328d3c84ac249e5800525240e31945ea1e45a2b438e1f4695ba5229835345881c1cd43acb567cb656282f75620dd0caa66e1b8c7eda9a6e44f6a04c22789365f23ba0554a1e1c76bbbb076259bf67d8f58f6b74c02cb80fe5cfd50a4d73b5bf816dc9a23b6fec679de26d50626d985e60da215a6290b72aebf88c1ced3cbfbf69ab91cb29e6e77f6bcbbc7cce6aa9edb2ccd135ea86aa068f7b8c7b67aed42b0f32dde4fef55bee4db9199871f887aee24fcf94d9939b9cd1245daed5568d0c81e0e36ef5be934b7eb12dfdacec093ee985e9dbe0cb6e6a60a125ac34c515d95f0fe3b2383b9d0d3885fd699cd754fe2d53215c73c01b2967cc80d12c5f408b2ffec4b3e2ccd822c2dc556f44d879e6068496d3240f199ec34e30d90d7196df9b1a622cedad63712a539974b26e2cd3ada7ee653bf587f9ba81fd4b21ebfb4c7775fcba6dbe55816d1edb20d486ce2348f81dfe9809f74a502fef13ebc1d9079a5bac29975459caa983575a90c208e6e719eca5d736c70c2a9771a7cf308fec34caf46db10ec2638866da921989caa947407cadf586489f64b9c18f1e7a83c67e0049267266223d11040bdd506aa11dfd7784f9bc7260cdea46b6de0322046e8382327ef8282b7255ba56fb55773e5db32f85ba468817955dbd8e74fe47ac47befc276fe2faad5619700b25d684e414fbdf2af0570f3df3b8fa60c80bbb616359718cf542a07d886ed99acf36f8c546deccb4d25643765d1ff92d46292f2dda17f59789ed7af3989002f59f3042fceb9fed0a95a5826b4ee6228452d8fd74de26bc8774bc2876dca7252fd850750d4e6ac637baeba488e61b9861c3da3bb500a1699ab28d6e6a6f30a5f6b7b26471a9f13646e5a1dd1243bd1a9880f05f6b777813b2229bfba3ec287610b68779d522c2bb9d133da211ec00751aa714b2b458a8bd6c3130ab517156b9fd2207190a30dfb32dc05e2a48a2d3255e047cc3e312db6e415c9e533a86ea8936dcce9462b102a3e0a8fc0a75b2fe3a27be1b6e4c5d974b022961023911422b5faf931aab0a589fda4473f017071f6993b777c3e79085717d97f80cf488cf9d92c1dc5aa2b3dfd996f655767ac9a593bfe056b7412c9a791ef09997c554b93b6363ca07a474972cbfaebabfc26345a1212f8363f762cb8267bb7c6901b82159e014808f9c45308ddfde0f57dcb020e5e2e4ea8a494d4e4158984886032ee66e9519e070b321054702e837a1e5179c627ea2cec32349e3833606829c1218a2f9b8d5a53d101fc6ee3cfccb6a84e8d0552ada1fdae4f62e4d0ad0d8ff12d6bbf80f3b04fb9d4333d76cac221cbcfbb841e8b31341f22902a8cee6f0721cd44e20b40aa0da0c6c8eb9af27723cffbb4b88581d84d7a9f98eda597c53ec325ba109a995d8593298a71511efecd4bbd6423e3129ae62890587a7352df28bfd8aeff3a50dd9598a4930b587557d916726c5be3a57d4cb73502a516a93381501b154e8d73d8d6380eced901738ff04a25fd2678c2cdf0b58de8164a400e89828c8bfa1c8c2174b4ed101dcae7d77a74965a959c10867c94da4a5776a2c91c80ad7d1231c0be1a4ad3cf3a6651e1a49a5a8396262d0805bfaa2f6ec57052e2bbd607c2f0924403d743777b8ebe03d87b5192c79a7f92502684b0c04608329c516afa0edb4548ab95eba3a991b675df089d6adf57b69c54e68275cc8ee00d9172e3ffa4e2c2b0e09524fd4fee23ff0941ee86274e4ee13ab6bfdbf98c1ed9e6d8c8b93b924cd459247639c229404ef66edc875267e7cd2887a862ca9690c0565db77f74a3c361415c913ae5a0a54b9dc51eeac5fb14fd6081f8138ba38d79b889f90f36f9e5f383f83eb37d106d7306cf9718857a1494afbac62b2d9d674c41f8fb095bb9729e0412a7e088ef96025c82679b1e19ca680302c4e86357999cddeea9a0023b5e339e5f5729f6ddb2d4a5cd1128716528ef0267ad69aa8647527e956fb3f7a7c03d7fb27b9bf7bace443a8e8512605284d2d34ae4f1cba246fbc52e08d5d09e1e21c2eb761a1cf9434d210c48d18c568efff698fafd2d26e4078a03439db8b1303a72cd46bd3e25a83315f5157944b333537b0a59862cb91c9585dec23bed5b91089b6d5cd2aebc91ecb524179be9b3c92c8a9b2da0508ca852390cdf0bac6d52413770dab9712d3e0aa585f7d2e9f4490488622a0522de14b0cb91b1f0c478153f2f5fdf230cdd1bc68ff07859aecefd79e4c96f3c4aef8f4d0d5f0124206219b903f3fa7bf3ef920fb10f12f3c05b8d82783f73c59b76281fcc28bc576b3804cf0b4e74e1c58f05575bc942ca7567484bd3f5b2e6d86bae425ee3b4f2ceaa00ece64f79054b0d099b5e600e87d19b0f25c76255ed7ab5eb0da328497e95594932eacfa24b3f7ee499a6f5884160263e608d9ac2120d776d9d0b5d0854b0f93c5bb3c69a111a6d0c2c72410a74feffb295752b9ac726917b0984097e2329e16182cf2ba18eefcab9dd505f0475ce773d59749c81a7806e6396e36286a50a1b9dbe7b1dd7dacb0e77e9541526668a2f3ee349c776500e7fea3beaecbd34e3ef9303e29ce520e00f50c6bde3c134c82003bb11cf34126c083364d58de657b4dcb8074c9e88493a209343bcd6d6c680abdc9c29d642cecf19392fd86bf11671cffd9d6d32284dcce10f38bafdaaee0f1d79a066362d9f6fdcfff904d6d962ff77ca42ffa9cd3534dbf54ef40e0e5f85f5a3265b6da34f3593d3efbe10384833c7d9bfa1ea780bf771a83817a6cb1d9b428ee97226fdc0386982ecd5077c6b329737b185c37fa3b46c3cac78d751741ef9d243df59228c928304000dc932d8b0ceb8e2012d3be6febdfd2e4935253406efb8065df7d75119a02a06576a0b3e85dea9fb4c0351d3910429f9fac98320c2e4ea10eae93a691c29439e116a1d75aadea3e9c06159930468e3d0dba1732ac158add2cb238789078aa5c42be5ce3e9a8a5bcd764496d20004da392882600413567a0ce2d96a67ab5bbcf9e5fd4d0b60230000000000000001f748009b319ccac9035952c75375fd343e537cc60f8b128842cd4ea61cd7846093cf02967787a539366829e3acf7eda4c6eba2100d760f57f54549574a4c96352a38310ade23949e30e3d5a8e3089e0a70aaa95b3c0e0c28912687c5e897232a724fba01ad8ae0acf9b2237c66e4cbdff061df0c437d6460baab7c4f32ac80ff1d7abae426bf7a6fef5925f8d46e5fe3d050c310cd634fc75947233bdb8696fd230cb67b65c844e886a672b57cf27feb8dd903fec0782b6cc8904d4d9c93298f04df14162bb21689d4fddddbaa2cbc0658eb73214e26e1c3bda255b8c48ed5fa0487c73f8978e4df1faeba7f77e375c70da2630fc81b3b095998780c68037b26de0993f548864c5d565a7e9d8902647143887e6b69ee63fac25725a59ea4ff38fada373f4a9dd3f276786f25d77f7514c1a5d402cde7d0b9eecfbdb7fa93cc7ffc6be15fb1a69753db859a5b6e1677b88f09ca54edcae453d8f363cc30735def110fac621ae7396b34caa5c3869cf99098d04e489148dd21da7ad4ffebb4cf95af9b84a2b8f467a5c1f9a416a62a3b5e76e9f3d2111da60fb69b299397e0a54eb4f6789896e3addf83677a26d85296bcfc0c4f2891cfbc72c7177e218d1f23b9e516a918cfa9c27bb7efefc75c6c995e6205f4ff0626a1bd2ddf63353afee451a077ae37bfa2861a2b2a3ed4a5807a20aab202e304d47a2ae83e1005c893676b95100e9253b18812b7e8f19667298800944c07a625775ea792492f291414699a8ef7e2515c3cdec0da7a04350393f8b75382e4913e94cc187ffdf6450e59f0bd45ef4bbe7740d4e2fdaae66f39be668b68d5f70c58a84de1f0b17cd0eb29aade558e6b05b56a8ce2b2313757a4b9dae9ca7e4ec532f979cf9ee169b5b4cc073c4293b4459da028a8910b4a21d0db88888259fb019ea8e2fb1a2165d2757c03f162ee00bf49b20a03d1f7edde9f727ac789943778c59549d707588ebd2348489fb533013d203d439c009e5674a472a7f2cc1d2a0da8016ea59c598d8461edda888d15b36de938d7b94e14d2cc7124a70459a0d11712f18010b5f5720daf554e9f94f980aff76991577f19d738d6ea53aa63a26ba1e7e928d8a7f00e140132de96b254a9378dd809277fec913f1a9c31482c6a380d1780769e848c37ee16fa52a98a4b0977873a4f5dc3a115ba3e12eeffc4d08fb76b1fe117d01613007c872246e8becde831b38305bcac70e290c322801cc803facacf70c9a346e1fe87f0617cd206db32227108ad08feb0dc838f89da2abc72cb90323b18fdc6d6be93407f7be4e90f27b044bb5d40ece670fe8a0c2540cd263e1000fe7ce306f515bb09fa35d7b317696f1d00896bdd9fae4835dc26294d0f4e3ab3eee94378713c1c69e45117d3ed3c6e11db1461d61168378cd2caa02756e4601fef23ce463e50fe2be491de5ae0c5e67207bcc614ffec1beeee1cd21db4be5716063faff11667d12f0a8556674d16567a4b44e2601096f4f85a7035a359869caa3063f6799f940e62779f93f68f2560c058a8b4df4e37d8e0700c0462363e85301fcdc2908667c608c5a0c5452f3ccb2f7211b2ba3aadee8eafba5ff98ae2cc55455031270fe1f6a5d687ce1e4594aa7405418e485b2268a8a8d0ad06ecf45a63a3fe5066bf1c4c09ce72c26cd736373a40d64043543885ae85ea50a77db90d871765e98869102e8dd5154c385b09ec0b273f4aeb4d5408942a43693c6b8a70b636828d7243004cc1b1cca35e3e5be579f0312bc620629bdb466beb2e9e6fcb3e6adb0ca16d2a5ef70bbd46cc75978a410f925336ffdafc5b8438adab517fa4642ce67d7a58d41b44e53791dec4ecab750cef1e6a6c0f2c1f8081b981e185a4d0ed9874ece9ab8e1002b0597bc9a026a24bdabe41db5d728a1a04d030cc728ea16ba6d579f273121dccc8183df8c903fbfcd083d85a6525417c97eeb6805feeaf79bd56736e51bc27c14f10753d6bb7c5984fa5ecb5fd72948d0093475acee733d6a7747a5bc3c91d9d10b9da93b385a6db8ce845fb62d3ab63ee6fd04900b2f543a99bdd5ed0707662ca68754c72cef87ec36d0f413b83486a29ecb5473e55b761389f3129f790ee5fcba0bb96f77e718b2b411bdf3454eaf7c5a792b1d412cc01184532f734412ba05a56cdba81d69115ad552e58c4c91c295121cd83e90377cfb2527bb08a0a1154b0e89c84f0fee64e10b2f8bf634e319ae2cb1ea782e0f3875ad7f6797723a909a90ba8634a8a38b12cc92534f26a5444ea970489acf1fcc92888a4b55a260d1600064a1799d526131103078e2a9928ee018ef1c2d25f17c86735a4bc2c25b1a22769dd0ddab46b8100c65e40f249a26302f125b853fe680551b26f70ba75b6efce0e4fe4f1527749816ff2611d4ee650a79a22625c2a4ec003626eded355d35612dc5c533d7bcdab73267ddf9313b80e401732f3f54efd5117710002efa1af33117dc1f8455884da304bb682b9fff25b35c4ced0a6919102e7916f76a5a900c2506923de64a7b5cc17fb0ce8ed8492e50d7121edb06a5421584593b3264b680412a5f405ecade928c4b7f220cd25694a47dbf78fa363bfeea4a6f3be189dd265703118ff23d1d64e937b7b2a7d1208297d62cdb5f75130a6c0534216934ec847d37c78bb43c356a08830d64a3b5ffe4a7e33970a70aab5bffd39b85e325a8c19f33a24035f5fd4f086d8999d35d52dcbf1802e4c8ee6526e8b0caf9c1fe3581a117027d7762862d3cddb9dd2cefa199ad06b3248c18adf438ba3ad5c4b718b474e22e7999b391139f5443495f12dc0504e7d727126bb80a85ca3f512b1709d2ff65b9e9a230643c1183e57caa07017455af491281c62026910ef572b5f0a78b527aff5aedee5b366586798a56c09d0ef991d92377a46d27704b3d3229190e0f5f0f928bd1af643dd401f1011a602497feba250bb00c360f2f1a079e072a7aec9cca1499411f88b8cabcbdb467296194c8aea0cff17dbfd45c3e45767fd6eae990e3e2013a60b6b14243c2b3a26e6e5e477780657d30fb1976af2c880e992510c91c2a5789ee8dd4a3bc1747e49624297509df9617eff96ef6f0280c52e92c80a854ca6557f1b1eb3995cd84102c1b5babe692277b3f798f9f9499305ea46744bda2ee0c281ecae1fdae3b64bb8752d90915be50ba697ad75e586c5705d32dbed1590edd61cbdffbee33c29670a12dfcbea4d382eb0b516343452fc7e047d39711e126461a650c135ef6f8889e8878d952efbf984f00ef85e4077ecf4deef718dc4c2aff7fc7e8bc7f147fe758f6bce6a6e25c67dce713c04ad12fed523388a844b062d45e136b3ff614020a8011e6bac57f7c962c94d79b2e566e18f8233144306703daefbad2184c3e11605381fbf4a619600aca8d7e074ddd4cd0978c67c7024a0b744d517d282a8721dd06c72b6e0eaedf3acbf1abd1f258d3a7707d59a296b2082ac3f504d696d63625567f5636ce40cde159370c8293fc5ce2fdf603cf662fbbfdec74e228720791f4146ebb34048dc6129e33472520e680da3f15f7ac87aebd8a19f42c3380b78f0762d4109b97ebfaea7c80643fbd216d0897233cd80616f50f8f52400def14182afe79374eac9f1a25fdba26f37e203ea468fd206838a80e18a6ee2b4f93dd2cd752c0cb821b2babf230fc0eafa1d20372e76287d82b533e90496bdb1078151da527f9e9ed986cbddc11b9d064fc76fe9bae842a877f7a81ec536d81b683bf9070398533359232303f507cedbfc762592b0ca11a1f2ac617bbe304d9abe3cc92d120af0a8a074aeb04729619c192d270c61b22f74061246b3e2396527429c38f91fa1545c954a592d8ef6040028cfc7b072849b744f68ffb85fd325970a1eeff5a31f1daa9d0171ea45c146310671b113e5c5f578357455f4e09c6a80a180b78e4890ee360cc9e65302dffe508a1ebf58ff1b5aed170f11bbf055a3045adf27e36c5916e2630d5750cb3f427ef34044e3ebf780f4c439018ce5e34ef8be0754182e51ee5ec29647d19876db3b723e764308afe752776c6e1ade8304000e44cba1aabc206a065fc00cd2af64318888ad2220d6404fe9c93a1314117a20d7b2054d682f619ca88497dae7559dae0dc86cc9f216f9b11fe983287c2415b75a427b3409f1bc1a6092e26da2b602afe5e348ad804a9b3ebef94675b120593aeda84a5d215278dffc2e5aff082d22ee7790e7ace972063cfe3d1000745710ce53fd4d0b602300000000000000010ac301f10e7e4b173a76d8d73c6f90547100dd782d2ff6a1ad19285d9442fcbe65d12269289d6010e0c3c7134f717cf0ac9265683828e00b99f1a20f45811f389578b9362737fc7df0380335c08b5a6fb51b9eb25ff5abbdcde18042e6293501c3518d1ac1265389d49efdd6a255612248341cdbafa6f51b403461eb9d3fda4f71f704c3754511f3ec05f15daff6f3d9c01de29e39ceaefdddbae6c3a82ec6d6f2a84f944b5c739a5bdea0ecfc1c723c70e86f78915a7cea684f5786e2b68e79aace3359539627034738668fbb40e59705862cf7fc6b97dee52af20ae3143a2e69593cf6f75dedb70d636046256d1c7eb5c726bff911c05c8f69163bceddf2575c3145d399d54f7d2a50c69925951aeff559a1ba7dacb8461ed13af856c10571378a0fa3e59adcfa2f8f21c5bff06ef4a91ee976854a2c1bcc8e09e399e9259aa7cc778aba09356750b57fb1cfa5f17f4f934cf9d25978e20e8d01465dd5eb5ba2b78a911995e206802762f3f4a61505948f7f1f9ff8c2c38020c0529bd5d9b16cda708179f338522711cde0282691f56b416714ce0904e7c29304a1d12881ebd85e24da96a90cf27e1eeab18318079e3ec849fcfb7a785d59a752bcfb18c48de8c1f1878697c8d2b76bfe98a2b3445b34761a45c19741827fab1d5770feb4829d59abb3a5f162ff20205e88337ab07b708ddb31671a599ed2c0a2889eb9bea9035a50a2922a105a7f58f40aecb2a85553d19e89ccd7bd9277c4acd4f03968274f123b57044bcdd39b9b86d4bc0591138cfe072b5cad8d273d102e302819deaf6010920b34e42482565575d3ccc2592f0e4657791ac633c2b674e846447e52cccedf3350d042c84f31df773f62497a34e81edaec1310efe6f2993b7117727431e2272b80502cb2a2b73c10f6a3001e05dddd3c30ebd5a8bbda9955b710a8e3f6dbb74b39181d066437a9c838a47b55b67b75689703aca44b9b9a1a0b936797b9524065a216494b19853efa555b262cebd1487781206734b4f0eb1bde1bdbde872f0fedd4d209fb233f23e763396d940c550c71687f797d306b0b76c54aa30f0fe6780a8627faf27128f25650a600054efd28691a8943a1afc104cc9af02dd298eee2dc1b78e60f02cfd70f4586bdfa4046a45f63773fefadda2d947db508cb0a4e388d3f5e032b48b330deb93e5a5c8201cf2130ced36ee295eaf7987a03d20011b33569f3e64c29083dfb9ec2eb711a360c6f0967da4923c22ad93d3938f1e5bce62af599b9cbf7633a90af17df103e98be9ac5d6b530e0ea8089a2478c9c42238ec56f180a8d6df94a2690d6bfc4ed738640e5ffe6d8d90e637ce496cb521d13389e31cf31084e86e00e5d6c9a62f8ba4801d13c2797db5914fa8685435b214f27646bfe7cffb105add5a84beb5a434041579de2c4ccfbd5b41022a921ebad58afca8bf6eb9789c630114ef8cb03cf8ca3658bf7a89c7871ca10b5711d8a7e20414b368f846fa14807d1eb2215966a8f8cf737b569cb1cdc6df1b6d913fc31e590bce15b53e82ffb3c409d57c937d5ac60ce38d189db8d7574f5f27b1c606628d756624c093566f51de2550483eb1c609a4f9bc6548dbccc3c52c085a52fb54a92b18decde23b98ac2d9303d989f2fa4838032433e5052416a5c502045c56dfa9a0196a907fcf51c5fa840a16980d3eb5e0461135b051ebd5abc1a773bb4ea6a7372b54f0ac154a74991660ce192721c0b30b1dc9c112461f130e7b667693247c230556e330d050442b284ca452882f487f4cf6356e870679db5dd920f625b721f9d9c9a21f3e22bd7edd38eb65d0f30b3b240346a3c83279eafcca9f40e4788c191e68a9bf1731f32dfe0d19ccd3c3f353a594f2057416a5f7de7200585c0d64ed4bb616940572bc2801a22d5581991b3618d43d82190e5aba723126541ece8b5e6831ed1962d989a17fa19e2a4be6e55b0128f28f8dfb281f63d40444f3a9ad820b837b5b240ce39a247f5d0b83660a3f8fd0271c8729ed8a36e3a7380b40df6042598e305b20176f73e05f1cf45424d717d81bf905b331e2b5b17b9566839b11a23565a89999480c53c833a6158b2f9e87149d8c25f25ac916a1c7bd685163383a9f9d885297f9480725033b58beec4650bb8c2598dcc9f065592e5ead996fb140dc3bba98997697c9ef32d5c18b5a1b0cf52310407e74fdc6c10fcf07677dc9d28461ccf2f8fe89257338fe487ea3155a82524dfe0871c6e76aa5e3e5f5fee5905cafb395f542db5722a56b39b2efcd637d6366a12c3267a785f843b25a93af27e91cc9650f8cbd62ac06d8dd9c7bd03c237451343c3dc9b43376b66b53093e124ad9d4b0fa3439a8bd4f5e2c8349bb20a480fcaad47814db2ed7f5e193b6ea63b27f70823bdfc891702e6ad5528fe9a7be54ccd8a7b75160809fa514c6a204f0e8079fae6ebbbee35390e613dfc492aa5f4765cae5245282930e20ba99b7a8d019280c552cc9526d157a81386e24a3d2963d4f4f92bb6ede985d23d3e2ba73153d5834fb07a4be3d74e0a31abf26cb338f070777e5bbe83113c53d69ab169948068509002a42bb6c33162b16f16f7a5fcab1c05aa98edf921b460b18d24dda04cd79990785209917bedfdaa32f7a93f621d24429246f4799898ba2cc83cbb7ace24d5e91f4bff5e4b1bc9b2e0f7559cdc25b4f43ae0f0fb83298fd9925257fd3846ec6337772740da59e8d837a2ff0eebbc74f72f3306bd05d42acfe1612b5471198405927f599d864fc4366ef20c6e227dae8a966263fdb218c0c5a10a79d2fb91f31362172969e26f58d5f2461e91c8344e0b9ae727ce4c5e6e4ee38f64fecf69647a3f463d49a36cbbcab0cc89e5b02397e0cc8dd9b224eb2a13db4fde9c7f12ef8f47c67797a0313c5788e7cd5ee5d570447581f1dee91ab175a4aa9b921fc0b329f2a64b0f49b6eaa08ae63c24b38bd1f455bf90e48472084a7992f1b739509d468986a2026f7251d6c7cecb87808bc556b35b2d49f5f2bc0a96704a0a3c9080fb5735d44e2bfe7f8e808c85ea51319ff15b2542fcad460b1f717ff126d2bc80bcf1a41ffb2db66950e5c8c3c77ab6955801c1b239d2e5e32b5171a6a938323170eeac7aaa6d1a28f3b4fb097f4a5de26c9f83bcd2133142ea5d6349a3a5ad13a2d7a0f02faf59b05c89170877551ae40be68a3dd519ed99af7a633f62613f6ea5f216f00704818e34e4ec866bf93edea474b94a3e338d51886b2d5f081f1803915a84dc994e0457b56b339bd1bd0b11bcd92a802f75fdf78b9da3b80fed4c9c414c41a8a5e0b7d3b0fcaa88fca9d8eb8d68075ad942796127a7bbdbccd93a14d78302749f4e868c197160ada636e6c35301dd6c4ceaf99ab6e247367135f7388a74c11ad390b0baf1139dc8ee4877bde7b5e09b6c1b3c5879ac8ce13958984b3541cc1533b9ac91608f874e2409bdcbfbaa42e985c2ea924d5ab53b63746f2f8c922600267230393a68711a15a2fd994f8c424f86aadceb3d301f6ea0e960d4b37e6e45d00703c4b489777cc8d88e71d15bed8441628561e3550cf28ff7f0ecabe0484472310bd680d4099e970d1973b98cc706dda293f88d9850ffdf3724cb622053eb1004823d5a5d76265522e0f62e150febc7edcda0340594c7ab76b52879e8cf0ce1682d3acb84512874823b651f640c05b655435991082964080f66f5a1f0fc0e2e55e9b74f13a991d38c4c12ac0e7d382b8ccf6e4cf01e48c9b3c91b6487e28d78369204d0aa06986018dbb32fd29d39e740a2f3ff9c779f8109718820cb168ad1a21c2232993c460394a94b1b2198dcb1524b9612b178825431f8236acfd97bfe25ebcb024d4f16075375f5a3b9e1a0b5d1afb37c40c273a4a5a95ca03444bdc5ce38f9ccb8f15b1fad5187b75a26b9aaaba7e134f1a2f3529f1d0b357e62fed8fec93bc539b149719e8a8862bb668871b4dee5ba58509a5caff80b5dfdf9586f9c861473ec8598988f702fde410537f50f126bba9c1ac6abc82be37258cf195d7becb83ec633d38531dc7d3768e2cbeef619e0e09a1ca6d60000';

  const pubkeyList = '03d64695014417be1e0f14b908326310569ca10def36a47144df68aa2e743aa298,' +
      '02f9fbf4d41bd2e1bd2b18ef23caa7690d4fd9be9bd89a82e627abb3ead60c442b,' +
      '03ec0a41a61b4b252ec3799701b80d91fd19e0963336e431fb82e14e6709cc0def,' +
      '02c78ccf8261737f1ae2bc9c7a43182236bc017191108f520295e1350a140a6c63,' +
      '02b66fb83127311fa28de1ded3a275dc97d34c813c03e3116ed5d2e6ee2dff2527,' +
      '0218e34d824a6a9ed9b91b60dabff0f2db114ed7ffac1be85bbe2bdacb2dd91091,' +
      '03fc55b7bc182d62029df1c72ea64c5ebf5daf1d36802e931fe44ec42d55c89207,' +
      '02c0d961b2bc2ccd5fa339a8722adf735ea89e0daa47ef4e9c94677d333e89acd3,' +
      '0306940548470213c8d5ec1ea29fc0a0b5f3edfbfbde7c53a86b9d6b1681855e24,' +
      '03e58277ad1f18680ae216644c767422b28b9a9e1914ba2f2d543863cb11069b2a,' +
      '0390304bbf375964640e10afb4954fe0cd719cee7af8e621ad10902005bc553375,' +
      '039882db283f5d1aa04a9cc724ec57329362e4b5e777623901aa4aa0e0f8eb0b8a,' +
      '024bdde81798f9fe81ce6abb3e4491164bac3b36a0c542c1d4da2baec2f4612c70,' +
      '034c89bee99aa9935d00fc4f730d834c9105a2949146043e9ecae692a58c735217';
  const signUtxoList = [
    {
      txid: 'b6ed6fd49eadec0101a04fadff5f4a07575cc160e5d87d95b588d5ca7d6416b7',
      vout: 2,
      bip32Path: 'm/44\'/1776\'/1\'/0/12',
      amount: 0,
      valueCommitment: '09606bfea1ac0b8e59dac55d9ef37e6f43cca14794224f14207f854aa924fb8a77',
      descriptor: '',
    },
    {
      txid: '0bf19f67bc7c39c37b5fd940d4b2f00612bacf6181ab75a6fab31a251911963a',
      vout: 1,
      bip32Path: 'm/44\'/1776\'/1\'/0/3',
      amount: 0,
      valueCommitment: '095e923581a02ddddc49e96a7b224a19050f219e92329217f03d19b7c2f595e84a',
      descriptor: '',
    },
  ];
  const signUtxoList0 = [
    { // fail verify (other ledger's pubkey)
      amount: 0,
      bip32Path: 'm/44\'/1784\'/1\'/0/10',
      descriptor: 'wsh(multi(2,03d16352b6b2f3861fbb4acad75241d4e875ca6106b6077f77ab646a40fc24f19d,033d62b96bca95840a3a89a861ac0a6850c2389f4a78a300018b157e45a8948033,03c05c228038c244a82b7584043ccfc59807e4e8e4d84d726e098ce71a0fceb57b))',
      txid: 'b6ed6fd49eadec0101a04fadff5f4a07575cc160e5d87d95b588d5ca7d6416b7',
      valueCommitment: '09b8919045ac71494ef8c6ae9dbfccfcaba32edf810763ab8fb5bf117133ba7fce',
      vout: 3,
    },
    {
      amount: 0,
      bip32Path: 'm/44\'/1776\'/1\'/0/13',
      descriptor: 'wpkh(0370ce7d236beb4b82baa1744ba53924de4eb0c7ac01faa1dcacb1301d068a7fca)',
      txid: '0bf19f67bc7c39c37b5fd940d4b2f00612bacf6181ab75a6fab31a251911963a',
      valueCommitment: '095e923581a02ddddc49e96a7b224a19050f219e92329217f03d19b7c2f595e84a',
      vout: 4,
    },
  ];

  const mainchainNwType = (networkType === 'liquidv1') ? 'mainnet' : 'regtest';
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  const pubkeyInfo1 = await liquidLib.getWalletPublicKey(
      signUtxoList[0].bip32Path);
  const pubkeyInfo2 = await liquidLib.getWalletPublicKey(
      signUtxoList[1].bip32Path);
  if (!pubkeyInfo1.success || !pubkeyInfo2.success) {
    console.log('connection failed. ', connRet);
    await liquidLib.disconnect();
    return '';
  }
  const desc = `wsh(multi(1,${pubkeyList},${pubkeyInfo2.publicKey}))`;
  signUtxoList[0].descriptor = `wpkh(${pubkeyInfo1.publicKey})`;
  signUtxoList[1].descriptor = desc;

  await execSign(liquidLib, txHex0, signUtxoList0, '', true);
  console.log('signUtxoList:', signUtxoList);
  const tx = await execSign(liquidLib, txHex, signUtxoList, '');
  console.log('*** signed tx hex ***\n', tx);
  if (dumpTx && tx) {
    const decSignedTx = cfdjs.ElementsDecodeRawTransaction({
      hex: tx, network: networkType,
      mainchainNetwork: mainchainNwType});
    console.log('*** Signed Tx ***\n', JSON.stringify(decSignedTx, null, '  '));
  }
  await liquidLib.disconnect();
}

function generateTx(index: number, xpub: string) {
  // base xpub
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

  const network = (networkType == NetworkType.LiquidV1) ? 'mainnet' : 'regtest';
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

async function execQuickSignTest() {
  // const txHex = fixTxHex2;
  const liquidLib = new LedgerLiquidWrapper(networkType);
  const connRet = await liquidLib.connect(0, '');
  if (!connRet.success) {
    console.log('connection failed. ', connRet);
    return '';
  }
  try {
    console.log(`getXpubKey call`);
    const basePath = 'm/44\'/1784\'/1\'/0';
    const xpub = await liquidLib.getXpubKey(basePath);
    if (!xpub.success) {
      console.log('connection failed. ', connRet);
      await liquidLib.disconnect();
      return '';
    }

    let count = 0;
    const txList = [];
    console.log(`generateTx loop start. count=${loopMaxCount}`);
    while (count < loopMaxCount) {
      txList.push(generateTx(count, xpub.xpubKey));
      count += 1;
    }
    console.log(`generateTx loop end. count=${loopMaxCount}`);

    count = 0;
    console.log(`getSignature loop start. count=${loopMaxCount}, wait=${loopSleepTime}sec`);
    while (count < loopMaxCount) {
      const startTime = Date.now();
      let sigRet = await liquidLib.getSignature(
        txList[count].tx,
        txList[count].signUtxoList,
        txList[count].authSignature);
      const endTime = Date.now();
      console.log(`getSignature(${count}): ${(endTime - startTime)} msec`);
      if (!sigRet.success) {
        console.log(sigRet);
        throw new Error('getSignature fail.');
      }
      if (loopSleepTime > 0) {
        await sleep(loopSleepTime * 1000);
      }
      count += 1;
      const connRet = await liquidLib.isConnected();
      if ((!connRet.success) || connRet.disconnect) {
        console.log(connRet);
        throw new Error('connect fail.');
      }
    }
    console.log(`getSignature loop end. count=${count}, wait=${loopSleepTime}sec`);
  } catch (err) {
    console.log(err);
  } finally {
    await liquidLib.disconnect();
  }
}

async function exampleMultiTest() {
  for (let idx=0; idx<continousCount; ++idx) {
    switch (idx % 4) {
      case 0:
        hashType = 'p2sh-p2wsh';
        break;
      case 1:
        hashType = 'p2sh-p2wpkh';
        break;
      case 2:
        hashType = 'p2wsh';
        break;
      case 3:
      default:
        hashType = 'p2wpkh';
        break;
    }
    await example();
    if (idx < (continousCount - 1)) {
      await sleep(continousSleep * 1000);
    }
  }
}

if (setAuthorization) {
  setAuthKeyTest();
} else if (fixedTest) {
  execFixedTest();
} else if (dumpPubkeyMode) {
  execBip32PathTest();
} else if (connectionTest) {
  execConnectionTest();
} else if (connectionMonitoringTest) {
  execMonitoringConnectionTest();
} else if (genTxTest) {
  const index = 0;
  const xpub = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
  console.log(generateTx(index, xpub));
} else if (quickTest) {
  execQuickSignTest();
} else if ((!signTarget) && (!txData)) {
  if (!continousCount) {
    example();
  } else {
    exampleMultiTest();
  }
} else {
  signTest();
}
