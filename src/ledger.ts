import { LedgerLiquidWrapper, NetworkType, WalletUtxoData } from './ledger-liquid-lib'
import { Mutex } from './mutex'

export const Ledger = new (class Ledger {
  private ledgerLiquid: LedgerLiquidWrapper
  private mutex: Mutex
  private connectMaxWaitTime: number

  constructor() {
    this.ledgerLiquid = new LedgerLiquidWrapper(
      NetworkType.Regtest
    )
    this.mutex = new Mutex()
    this.connectMaxWaitTime = 10
  }

  private waitForLock = () => this.mutex.acquire()

  public connect = async () => {
    const release = await this.waitForLock()
    try {
      const isConnected = await this.ledgerLiquid.isConnected()
      if (isConnected.success) {
        return
      }
      const response = await this.ledgerLiquid.connect(this.connectMaxWaitTime, undefined)
      if (!response.success) {
        throw new Error(`this.ledgerLiquid.connect: ${JSON.stringify(response)}`)
      }
      return
    } catch (err) {
      console.log(err)
      throw err
    } finally {
      release()
    }
  }

  public disconnect = async () => {
    const release = await this.waitForLock()
    try {
      const response = await this.ledgerLiquid.isConnected()
      if (!response.success) {
        return
      }
      return this.ledgerLiquid.disconnect()
    } catch (err) {
      console.log(err)
      throw err
    } finally {
      release()
    }
  }

  public checkConnection = async () => (await this.ledgerLiquid.isConnected()).success

  public getXpubKey = async (param: { hdWalletPath: string }) => {
    const release = await this.waitForLock()
    try {
      const response = await this.ledgerLiquid.getXpubKey(param.hdWalletPath)
      if (!response.success) {
        throw new Error(`this.ledgerLiquid.getXpubKey: ${JSON.stringify(response)}`)
      }
      return response.xpubKey
    } catch (err) {
      console.log(err)
      throw err
    } finally {
      release()
    }
  }

  public listSignatures = async (param: {
    proposalTx: string
    signTargetUtxos: WalletUtxoData[]
    proposalTxSignature: string
  }) => {
    const release = await this.waitForLock()
    try {
      const response = await this.ledgerLiquid.getSignature(
        param.proposalTx,
        param.signTargetUtxos,
        param.proposalTxSignature
      )
      if (!response.success) {
        throw new Error(`this.ledgerLiquid.getSignature: ${JSON.stringify(response)}`)
      }
      return response.signatureList.map(data => data.signature)
    } catch (err) {
      console.log(err)
      throw err
    } finally {
      release()
    }
  }
})()
