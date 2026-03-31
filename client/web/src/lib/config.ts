export const chainConfig = {
  chainId: "nix",
  chainName: "Nix Protocol",
  rpc: "http://localhost:26657",
  rest: "http://localhost:1317",
  bip44: { coinType: 118 },
  bech32Config: {
    bech32PrefixAccAddr: "cosmos",
    bech32PrefixAccPub: "cosmospub",
    bech32PrefixValAddr: "cosmosvaloper",
    bech32PrefixValPub: "cosmosvaloperpub",
    bech32PrefixConsAddr: "cosmosvalcons",
    bech32PrefixConsPub: "cosmosvalconspub",
  },
  currencies: [
    { coinDenom: "ANIX", coinMinimalDenom: "anix", coinDecimals: 0 },
    { coinDenom: "STAKE", coinMinimalDenom: "stake", coinDecimals: 0 },
  ],
  feeCurrencies: [
    { coinDenom: "STAKE", coinMinimalDenom: "stake", coinDecimals: 0, gasPriceStep: { low: 0.01, average: 0.025, high: 0.04 } },
  ],
  stakeCurrency: {
    coinDenom: "STAKE",
    coinMinimalDenom: "stake",
    coinDecimals: 0,
  },
  gasPrice: "0.025stake",
} as const;

/** Flat alias used by keplr.ts and chain.ts */
export const CHAIN_CONFIG = {
  chainId: chainConfig.chainId,
  chainName: chainConfig.chainName,
  rpc: chainConfig.rpc,
  rest: chainConfig.rest,
  coinType: chainConfig.bip44.coinType,
  bech32Prefix: chainConfig.bech32Config.bech32PrefixAccAddr,
} as const;
