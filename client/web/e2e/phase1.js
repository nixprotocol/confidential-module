(async () => {
  await window.wasmReady;
  const chainId = 'test-chain-1', denom = 'uatom';
  const alice = 'cosmos1v9kxjcm9ta047h6lta047h6lta047h6l33fvfn', bob = 'cosmos1vfhkyh6lta047h6lta047h6lta047h6ludswkc';
  const chk = (l, r) => { if (r && r.error) throw new Error(l + ': ' + r.error); return r; };

  const aliceK = chk('key alice', wasmDeriveKey('11'.repeat(32), 0));
  const bobK   = chk('key bob',   wasmDeriveKey('22'.repeat(32), 0));
  const audK   = chk('key aud',   wasmDeriveKey('33'.repeat(32), 0));

  const alicePop = chk('pop alice', wasmRegisterKeyProof(aliceK.secretKeyHex, aliceK.pubkeyHex, chainId, alice));
  const bobPop   = chk('pop bob',   wasmRegisterKeyProof(bobK.secretKeyHex,   bobK.pubkeyHex,   chainId, bob));

  // Amounts cross as decimal strings; maxBits must match the chain's
  // params.max_transfer_bits.
  const maxBits = 64;

  const shield = chk('shield', wasmShield(
    aliceK.secretKeyHex, aliceK.pubkeyHex, '5000', chainId, alice, denom, '', 0));

  const send = chk('send', wasmSend(
    aliceK.secretKeyHex, aliceK.pubkeyHex, bobK.pubkeyHex, audK.pubkeyHex,
    '1000', '5000', shield.randomnessHex,
    chainId, alice, bob, denom, shield.ciphertextHex, 1, maxBits));

  return { aliceK, bobK, audK, alicePop, bobPop, shield, send };
})()
