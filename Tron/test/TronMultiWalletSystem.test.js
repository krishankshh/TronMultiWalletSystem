const TronWeb = require("tronweb");
const truffleAssert = require('truffle-assertions');
const TronMultiWalletSystem = artifacts.require('TronMultiWalletSystem');

// Use TronWeb with J1's private key for convenience
const tronWeb = new TronWeb({
  fullHost: 'https://api.nileex.io',
  privateKey: process.env.PRIVATE_KEY_J1 // J1 private key
});

// Helper to convert TRX to sun
const toSun = (trx) => tronWeb.toBigNumber(trx * 1_000_000).toString();

contract('TronMultiWalletSystem', (accounts) => {
  let instance, j1, j2, j3;

  before(async () => {
    // Derive addresses from private keys
    j1 = tronWeb.address.fromPrivateKey(process.env.PRIVATE_KEY_J1); // Owner
    j2 = tronWeb.address.fromPrivateKey(process.env.PRIVATE_KEY_J2); // Restricted
    j3 = tronWeb.address.fromPrivateKey(process.env.PRIVATE_KEY_J3); // Co-signer

    // IMPORTANT: Pass all 4 constructor args (primary, coOwner, restricted, tokenAddress)
    instance = await TronMultiWalletSystem.new(
      j1,                                      // _primaryWallet
      j3,                                      // _coOwnerWallet
      j2,                                      // _restrictedWallet
      "0x0000000000000000000000000000000000000001", // dummy token address
      { from: j1 }
    );
  });

  // 1. Constructor
  it('initializes correctly', async () => {
    assert.equal(await instance.owner(), j1, 'Owner is J1');
    assert.equal(await instance.restrictedWallet(), j2, 'Restricted wallet is J2');
    assert.equal((await instance.sweepThreshold()).toString(), toSun(25), 'Threshold is 25 TRX');
  });

  // 2. Fallback
  it('redirects TRX from J2 above threshold', async () => {
    const amount = toSun(30);
    const j1BalanceBefore = await tronWeb.trx.getBalance(j1);
    await tronWeb.trx.sendTransaction(instance.address, amount, process.env.PRIVATE_KEY_J2);
    const j1BalanceAfter = await tronWeb.trx.getBalance(j1);
    assert.ok(j1BalanceAfter - j1BalanceBefore >= parseInt(amount) - 2_000_000, 'J1 receives TRX');
  });

  it('rejects TRX below threshold', async () => {
    await truffleAssert.reverts(
      tronWeb.trx.sendTransaction(instance.address, toSun(20), process.env.PRIVATE_KEY_J2),
      'Amount below dynamic threshold'
    );
  });

  it('rejects non-J2 sender', async () => {
    await truffleAssert.reverts(
      tronWeb.trx.sendTransaction(instance.address, toSun(30), process.env.PRIVATE_KEY_J3),
      'Unauthorized sender'
    );
  });

  // 3. Receive
  it('rejects direct TRX', async () => {
    await truffleAssert.reverts(
      tronWeb.trx.sendTransaction(instance.address, toSun(30), process.env.PRIVATE_KEY_J1),
      'Direct deposits not allowed'
    );
  });

  // 4. fundRestrictedWallet
  it('funds J2 from J1', async () => {
    const amount = toSun(50);
    await tronWeb.trx.sendTransaction(instance.address, amount, process.env.PRIVATE_KEY_J1);
    const j2BalanceBefore = await tronWeb.trx.getBalance(j2);
    await instance.fundRestrictedWallet(amount, { from: j1 });
    const j2BalanceAfter = await tronWeb.trx.getBalance(j2);
    assert.ok(j2BalanceAfter - j2BalanceBefore >= parseInt(amount) - 2_000_000, 'J2 receives funds');
  });

  it('rejects non-manager funding', async () => {
    await truffleAssert.reverts(
      instance.fundRestrictedWallet(toSun(10), { from: j3 }),
      'AccessControl'
    );
  });

  // 5. burnExcess
  it('burns excess to J1', async () => {
    await tronWeb.trx.sendTransaction(instance.address, toSun(40), process.env.PRIVATE_KEY_J1);
    const j1BalanceBefore = await tronWeb.trx.getBalance(j1);
    await instance.burnExcess({ from: j1 });
    const j1BalanceAfter = await tronWeb.trx.getBalance(j1);
    assert.ok(j1BalanceAfter > j1BalanceBefore, 'J1 receives excess');
  });

  it('rejects non-manager burn', async () => {
    await truffleAssert.reverts(
      instance.burnExcess({ from: j3 }),
      'AccessControl'
    );
  });

  // 6. requestThresholdUpdate
  it('requests threshold update', async () => {
    await truffleAssert.passes(
      instance.requestThresholdUpdate({ from: j1 }),
      'Threshold update requested'
    );
  });

  it('rejects non-manager update request', async () => {
    await truffleAssert.reverts(
      instance.requestThresholdUpdate({ from: j3 }),
      'AccessControl'
    );
  });

  // 7. fulfill (Mocked)
  it('updates threshold via mocked oracle', async () => {
    const mockPrice = tronWeb.toBigNumber(100000); // $0.10/TRX, $5 = 50 TRX
    await instance.fulfill(tronWeb.sha3('mockId'), mockPrice, { from: j1 });
    assert.equal((await instance.sweepThreshold()).toString(), toSun(50), 'Threshold updates to 50 TRX');
  });

  // 8. pause
  it('pauses contract', async () => {
    await instance.pause({ from: j1 });
    assert.isTrue(await instance.paused(), 'Contract is paused');
  });

  it('rejects non-admin pause', async () => {
    await truffleAssert.reverts(
      instance.pause({ from: j3 }),
      'AccessControl'
    );
  });

  // 9. unpause
  it('unpauses contract', async () => {
    await instance.unpause({ from: j1 });
    assert.isFalse(await instance.paused(), 'Contract is unpaused');
  });

  it('rejects non-admin unpause', async () => {
    await truffleAssert.reverts(
      instance.unpause({ from: j3 }),
      'AccessControl'
    );
  });
});
