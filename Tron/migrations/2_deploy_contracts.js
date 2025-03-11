const TronMultiWalletSystem = artifacts.require("TronMultiWalletSystem");

module.exports = function(deployer) {
  const j1 = "THEJwQ8iiaEFbTa18jzPa8v61eo1yQ3YwZ";
  const j3 = "TPG3Lf4YJKZYhHsyfRRnsFxtKMP2zskfA2";
  const j2 = "TK7UMoA1eUi3NmqEUKFNU7UdxXVBep9VUZ";
  const usdt = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf";

  deployer.deploy(
    TronMultiWalletSystem,
    j1,
    j3,
    j2,
    usdt
  );
};