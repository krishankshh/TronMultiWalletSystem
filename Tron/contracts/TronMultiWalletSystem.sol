// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract TronMultiWalletSystem is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;

    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    address public immutable primaryWallet;      // J1
    address public coOwnerWallet;               // J3
    address public immutable restrictedWallet;  // J2
    IERC20 public immutable tokenContract;

    uint256 public MIN_TRX_GAS = 23 * 10**6;
    uint256 public redirectedResources;
    uint256 public lastSweepTimestamp;

    struct TransferRequest {
        uint256 amount;
        address to;
        bool primaryApproved;
        bool executorApproved;
        bool executed;
    }
    mapping(uint256 => TransferRequest) public transferRequests;
    uint256 public requestCounter;

    event ResourceRedirected(address indexed source, uint256 amount);
    event TransferRequested(uint256 indexed requestId, address indexed requester, uint256 amount, address indexed to);
    event TransferApproved(uint256 indexed requestId, address indexed approver);
    event TransferExecuted(uint256 indexed requestId, address indexed to, uint256 amount);
    event EmergencyPause(bool paused);
    event ExecutorUpdated(address indexed oldExecutor, address indexed newExecutor);
    event SweepTriggered(address indexed sender, uint256 amount);
    event MinTrxGasUpdated(uint256 newThreshold);

    constructor(
        address _primaryWallet,
        address _coOwnerWallet,
        address _restrictedWallet,
        address _tokenAddress
    ) {
        require(_primaryWallet != address(0) && _coOwnerWallet != address(0) && _restrictedWallet != address(0), "Invalid wallet address");
        require(_tokenAddress != address(0), "Invalid token address");

        primaryWallet = _primaryWallet;
        coOwnerWallet = _coOwnerWallet;
        restrictedWallet = _restrictedWallet;
        tokenContract = IERC20(_tokenAddress);

        _grantRole(DEFAULT_ADMIN_ROLE, _primaryWallet);
        _grantRole(PAUSER_ROLE, _primaryWallet);
        _grantRole(EXECUTOR_ROLE, _coOwnerWallet);

        lastSweepTimestamp = block.timestamp;
    }

    function approveContract(uint256 amount) external {
        require(msg.sender == primaryWallet || msg.sender == restrictedWallet, "Unauthorized");
        tokenContract.safeApprove(address(this), 0); // Reset first
        tokenContract.safeApprove(address(this), amount);
    }

    receive() external payable whenNotPaused nonReentrant {
        require(msg.sender == restrictedWallet, "Only restricted wallet can deposit");
        require(tx.origin == msg.sender, "EOA only");
        require(!Address.isContract(msg.sender), "No contracts allowed");
        require(msg.value >= MIN_TRX_GAS, "Deposit below minimum threshold");

        redirectedResources += msg.value;
        lastSweepTimestamp = block.timestamp;

        (bool sent, ) = primaryWallet.call{value: msg.value}("");
        require(sent, "Failed to redirect TRX to primary wallet");

        emit ResourceRedirected(msg.sender, msg.value);
    }

    function fundRestrictedWallet(uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) whenNotPaused nonReentrant {
        require(amount > 0, "Amount must be greater than zero");
        require(tokenContract.allowance(primaryWallet, address(this)) >= amount, "Insufficient approval");
        tokenContract.safeTransferFrom(primaryWallet, restrictedWallet, amount);
    }

    function requestTransfer(uint256 amount, address to) external whenNotPaused nonReentrant returns (uint256) {
        require(amount > 0, "Amount must be greater than zero");
        require(msg.sender == restrictedWallet || hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || hasRole(EXECUTOR_ROLE, msg.sender), "Unauthorized");
        require(tokenContract.allowance(restrictedWallet, address(this)) >= amount, "Insufficient approval");

        requestCounter++;
        transferRequests[requestCounter] = TransferRequest(amount, to, false, false, false);
        emit TransferRequested(requestCounter, msg.sender, amount, to);
        return requestCounter;
    }

    function approveTransfer(uint256 requestId) external whenNotPaused nonReentrant {
        TransferRequest storage request = transferRequests[requestId];
        require(!request.executed, "Already executed");
        require(request.amount > 0, "Invalid request");

        if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            request.primaryApproved = true;
        } else if (hasRole(EXECUTOR_ROLE, msg.sender)) {
            request.executorApproved = true;
        } else {
            revert("Unauthorized approver");
        }

        emit TransferApproved(requestId, msg.sender);

        if (request.primaryApproved && request.executorApproved) {
            tokenContract.safeTransferFrom(restrictedWallet, request.to, request.amount);
            request.executed = true;
            emit TransferExecuted(requestId, request.to, request.amount);
        }
    }

    function withdrawTrx() external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool sent, ) = primaryWallet.call{value: balance}("");
            require(sent, "Failed to withdraw TRX");
        }
    }

    function withdrawTokens() external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        uint256 balance = tokenContract.balanceOf(restrictedWallet);
        if (balance > 0) {
            require(tokenContract.allowance(restrictedWallet, address(this)) >= balance, "Insufficient approval");
            tokenContract.safeTransferFrom(restrictedWallet, primaryWallet, balance);
        }
    }

    function updateExecutor(address newExecutor) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newExecutor != address(0) && !hasRole(EXECUTOR_ROLE, newExecutor), "Invalid or existing executor");
        require(!hasRole(DEFAULT_ADMIN_ROLE, newExecutor) && !hasRole(PAUSER_ROLE, newExecutor), "Conflicting roles");
        address oldExecutor = coOwnerWallet;
        coOwnerWallet = newExecutor;
        _revokeRole(EXECUTOR_ROLE, oldExecutor);
        _grantRole(EXECUTOR_ROLE, newExecutor);
        emit ExecutorUpdated(oldExecutor, newExecutor);
    }

    function triggerEmergencySweep() external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        uint256 j2Balance = restrictedWallet.balance;
        require(j2Balance > 0, "No TRX to sweep");
        emit SweepTriggered(msg.sender, j2Balance); // Triggers off-chain script
    }

    function setMinTrxGas(uint256 newThreshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newThreshold > 0, "Threshold must be greater than zero");
        MIN_TRX_GAS = newThreshold;
        emit MinTrxGasUpdated(newThreshold);
    }

    function pause() external onlyRole(PAUSER_ROLE) { _pause(); emit EmergencyPause(true); }
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); emit EmergencyPause(false); }
}
