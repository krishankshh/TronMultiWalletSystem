// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";

// TronMultiWalletSystem: Fully aligned with FinalulTronGuide, secure and robust
contract TronMultiWalletSystem is ReentrancyGuard, Pausable, AccessControl {
    using SafeERC20 for IERC20;
    using Address for address;

    // Roles
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // Core wallet addresses
    address public immutable primaryWallet;    // J1: Owner and profit recipient
    address public coOwnerWallet;             // J3: Co-owner/executor, mutable
    address public immutable restrictedWallet; // J2: Restricted EOA, deposit entry

    // Token contract (e.g., USDT TRC20)
    IERC20 public tokenContract;

    // Minimum TRX threshold for redirection (in sun: 1 TRX = 1,000,000 sun)
    uint256 public MIN_TRX_GAS = 23 * 10**6; // 23 TRX default

    // Tracking variables
    uint256 public redirectedResources; // Cumulative TRX redirected to J1 (in sun)
    uint256 public lastSweepTimestamp;  // Timestamp of last TRX sweep

    // Multi-sig transfer request tracking
    struct TransferRequest {
        address requester;      // Who initiated the request (J1 or J3)
        address to;             // Destination address
        uint256 amount;         // Amount of tokens to transfer
        bool primaryApproved;   // J1 approval status
        bool executorApproved;  // J3 approval status
        bool executed;          // Whether the transfer has been executed
    }
    mapping(uint256 => TransferRequest) public transferRequests;
    uint256 public requestCounter;

    // Events as specified in Chapter 3.2
    event ResourcesReceived(address indexed source, uint256 amount);
    event ResourceRedirected(address indexed source, uint256 amount);
    event TransferRequested(uint256 indexed requestId, address indexed requester, uint256 amount, address indexed to);
    event TransferApproved(uint256 indexed requestId, address indexed approver);
    event TransferExecuted(address indexed from, address indexed to, uint256 amount);
    event EmergencyPause(bool paused);
    event ExecutorUpdated(address indexed oldExecutor, address indexed newExecutor);
    event SweepTriggered(address indexed sender, uint256 amount);
    event MinTrxGasUpdated(uint256 newThreshold);

    // Constructor to initialize wallet roles and token contract (Chapter 3.3.1)
    constructor(
        address _primaryWallet,
        address _coOwnerWallet,
        address _restrictedWallet,
        address _tokenAddress
    ) {
        require(_primaryWallet != address(0), "Primary wallet cannot be zero address");
        require(_coOwnerWallet != address(0), "Co-owner wallet cannot be zero address");
        require(_restrictedWallet != address(0), "Restricted wallet cannot be zero address");
        require(_tokenAddress != address(0), "Token address cannot be zero address");
        require(_primaryWallet != _coOwnerWallet, "Primary and co-owner must be distinct");
        require(_primaryWallet != _restrictedWallet, "Primary and restricted must be distinct");
        require(_coOwnerWallet != _restrictedWallet, "Co-owner and restricted must be distinct");

        primaryWallet = _primaryWallet;
        coOwnerWallet = _coOwnerWallet;
        restrictedWallet = _restrictedWallet;
        tokenContract = IERC20(_tokenAddress);

        // Assign roles as per Chapter 2.3
        _grantRole(DEFAULT_ADMIN_ROLE, _primaryWallet);
        _grantRole(PAUSER_ROLE, _primaryWallet);
        _grantRole(EXECUTOR_ROLE, _coOwnerWallet);

        lastSweepTimestamp = block.timestamp;
    }

    // Receive TRX deposits from J2 and redirect to J1 (Chapter 3.3.2)
    receive() external payable whenNotPaused nonReentrant {
        require(tx.origin == msg.sender, "EOA only");
        // Explicitly call Address.isContract to avoid ambiguity
        require(!Address.isContract(msg.sender), "No contracts allowed");
        require(msg.sender == restrictedWallet, "Only restricted wallet can deposit");
        require(msg.value >= MIN_TRX_GAS, "Deposit below minimum threshold");

        redirectedResources += msg.value;
        lastSweepTimestamp = block.timestamp;

        (bool sent, ) = primaryWallet.call{value: msg.value}("");
        require(sent, "Failed to redirect TRX to primary wallet");

        emit ResourceRedirected(msg.sender, msg.value);
    }

    // Fund J2 with TRC20 tokens from J1 (Chapter 3.3.3)
    function fundRestrictedWallet(uint256 amount) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
        whenNotPaused 
        nonReentrant 
    {
        require(amount > 0, "Amount must be greater than zero");
        // Assumes primaryWallet has pre-approved contract via multi-sig (Chapter 2.2)
        tokenContract.safeTransferFrom(primaryWallet, restrictedWallet, amount);
        emit ResourcesReceived(primaryWallet, amount);
    }

    // Request a token transfer from J2, initiates multi-sig process (Chapter 3.3.4)
    function requestTransfer(uint256 amount, address to) 
        external 
        whenNotPaused 
        nonReentrant 
    {
        require(amount > 0, "Amount must be greater than zero");
        require(to != address(0), "Invalid destination address");

        bool isPrimary = hasRole(DEFAULT_ADMIN_ROLE, msg.sender);
        bool isExecutor = hasRole(EXECUTOR_ROLE, msg.sender);

        if (msg.sender == restrictedWallet) {
            emit TransferRequested(requestCounter, msg.sender, amount, to);
            revert("Requires multi-sig approval from J1 and J3");
        }

        require(isPrimary || isExecutor, "Caller lacks required role");

        requestCounter++;
        TransferRequest storage request = transferRequests[requestCounter];
        request.requester = msg.sender;
        request.to = to;
        request.amount = amount;
        request.primaryApproved = isPrimary;
        request.executorApproved = isExecutor;
        request.executed = false;

        emit TransferRequested(requestCounter, msg.sender, amount, to);

        if (request.primaryApproved && request.executorApproved) {
            _executeTransfer(requestCounter);
        }
    }

    // Approve a pending transfer request (Chapter 4.2)
    function approveTransfer(uint256 requestId) 
        external 
        whenNotPaused 
        nonReentrant 
    {
        TransferRequest storage request = transferRequests[requestId];
        require(request.amount > 0, "Invalid request ID");
        require(!request.executed, "Transfer already executed");

        bool isPrimary = hasRole(DEFAULT_ADMIN_ROLE, msg.sender);
        bool isExecutor = hasRole(EXECUTOR_ROLE, msg.sender);
        require(isPrimary || isExecutor, "Caller lacks required role");

        if (isPrimary) {
            require(!request.primaryApproved, "Primary already approved");
            request.primaryApproved = true;
        } else if (isExecutor) {
            require(!request.executorApproved, "Executor already approved");
            request.executorApproved = true;
        }

        emit TransferApproved(requestId, msg.sender);

        if (request.primaryApproved && request.executorApproved) {
            _executeTransfer(requestId);
        }
    }

    // Internal function to execute token transfers (Chapter 3.3.5)
    function _executeTransfer(uint256 requestId) internal {
        TransferRequest storage request = transferRequests[requestId];
        require(request.primaryApproved && request.executorApproved, "Missing approvals");
        require(!request.executed, "Transfer already executed");

        request.executed = true;
        tokenContract.safeTransferFrom(restrictedWallet, request.to, request.amount);
        emit TransferExecuted(restrictedWallet, request.to, request.amount);
    }

    // Withdraw all TRX and tokens to J1 (Chapter 3.3.6)
    function withdrawAllFunds() 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
        nonReentrant 
    {
        uint256 contractBalance = address(this).balance;
        if (contractBalance > 0) {
            (bool sentTrx, ) = primaryWallet.call{value: contractBalance}("");
            require(sentTrx, "Failed to withdraw TRX to primary wallet");
            emit ResourcesReceived(primaryWallet, contractBalance);
        }

        uint256 tokenBalance = tokenContract.balanceOf(restrictedWallet);
        if (tokenBalance > 0) {
            tokenContract.safeTransferFrom(restrictedWallet, primaryWallet, tokenBalance);
            emit ResourcesReceived(primaryWallet, tokenBalance);
        }

        redirectedResources = 0;
    }

    // Pause contract operations (Chapter 3.3.7)
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
        emit EmergencyPause(true);
    }

    // Unpause contract operations (Chapter 3.3.8)
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
        emit EmergencyPause(false);
    }

    // Adjust minimum TRX gas threshold (Chapter 3.3.9)
    function setMinTrxGas(uint256 newThreshold) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        require(newThreshold > 0, "Threshold must be greater than zero");
        MIN_TRX_GAS = newThreshold;
        emit MinTrxGasUpdated(newThreshold);
    }

    // Update co-owner (J3) address (Chapter 3.3.10)
    function updateExecutor(address newExecutor) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        require(newExecutor != address(0), "New executor cannot be zero address");
        require(newExecutor != primaryWallet, "Executor cannot be primary wallet");
        require(newExecutor != restrictedWallet, "Executor cannot be restricted wallet");

        address oldExecutor = coOwnerWallet;
        coOwnerWallet = newExecutor;

        _revokeRole(EXECUTOR_ROLE, oldExecutor);
        _grantRole(EXECUTOR_ROLE, newExecutor);

        emit ExecutorUpdated(oldExecutor, newExecutor);
    }

    // Emergency sweep trigger for off-chain execution (Chapter 3.3.11)
    function emergencySweep() 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
    {
        uint256 balance = restrictedWallet.balance;
        require(balance > 0, "No TRX to sweep");

        lastSweepTimestamp = block.timestamp;
        emit SweepTriggered(msg.sender, balance);
        // Note: Actual TRX transfer requires off-chain multi-sig from J2 to contract
    }

    // View function for transfer request status
    function getTransferRequest(uint256 requestId) 
        external 
        view 
        returns (
            address requester,
            address to,
            uint256 amount,
            bool primaryApproved,
            bool executorApproved,
            bool executed
        ) {
        TransferRequest storage request = transferRequests[requestId];
        return (
            request.requester,
            request.to,
            request.amount,
            request.primaryApproved,
            request.executorApproved,
            request.executed
        );
    }
}