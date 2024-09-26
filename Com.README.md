- 👋 Hi, I’m "ChaisFitzwater@ETEnterprises1.com
- 👀 I’m interested in "https://d.docs.live.net/e4c013ddd9f664a6/Documents/May%2023%5eLJ%202023%201105%20PM.0x74de79a7352e128df63b40949dd94a2f95e8d9ebfd0c2bc1892439c8ec2e5214.docx...
- 🌱 # I’m currently learning #/"0x74de79a7352e128df63b40949dd94a2f95e8d9ebfd0c2bc1892439c8ec2e5214...
- 💞️ I’m looking to collaborate on "https://etherscan.io/address/0x00000000219ab540356cbb839cbe05303d7705fa#code#L1...
- 📫 #How to reach me #/"master333-ui-web-bank...
- 😄 Pronouns: ...
- ⚡ Fun fact:
Search by Address / Txn Hash / Block / Token / Domain Name
Etherscan Logo
 Sign In


Token
Ethereum 2.0 (ETH 2.0)
Sponsored:   MetaWin: Compete for your share of $ 1 MILLION in prizes. $350k for 1st Place. Play Now! 
ERC-20
Overview
Max Total Supply
986,277,641,606.951759644958850414
ETH 2.0
Holders
42
Market
Onchain Market Cap 
$0.00
Circulating Supply Market Cap
-
Other Info
Token Contract (WITH 18 Decimals)
0x0dd7cf1d102118fcb498fc5b9a5f23c043407748
Image by Persona
PersonaAds By Persona
 Filtered by Token Holder
0x00000000219ab540356cBB839Cbe05303d7705Fa
Beacon Deposit Contract
Balance
35,096,351,552.378900036417012812 ETH 2.0
Value
$0.00
Transfers
Info
Contract
Analytics
Cards
New
0x00000000219ab540356cbb839cbe05303d7705fa

[ Download: CSV Export  ]
A token is a representation of an on-chain or off-chain asset. The token page shows information such as price, total supply, holders, transfers and social links. Learn more about this page in our Knowledge Base.
Back to Top
Ethereum Logo
Powered by Ethereum
Etherscan is a Block Explorer and Analytics Platform for Ethereum, a decentralized smart contracts platform.

Company
About Us
Brand Assets
Contact Us
Careers We're Hiring!
Terms & Privacy
Bug Bounty
Community
API Documentation
Knowledge Base
Network Status
Newsletters
Products & Services
Advertise
Explorer as a Service (EaaS)
API Plans
Priority Support
Blockscan 
Blockscan Chat 
Etherscan © 2024 (B1)

Donations: 0x71c765...d8976f 
/**
 *Submitted for verification at Etherscan.io on 2020-10-14
*/

// ┏━━━┓━┏┓━┏┓━━┏━━━┓━━┏━━━┓━━━━┏━━━┓━━━━━━━━━━━━━━━━━━━┏┓━━━━━┏━━━┓━━━━━━━━━┏┓━━━━━━━━━━━━━━┏┓━
// ┃┏━━┛┏┛┗┓┃┃━━┃┏━┓┃━━┃┏━┓┃━━━━┗┓┏┓┃━━━━━━━━━━━━━━━━━━┏┛┗┓━━━━┃┏━┓┃━━━━━━━━┏┛┗┓━━━━━━━━━━━━┏┛┗┓
// ┃┗━━┓┗┓┏┛┃┗━┓┗┛┏┛┃━━┃┃━┃┃━━━━━┃┃┃┃┏━━┓┏━━┓┏━━┓┏━━┓┏┓┗┓┏┛━━━━┃┃━┗┛┏━━┓┏━┓━┗┓┏┛┏━┓┏━━┓━┏━━┓┗┓┏┛
// ┃┏━━┛━┃┃━┃┏┓┃┏━┛┏┛━━┃┃━┃┃━━━━━┃┃┃┃┃┏┓┃┃┏┓┃┃┏┓┃┃━━┫┣┫━┃┃━━━━━┃┃━┏┓┃┏┓┃┃┏┓┓━┃┃━┃┏┛┗━┓┃━┃┏━┛━┃┃━
// ┃┗━━┓━┃┗┓┃┃┃┃┃┃┗━┓┏┓┃┗━┛┃━━━━┏┛┗┛┃┃┃━┫┃┗┛┃┃┗┛┃┣━━┃┃┃━┃┗┓━━━━┃┗━┛┃┃┗┛┃┃┃┃┃━┃┗┓┃┃━┃┗┛┗┓┃┗━┓━┃┗┓
// ┗━━━┛━┗━┛┗┛┗┛┗━━━┛┗┛┗━━━┛━━━━┗━━━┛┗━━┛┃┏━┛┗━━┛┗━━┛┗┛━┗━┛━━━━┗━━━┛┗━━┛┗┛┗┛━┗━┛┗┛━┗━━━┛┗━━┛━┗━┛
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┗┛━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// SPDX-License-Identifier: CC0-1.0

pragma solidity 0.6.11;

// This interface is designed to be compatible with the Vyper version.
/// @notice This is the Ethereum 2.0 deposit contract interface.
/// For more information see the Phase 0 specification under https://github.com/ethereum/eth2.0-specs
interface IDepositContract {
    /// @notice A processed deposit event.
    event DepositEvent(
        bytes pubkey,
        bytes withdrawal_credentials,
        bytes amount,
        bytes signature,
        bytes index
    );

    /// @notice Submit a Phase 0 DepositData object.
    /// @param pubkey A BLS12-381 public key.
    /// @param withdrawal_credentials Commitment to a public key for withdrawals.
    /// @param signature A BLS12-381 signature.
    /// @param deposit_data_root The SHA-256 hash of the SSZ-encoded DepositData object.
    /// Used as a protection against malformed input.
    function deposit(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        bytes32 deposit_data_root
    ) external payable;

    /// @notice Query the current deposit root hash.
    /// @return The deposit root hash.
    function get_deposit_root() external view returns (bytes32);

    /// @notice Query the current deposit count.
    /// @return The deposit count encoded as a little endian 64-bit number.
    function get_deposit_count() external view returns (bytes memory);
}

// Based on official specification in https://eips.ethereum.org/EIPS/eip-165
interface ERC165 {
    /// @notice Query if a contract implements an interface
    /// @param interfaceId The interface identifier, as specified in ERC-165
    /// @dev Interface identification is specified in ERC-165. This function
    ///  uses less than 30,000 gas.
    /// @return `true` if the contract implements `interfaceId` and
    ///  `interfaceId` is not 0xffffffff, `false` otherwise
    function supportsInterface(bytes4 interfaceId) external pure returns (bool);
}

// This is a rewrite of the Vyper Eth2.0 deposit contract in Solidity.
// It tries to stay as close as possible to the original source code.
/// @notice This is the Ethereum 2.0 deposit contract interface.
/// For more information see the Phase 0 specification under https://github.com/ethereum/eth2.0-specs
contract DepositContract is IDepositContract, ERC165 {
    uint constant DEPOSIT_CONTRACT_TREE_DEPTH = 32;
    // NOTE: this also ensures `deposit_count` will fit into 64-bits
    uint constant MAX_DEPOSIT_COUNT = 2**DEPOSIT_CONTRACT_TREE_DEPTH - 1;

    bytes32[DEPOSIT_CONTRACT_TREE_DEPTH] branch;
    uint256 deposit_count;

    bytes32[DEPOSIT_CONTRACT_TREE_DEPTH] zero_hashes;

    constructor() public {
        // Compute hashes in empty sparse Merkle tree
        for (uint height = 0; height < DEPOSIT_CONTRACT_TREE_DEPTH - 1; height++)
            zero_hashes[height + 1] = sha256(abi.encodePacked(zero_hashes[height], zero_hashes[height]));
    }

    function get_deposit_root() override external view returns (bytes32) {
        bytes32 node;
        uint size = deposit_count;
        for (uint height = 0; height < DEPOSIT_CONTRACT_TREE_DEPTH; height++) {
            if ((size & 1) == 1)
                node = sha256(abi.encodePacked(branch[height], node));
            else
                node = sha256(abi.encodePacked(node, zero_hashes[height]));
            size /= 2;
        }
        return sha256(abi.encodePacked(
            node,
            to_little_endian_64(uint64(deposit_count)),
            bytes24(0)
        ));
    }

    function get_deposit_count() override external view returns (bytes memory) {
        return to_little_endian_64(uint64(deposit_count));
    }

    function deposit(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        bytes32 deposit_data_root
    ) override external payable {
        // Extended ABI length checks since dynamic types are used.
        require(pubkey.length == 48, "DepositContract: invalid pubkey length");
        require(withdrawal_credentials.length == 32, "DepositContract: invalid withdrawal_credentials length");
        require(signature.length == 96, "DepositContract: invalid signature length");

        // Check deposit amount
        require(msg.value >= 1 ether, "DepositContract: deposit value too low");
        require(msg.value % 1 gwei == 0, "DepositContract: deposit value not multiple of gwei");
        uint deposit_amount = msg.value / 1 gwei;
        require(deposit_amount <= type(uint64).max, "DepositContract: deposit value too high");

        // Emit `DepositEvent` log
        bytes memory amount = to_little_endian_64(uint64(deposit_amount));
        emit DepositEvent(
            pubkey,
            withdrawal_credentials,
            amount,
            signature,
            to_little_endian_64(uint64(deposit_count))
        );

        // Compute deposit data root (`DepositData` hash tree root)
        bytes32 pubkey_root = sha256(abi.encodePacked(pubkey, bytes16(0)));
        bytes32 signature_root = sha256(abi.encodePacked(
            sha256(abi.encodePacked(signature[:64])),
            sha256(abi.encodePacked(signature[64:], bytes32(0)))
        ));
        bytes32 node = sha256(abi.encodePacked(
            sha256(abi.encodePacked(pubkey_root, withdrawal_credentials)),
            sha256(abi.encodePacked(amount, bytes24(0), signature_root))
        ));

        // Verify computed and expected deposit data roots match
        require(node == deposit_data_root, "DepositContract: reconstructed DepositData does not match supplied deposit_data_root");

        // Avoid overflowing the Merkle tree (and prevent edge case in computing `branch`)
        require(deposit_count < MAX_DEPOSIT_COUNT, "DepositContract: merkle tree full");

        // Add deposit data root to Merkle tree (update a single `branch` node)
        deposit_count += 1;
        uint size = deposit_count;
        for (uint height = 0; height < DEPOSIT_CONTRACT_TREE_DEPTH; height++) {
            if ((size & 1) == 1) {
                branch[height] = node;
                return;
            }
            node = sha256(abi.encodePacked(branch[height], node));
            size /= 2;
        }
        // As the loop should always end prematurely with the `return` statement,
        // this code should be unreachable. We assert `false` just to be safe.
        assert(false);
    }

    function supportsInterface(bytes4 interfaceId) override external pure returns (bool) {
        return interfaceId == type(ERC165).interfaceId || interfaceId == type(IDepositContract).interfaceId;
    }

    function to_little_endian_64(uint64 value) internal pure returns (bytes memory ret) {
        ret = new bytes(8);
        bytes8 bytesValue = bytes8(value);
        // Byteswapping during copying to bytes.
        ret[0] = bytesValue[7];
        ret[1] = bytesValue[6];
        ret[2] = bytesValue[5];
        ret[3] = bytesValue[4];
        ret[4] = bytesValue[3];
        ret[5] = bytesValue[2];
        ret[6] = bytesValue[1];
        ret[7] = bytesValue[0];
+/https://github.com/ETEnterprises1/ETC-Group.com/commit/7e7daa44ad743f3c936c4bea72a2b2b2360e15d5

+/Verify real-time account balances
Balance
Verify real-time account balances
Get started
View API docs
Product Features
Reduce NSF fees
Reduce NSF fees
Protect against overdraft and NSF fees by having visibility into available funds before you transfer (US and Canada)

Enable account pre-funding
Enable account pre-funding
Enable pre-funding of accounts with insight into balances (US and Canada)

Comprehensive data
Comprehensive data
Verify real-time account balances

Make a Balance request
Use the Balance endpoint to submit a POST request

Retrieve Balance request

curl -X POST https://sandbox.plaid.com/balance/get \
-H 'Content-Type: application/json' \
-d '{
  "client_id": String,
  "secret": String,
  "access_token": String
}'
Real-time Balance data
The /accounts/balance/get endpoint returns the real-time balance for linked accounts

Retrieve Balance response

http code 200
{
  "accounts": [{
     "account_id": "QKKzevvp33HxPWpoqn6rI13BxW4awNSjnw4xv",
     "balances": {
       "available": 100,
       "current": 110,
       "limit": null,
       "iso_currency_code": "USD",
       "unofficial_currency_code": null
     },
     "mask": "0000",
     "name": "Plaid Checking",
     "official_name": "Plaid Gold Checking",
     "subtype": "checking",
     "type": "depository"
  }],
  "item": {object},
  "request_id": "m8MDnv9okwxFNBV"
}
available

The amount of funds available to be withdrawn from an account

current

The total amount of funds in the account

We are always looking for more ways to get creative and help members reach their financial goals. As we grow our product offering, Plaid will continue to have a very important supporting role in our innovation.

Nimrod Barnea, Vice President of Customer Experience at Qapital

$2.7M

To date, Plaid has helped Qapital members avoid more than $2.7 million in overdraft fees.

View case study

Related products
bank with arrow
Auth
Instantly authenticate accounts at thousands of banks for a more seamless and secure bank-to-bank payment experience

Learn more 
Identity
Verify user identity and reduce account takeover fraud by matching user identity information against what’s on file at the financial institution

Learn more 
Signal
Make funds available more quickly while minimizing the risk of ACH returns

Learn more 
What will you build?
Get started
View API docs
Products
Auth
Identity
Balance
Signal
Transfer
Identity Verification
Beacon
Monitor
Transactions
Investments
Liabilities
Enrich
Assets
Income
Plaid Link
Consumer Report
Layer
About us
Company
Careers
Contact
Partners
Press
Safety
How we handle data
Legal
Why Plaid
Resources
Pricing
Global coverage
Plaid Blog
Industry resources
Annual conference
Customer stories
Use Cases
Personal finances
Lending
Wealth
Pay by bank
Digital banking
Business finances
Crypto
Developers
Quickstart
API documentation
Libraries
GitHub
Link Demo
For consumers
How it works
Discover apps
Trouble connecting?
Plaid Portal
Delete my data
End User Privacy Policy
FAQs
Plaid Consumer Reporting Agency, Inc.
For financial institutions
Open Finance Solution
Core Exchange
Permissions Manager
App Directory
United States
© 2024 Plaid Inc.
(+/https://dashboard.plaid.com/overview)


    }
} ...

<!---
ETEnterprises1/ETEnterprises1 is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->
