# NIZK-Fabric
Privacy-Preserving, and Auditable Transactions on Hyperledger Fabric using Pedersen Commitment and Non-Interactive Zero Knowledge Proofs.

Abstract:

The banking industry is considering adopting permissioned blockchain technology to improve security and reconcile transactions efficiently. The financial institutions are de- termined to demonstrate their compliance, but the banks are reluctant to have the ledgers transparent to the other network participants as it might leak trading strategy. In this thesis, we provide an integrated system for privacy-preserving, and auditable decentral- ized transaction system on Hyperledger Fabric with zkLedger. Through literature review, prototype design, and experimentation, the study identifies the challenges and bottle- necks in implementing the zkLedger design on Hyperledger Fabric, particularly regarding transaction security and concurrency. Two approaches are proposed as trade-offs between security and efficiency: the first provides complete security properties but requires serial transaction processing, while the second allows concurrent transactions with delayed Proof of Assets, offering increased practicality at the cost of reduced security. The research con- tributes to the understanding of auditable privacy-preserving transactions on blockchain and presents a novel approach to implementing zkLedger with enhanced concurrency, improving the overall efficiency and scalability of the system.


Instruction:

This is the Chaincode (Smart Contract) for Hyperledger Fabric. This Chaincode accepts the zkLedger transactions sent by the client applications via REST API. The Pedersen Commitment transactions with NIZK proofs shall be created locally in the client application, while this Chaincode allows Hyperledger Fabric to verify the transactions and put such transactions into the blockchain.
