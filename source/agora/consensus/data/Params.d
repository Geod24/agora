/*******************************************************************************

    The set for consensus-critical constants

    This defines the class for the consensus-critical constants. Only one
    object should exist for a single node. The `class` is `immutable`, hence
    the constants need to be set at the start of the process. The
    consensus-critical constants are the protocol-level constants, so they
    shouldn't be modified outside of test environments.

    It also exposes basic (relying only on hash / signatures) utilities
    to construct more advanced schemes, such as `makeSecret`.

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.Params;

import agora.common.Amount;
import agora.consensus.data.Block;
import agora.crypto.ECC;
import agora.crypto.Hash;
import agora.crypto.Key;

import core.time;

/// Ditto
public immutable class ConsensusParams
{
    /// The Genesis block of the chain
    public Block Genesis;

    /// How often blocks should be created
    public Duration BlockInterval;

    /// The address of commons budget
    public PublicKey CommonsBudgetAddress;

    /// Underlying data
    private ConsensusConfig data;

    mixin ROProperty!("ValidatorCycle", "validator_cycle");
    mixin ROProperty!("MaxQuorumNodes", "max_quorum_nodes");
    mixin ROProperty!("QuorumThreshold", "quorum_threshold");
    mixin ROProperty!("QuorumShuffleInterval", "quorum_shuffle_interval");
    mixin ROProperty!("TxPayloadMaxSize", "tx_payload_max_size");
    mixin ROProperty!("TxPayloadFeeFactor", "tx_payload_fee_factor");
    mixin ROProperty!("ValidatorTXFeeCut", "validator_tx_fee_cut");
    mixin ROProperty!("PayoutPeriod", "payout_period");
    mixin ROProperty!("SlashPenaltyAmount", "slash_penalty_amount");
    mixin ROProperty!("GenesisTimestamp", "genesis_timestamp");

    /***************************************************************************

        Constructor

        Params:
            genesis = Genesis block to use for this chain
            commons_budget_address = Address of the 'Commons' budget
            config = The (potentially) user-configured consensus parameters
            block_interval = How often blocks are expected to be created

    ***************************************************************************/

    public this (immutable(Block) genesis,
                 in PublicKey commons_budget_address,
                 ConsensusConfig config = ConsensusConfig.init,
                 Duration block_interval = 1.seconds)
    {
        this.Genesis = genesis;
        this.CommonsBudgetAddress = commons_budget_address,
        this.BlockInterval = block_interval;
        this.data = config;
    }

    /// Default for unittest, uses the test genesis block
    version (unittest) public this (
        uint validator_cycle = 1008, uint max_quorum_nodes = 7,
        uint quorum_threshold = 80)
    {
        const genesis_timestamp = 1609459200;  // 2021-01-01:00:00:00 GMT
        import agora.consensus.data.genesis.Test : GenesisBlock;
        import agora.utils.WellKnownKeys;
        ConsensusConfig config = {
            validator_cycle: validator_cycle,
            max_quorum_nodes: max_quorum_nodes,
            quorum_threshold: quorum_threshold,
        };
        this(GenesisBlock, CommonsBudget.address, config);
    }

    /***************************************************************************

        Expose a functionality to make predictable secrets

        In some occasions, the node needs to generate a value that has to be
        kept secret, needs not be reused (is random) and can be recovered in
        case of crash.
        As the only piece of data that is truly private to a node is
        its private key, we use this as an input to a hash function to generate
        such data. To avoid re-using the same value for different usage,
        the function accepts a 'category', which is a constant string.
        Finally, within a category, a nonce is used to allow for the same
        category to have successive values. To avoid re-using the same value,
        care should be taken to set 'nonce' properly,
        usually based on the height.

        An example usage of this method is when generating the signature noise
        used for validating. In order to make the private `r` recoverable,
        the value is generated through this function.

        Params:
            kp = KeyPair of the node to use
            category = Name of the category to which this secret belongs
            nonce = Nonce within the category for this secret

        Returns:
          The equivalent to `hash(kp, category, nonce)` reduced to a `Scalar`

    ***************************************************************************/

    public static Scalar makeSecret (in KeyPair kp, in char[] category, ulong nonce)
        @safe nothrow @nogc
    {
        assert(kp.secret !is KeyPair.init.secret);
        assert(category.length);

        return Scalar(hashMulti(kp.secret, category, nonce));
    }
}

/// Ditto
public struct ConsensusConfig
{
    public ulong genesis_timestamp = 1609459200; // 2021-01-01:00:00:00 GMT

    /// The cycle length for a validator
    public uint validator_cycle = 1008;

    /// Maximum number of nodes to include in an autogenerated quorum set
    public uint max_quorum_nodes = 7;

    /// Threshold to use in the autogenerated quorum. Between 1 and 100.
    public uint quorum_threshold = 80;

    /// The maximum number of blocks before a quorum shuffle takes place.
    /// Note that a shuffle may occur before the cycle ends if the active
    /// validator set changes (new enrollments, expired enrollments..)
    public uint quorum_shuffle_interval = 30;

    /// The maximum size of data payload
    public uint tx_payload_max_size = 1024;

    /// The factor to calculate for the fee of data payload
    public uint tx_payload_fee_factor = 200;

    /// The share that Validators would get out of the transction fees (Out of 100)
    /// The rest would go to the Commons Budget
    public ubyte validator_tx_fee_cut = 70;

    /// How frequent the payments to Validators will be in blocks
    public uint payout_period = 144;

    /// The amount of a penalty for slashed validators
    public Amount slash_penalty_amount = 10_000.coins;
}

/// Inserts properties functions aliasing `ConsensusConfig`
private mixin template ROProperty (string to, string from)
{
    mixin (
        "public typeof(this.data.", from, ") ", to,
        " () @safe pure nothrow @nogc { return this.data.", from, "; }");
}
