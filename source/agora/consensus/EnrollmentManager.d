/*******************************************************************************

    Manages this node's Enrollment, the `ValidatorSet`, and `EnrollmentPool`

    This class currently has 3 responsibilities:
    - It's a bridge to the `ValidatorSet`, where the list of currently active
      validators is stored;
    - It stores `Enrollment`s that are not yet part of the validator set;
    - Most importantly, if this node is a validator, it manages this node's
      enrollement data, including pre-images.

    The consensus protocol requires each validator to commit to a hash and
    to reveal a pre-image for the next `ValidatorCycle` blocks (currently 1008).
    That newly-revealed hash is used as a basis for various operations,
    such as deriving the new signature noise (in order to make signature
    aggregation possible) and both as a source of randomness for the node
    itself (e.g. for the quorum balancing) and as part of the network
    randomness function, when aggregated with other node's pre-images.
    As a result, revealing the pre-image in time is absolutely critical and
    not doing so will lead to penalties.

    In order to ensure that we will never lose the ability to reveal
    pre-images, this implementation uses a reproducible scheme:
    on the first run, we generate a "cycle seed" which is derived from a hash
    of the private key, a constant string, and a nonce, starting from 0.
    Using this cycle seed, we generate a large amount of pre-images
    (currently enough for 100 enrollments). Then out of this range of
    [0 .. 100_800] pre-images, we reveal the last 1008 (`ValidatorCycle`),
    or in D terms `[$ - 1008 .. $]`.
    When the first enrollment runs out, we reveal the next last 1008,
    or in D terms `[$ - 2016 .. $ - 1008]`.
    When the cycle is expired, we re-generate a new cycle seed after
    increasing the nonce.
    By using this scheme, a node that would start from scratch with
    an already-enrolled key will be able to recover its nonce and
    cycle index by scanning the blockchain, and resume validating.

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.EnrollmentManager;

import agora.common.crypto.ECC;
import agora.common.crypto.Key;
import agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.common.ManagedDatabase;
import agora.common.Serializer;
import agora.common.Types;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Params;
import agora.consensus.data.PreImageInfo;
import agora.consensus.EnrollmentPool;
import agora.consensus.PreImage;
import agora.consensus.validation;
import agora.consensus.state.ValidatorSet;
import agora.consensus.state.UTXOSet;
import agora.stats.Utils;
import agora.stats.Validator;
import agora.utils.Log;
version (unittest) import agora.utils.Test;

import d2sqlite3.library;
import d2sqlite3.results;
import d2sqlite3.sqlite3;

import std.algorithm;
import std.file;
import std.path;
import std.string;

mixin AddLogger!();

/*******************************************************************************

    Handle enrollment data and manage the validators set

*******************************************************************************/

public class EnrollmentManager
{
    /// SQLite db instance
    private ManagedDatabase db;

    /// Node's key pair
    private Pair key_pair;

    /// Key used for enrollment which is actually an UTXO hash
    private Hash enroll_key;

    /// The period for revealing a preimage
    /// It is an hour interval if a block is made in every 10 minutes
    public static immutable uint PreimageRevealPeriod = 6;

    /// Validator set managing validators' information such as Enrollment object
    /// enrolled height, and preimages.
    private ValidatorSet validator_set;

    /// Enrollment pool managing enrollments waiting to be a validator
    private EnrollmentPool enroll_pool;

    /// Ditto
    private PreImageCycle cycle;

    /// Parameters for consensus-critical constants
    private immutable(ConsensusParams) params;

    /// Validator count stats
    private ValidatorCountStats validator_count_stats;

    /// Validator preimages stats
    private ValidatorPreimagesStats validator_preimages_stats;

    /***************************************************************************

        Constructor

        Params:
            db_path = path to the database file, or in-memory storage if
                        :memory: was passed
            key_pair = the keypair of the owner node
            params = the consensus-critical constants

    ***************************************************************************/

    public this (string db_path, KeyPair key_pair,
        immutable(ConsensusParams) params)
    {
        assert(params !is null);
        this.params = params;
        this.cycle = PreImageCycle(
            /* nounce: */ 0,
            /* index:  */ 0,
            /* seeds:  */ PreImageCache(PreImageCycle.NumberOfCycles,
                this.params.ValidatorCycle),
            // Since those pre-images might be accessed often,
            // use an interval of 1 (no interval)
            /* preimages: */ PreImageCache(this.params.ValidatorCycle, 1)
        );

        this.db = new ManagedDatabase(db_path);
        this.validator_set = new ValidatorSet(this.db, params);
        this.enroll_pool = new EnrollmentPool(this.db);


        // create the table for enrollment data for a node itself
        this.db.execute("CREATE TABLE IF NOT EXISTS node_enroll_data " ~
            "(key CHAR(128) PRIMARY KEY, val BLOB NOT NULL)");

        // create Pair object from KeyPair object
        this.key_pair = Pair.fromScalar(secretKeyToCurveScalar(key_pair.secret));

        // load enrollment key
        this.enroll_key = this.getEnrollmentKey();

        // load the count of 'populate' of `PreImageCycle`
        const uint populate_count = this.getCycleIndex();
        foreach (_; 0 .. populate_count)
            this.cycle.populate(this.key_pair.v, true);

        Utils.getCollectorRegistry().addCollector(&this.collectValidatorStats);
    }

    /***************************************************************************

        In validatorSet DB, return the enrolled block height.

        Params:
            enroll_hash = key for an enrollment block height

        Returns:
            the enrolled block height, or `ulong.max` if no matching key exists

    ***************************************************************************/

    public Height getEnrolledHeight (const ref Hash enroll_hash)
        @trusted nothrow
    {
        return this.validator_set.getEnrolledHeight(enroll_hash);
    }

    /***************************************************************************

        Add a enrollment data to the enrollment pool

        Params:
            enroll = the enrollment data to add
            block_height = current block height
            finder = the delegate to find UTXOs with

        Returns:
            true if the enrollment data has been added to the enrollment pool

    ***************************************************************************/

    public bool addEnrollment (const ref Enrollment enroll, Height block_height,
        scope UTXOFinder finder) @safe nothrow
    {
        auto enrolled_height = this.getEnrolledHeight(enroll.utxo_key);

        // The first height at which the enrollment can be enrolled.
        ulong avail_height;

        if (enrolled_height == ulong.max)
            avail_height = block_height + 1;
        else
            avail_height = enrolled_height + this.params.ValidatorCycle;

        return this.enroll_pool.add(enroll, Height(avail_height), finder);
    }

    /***************************************************************************

        Get the unregistered enrollments that can be validator in the next
        block based on the current block height.

        Params:
            enrolls = will contain the unregistered enrollments data if found
            height = current block height

        Returns:
            The unregistered enrollments data

    ***************************************************************************/

    public Enrollment[] getEnrollments (ref Enrollment[] enrolls, Height height)
        @trusted nothrow
    {
        enrolls.length = 0;
        assumeSafeAppend(enrolls);

        static Enrollment[] pool_enrolls;
        this.enroll_pool.getEnrollments(pool_enrolls, Height(height + 1));
        foreach (enroll; pool_enrolls)
        {
            const enroll_height = this.getEnrolledHeight(enroll.utxo_key);
            const avail_height =
                this.enroll_pool.getAvailableHeight(enroll.utxo_key);
            assert(avail_height != Height(0));
            if (enroll_height == ulong.max ||
                (avail_height >= enroll_height &&
                    height >= enroll_height + this.params.ValidatorCycle - 1))
            {
                enrolls ~= enroll;
            }
        }
        return enrolls;
    }

    /***************************************************************************

        Add a validator to the validator set or update the enrolled height.

        This also gets and stores the information about this node's enrollment
        information which could be lost in abnormal situations.

        Params:
            enroll = Enrollment structure to add to the validator set
            block_height = enrolled blockheight
            finder = the delegate to find UTXOs with
            self_utxos = the UTXOs belonging to this node

        Returns:
            A string describing the error, or `null` on success

    ***************************************************************************/

    public string addValidator (const ref Enrollment enroll,
        Height block_height, scope UTXOFinder finder,
        const UTXO[Hash] self_utxos) @safe nothrow
    {
        this.enroll_pool.remove(enroll.utxo_key);

        if (auto r = this.validator_set.add(block_height, finder, enroll))
            return r;

        if (enroll.utxo_key in self_utxos)
        {
            this.setEnrollmentKey(enroll.utxo_key);

            // consume pre-images
            this.cycle.populate(this.key_pair.v, true);

            // save the count of 'populate' of `PreImageCycle`
            this.setCycleIndex(
                (this.cycle.nonce * this.cycle.NumberOfCycles) + this.cycle.index);
        }

        return null;
    }

    /***************************************************************************

        Build an `Enrollment` using `buildEnrollment`, stores and returns it

        Params:
            utxo = The hash of the frozen UTXO used as a stake.
                   It must be owned by the private key this validator controls
                   (`key_pair` argument to constructor).

        Returns:
            The `Enrollment` created by `buildEnrollment`

    ***************************************************************************/

    public Enrollment createEnrollment (Hash utxo) @safe nothrow
    {
        // K, frozen UTXO hash
        this.enroll_key = utxo;

        // X, final seed data and preimages of hashes
        const seed = this.cycle.populate(this.key_pair.v, false);
        const enroll = makeEnrollment(
            this.key_pair, utxo, this.params.ValidatorCycle,
            seed, this.cycle.index);

        return enroll;
    }

    /***************************************************************************

        Build enrollment data for an arbitrary utxo + key combination

        This static function builds a valid, real-world 'enrollment' for any
        private key + utxo combination.  It can be used to generate realistic
        test data or specialized usage, e.g. by tools.

        To avoid code duplication and overhead, this function has two overload:
        the one accepting an offset will generate a new `PreImageCache`,
        which is quite expensive, and retrieve the hash to use based on the
        offset (defaults to `0`), and then forwards to the second overload
        that accepts a `Hash` and thus does not incur the cost of re-generating
        the pre-images.

        Params:
            key  = `KeyPair` that controls the `utxo`
            utxo = `Hash` of a frozen UTXO value that can be used for enrollment
            cycle_length = The cycle length to use (see `ConsensusParams`)
            seed = Random seed to use
            offset = The number of times this private key has enrolled before.
                     If `seed` is provided, this parameter is non-optional.

        Returns:
            An `Enrollment` refencing `utxo` signed with `key`

    ***************************************************************************/

    public static Enrollment makeEnrollment (
        Pair key, const ref Hash utxo, uint cycle_length, Hash seed, ulong offset)
        @safe nothrow @nogc
    {
        Enrollment result = {
            utxo_key: utxo,
            cycle_length: cycle_length,
            random_seed: seed,
        };

        // Generate signature noise
        const Pair noise = Pair.fromScalar(Scalar(hashMulti(key.v, "consensus.signature.noise", offset)));

        // We're done, sign & return
        result.enroll_sig = sign(key, noise, result);
        return result;
    }

    /// Ditto
    version (unittest) public static Enrollment makeEnrollment (
        KeyPair key, const Hash utxo, uint cycle_length, uint offset = 0)
        @trusted nothrow
    {
        // Convert stellar-type keypair to curve scalars
        const kp = Pair.fromScalar(secretKeyToCurveScalar(key.secret));

        // Generate the random seed to use
        auto cache = PreImageCache(PreImageCycle.NumberOfCycles, cycle_length);
        assert(offset < cache.length);
        cache.reset(hashMulti(kp.v, "consensus.preimages", offset));

        return makeEnrollment(kp, utxo, cycle_length, cache[$ - offset - 1], offset);
    }

    /***************************************************************************

        Get all the enrolled validator's UTXO keys.

        Params:
            utxo_keys = will contain the set of UTXO keys

        Returns:
            Return true if there was no error in getting the UTXO keys

    ***************************************************************************/

    public bool getEnrolledUTXOs (out Hash[] keys) @safe nothrow
    {
        return this.validator_set.getEnrolledUTXOs(keys);
    }

    /***************************************************************************

        Get the number of active validators.

        Client code can use this between clearExpiredValidators() calls to
        determine if the number of validators has changed, and act accordingly.

        Returns:
            the number of active validators

    ***************************************************************************/

    public size_t validatorCount () @safe
    {
        return this.validator_set.count();
    }

    /***************************************************************************

        Check if an enrollment is a valid candidate for the proposed height

        Params:
            enroll = The enrollment of the target to be checked
            height = the height of proposed block
            findUTXO = delegate to find the referenced unspent UTXOs with

        Returns:
            `null` if the enrollment can be a validator at the proposed height,
            otherwise a string explaining the reason it is invalid.

    ***************************************************************************/

    public string isInvalidCandidateReason (const ref Enrollment enroll,
        Height height, scope UTXOFinder findUTXO) @safe nothrow
    {
        if (auto fail_reason = enroll.isInvalidReason(findUTXO))
            return fail_reason;

        const enrolled = this.validator_set.getEnrolledHeight(enroll.utxo_key);
        if (enrolled != ulong.max &&
            height < (enrolled + this.params.ValidatorCycle))
        {
            return "Enrollment: Duplicated enrollments";
        }

        return null;
    }

    /***************************************************************************

        Clear up expired validators whose cycle for a validator ends

        The enrollment manager clears up expired validators from the set based
        on the block height. It also clears up the enrollment of this node.

        Params:
            block_height = current block height

    ***************************************************************************/

    public void clearExpiredValidators (Height block_height) @safe nothrow
    {
        // clear up the enrollment of a node if the validator cycle of the node
        // ends at the `block_height`
        const enrolled = this.validator_set.getEnrolledHeight(this.enroll_key);
        if (block_height >= enrolled + params.ValidatorCycle)
            this.resetNodeEnrollment();

        this.validator_set.clearExpiredValidators(block_height);
    }

    /***************************************************************************

        Get a pre-image for revelation

        Params:
            preimage = will contain the PreImageInfo if exists
            height = current block height

        Returns:
            true if the pre-image exists

    ***************************************************************************/

    public bool getNextPreimage (out PreImageInfo preimage, Height height) @safe
    {
        uint next_dist = getRevealDistance(height);
        if (next_dist >= this.params.ValidatorCycle)
            return false;

        preimage.enroll_key = this.enroll_key;
        preimage.distance = cast(ushort)next_dist;
        preimage.hash = this.cycle.preimages[$ - next_dist - 1];
        return true;
    }

    /***************************************************************************

        Check if a pre-image exists

        Params:
            enroll_key = The key for the enrollment in which the pre-image is
                contained.
            distance = The distance of the preimage

        Returns:
            true if the pre-image exists

    ***************************************************************************/

    public bool hasPreimage (const ref Hash enroll_key, ushort distance) @safe
        nothrow
    {
        return this.validator_set.hasPreimage(enroll_key, distance);
    }

    /***************************************************************************

        Generate the random seed reduced from the preimages for the provided
        block height.

        Params:
            keys = the keys to look up (must be sorted)
            height = the desired block height to look up the images for

        Returns:
            the random seed

    ***************************************************************************/

    public Hash getRandomSeed (in Hash[] keys, in Height height) @safe nothrow
    in
    {
        assert(keys.length != 0);
        assert(keys.isStrictlyMonotonic!((a, b) => a < b));
    }
    do
    {
        Hash rand_seed;
        foreach (const ref key; keys)
        {
            const preimage = this.validator_set.getPreimageAt(key, height);
            // this should not happen. validators which didn't reveal the
            // preimage should not be in the active validator set 'keys'.
            if (preimage == PreImageInfo.init)
            {
                log.fatal("No preimage at height {} for validator key {}", height.value, key);
                assert(0, "No preimage at expected height");
            }
            rand_seed = hashMulti(rand_seed, preimage);
        }

        return rand_seed;
    }

    /***************************************************************************

        Get validator's pre-image from the validator set.

        Params:
            enroll_key = The key for the enrollment in which the pre-image is
                contained.

        Returns:
            the PreImageInfo of the enrolled key if it exists,
            otherwise PreImageInfo.init

    ***************************************************************************/

    public PreImageInfo getValidatorPreimage (const ref Hash enroll_key)
        @trusted nothrow
    {
        return this.validator_set.getPreimage(enroll_key);
    }

    /***************************************************************************

        Add a pre-image information to a validator data

        Params:
            preimage = the pre-image information to add

        Returns:
            true if the pre-image information has been added to the validator

    ***************************************************************************/

    public bool addPreimage (const ref PreImageInfo preimage) @safe nothrow
    {
        return this.validator_set.addPreimage(preimage);
    }

    /***************************************************************************

        Restore validators' information from block

        Params:
            last_height = the latest block height
            block = the block to update the validator set with
            finder = the delegate to find UTXOs with
            self_utxos = the UTXOs belonging to this node

    ***************************************************************************/

    public void restoreValidators (Height last_height, const ref Block block,
        scope UTXOFinder finder, const ref UTXO[Hash] self_utxos)
        @safe nothrow
    {
        assert(last_height >= block.header.height);
        if (last_height - block.header.height < this.params.ValidatorCycle)
        {
            foreach (const ref enroll; block.header.enrollments)
            {
                this.addValidator(enroll, block.header.height, finder,
                    self_utxos);
            }
        }
    }

    /***************************************************************************

        Get the public key of node that is used for a enrollment

        Returns:
            Public key of a node

    ***************************************************************************/

    public PublicKey getEnrollmentPublicKey () @safe nothrow
    {
        return PublicKey(this.key_pair.V[]);
    }

    /// Returns: true if this validator is currently enrolled
    public bool isEnrolled (scope UTXOFinder finder) nothrow @safe
    {
        return this.getEnrolledUTXO(finder) != Hash.init;
    }

    /// Returns: The UTXO hash that this Validator is enrolled with or Hash.init if not enrolled
    public Hash getEnrolledUTXO (scope UTXOFinder finder) nothrow @safe
    {
        Hash[] utxo_keys;
        assert(this.validator_set.getEnrolledUTXOs(utxo_keys));

        const PublicKey key = this.getEnrollmentPublicKey();
        foreach (utxo_key; utxo_keys)
        {
            UTXO value;
            if (!finder(utxo_key, value))
                assert(0, "UTXO for validator not found!");  // should never happen

            if (value.output.address == key)
                return utxo_key;
        }

        return Hash.init;
    }

    /***************************************************************************

        Get the key for the enrollment for this node

        If this node is not enrolled yet, the result will be empty. And if
        the database operation fails, this displays a log message and also
        returns `Hash.init`. Database errors mean that this node is not in
        a normal situation overall.

        Returns:
            the key for the enrollment

    ***************************************************************************/

    public Hash getEnrollmentKey () @trusted nothrow
    {
        try
        {
            auto results = this.db.execute("SELECT val FROM node_enroll_data " ~
                "WHERE key = ?", "enroll_key");

            if (!results.empty)
                return results.oneValue!(ubyte[]).deserializeFull!(Hash);
        }
        catch (Exception ex)
        {
            log.warn("ManagedDatabase operation error: {}", ex.msg);
        }

        return Hash.init;
    }

    /***************************************************************************

        Set the key for the enrollment for this node

        If saving an enrollment key fails, this displays a log messages and just
        returns. The `enroll_key` stores the value anyway and it can be restored
        from the catch-up process later. If the database or serialization
        operation fails, it means that node is not in normal situation overall.

        Params:
            enroll_key = the key for the enrollment

    ***************************************************************************/

    private void setEnrollmentKey (const ref Hash enroll_key) @trusted nothrow
    {
        this.enroll_key = enroll_key;

        static ubyte[] buffer;
        try
        {
            serializeToBuffer(this.enroll_key, buffer);
        }
        catch (Exception ex)
        {
            log.warn("Serialization error of enroll_key {}", ex.msg);
            return;
        }

        try
        {
            this.db.execute("REPLACE into node_enroll_data " ~
                "(key, val) VALUES (?, ?)", "enroll_key", buffer);
        }
        catch (Exception ex)
        {
            log.warn("ManagedDatabase operation error {}", ex.msg);
        }
    }

    /***************************************************************************

        Collect all validator & preimage stats into the collector

        Params:
            collector = the Collector to collect the stats into

    ***************************************************************************/

    private void collectValidatorStats (Collector collector)
    {
        validator_count_stats.setMetricTo!"agora_validators_gauge"(validator_set.count());
        Hash[] keys;
        if (getEnrolledUTXOs(keys))
            foreach (const ref key; keys)
                validator_preimages_stats.setMetricTo!"agora_preimages_gauge"(
                    validator_set.getPreimage(key).distance, key.toString());

        foreach (stat; validator_count_stats.getStats())
            collector.collect(stat.value);

        foreach (stat; validator_preimages_stats.getStats())
            collector.collect(stat.value, stat.label);
    }

    /***************************************************************************

        Get the cycle index of `PreImageCycle`

        Returns:
            the cycle index

    ***************************************************************************/

    private uint getCycleIndex () @trusted nothrow
    {
        try
        {
            auto results = this.db.execute(
                `SELECT val FROM node_enroll_data WHERE key = 'cycle_index'`);
            if (results.empty)
                return 0;

            return results.oneValue!(uint);
        }
        catch (Exception ex)
        {
            log.error("ManagedDatabase operation error {}", ex);
            return 0;
        }
    }

    /***************************************************************************

        Set the cycle index of `PreImageCycle`

        Params:
            cycle_index = the cycle index

    ***************************************************************************/

    private void setCycleIndex (uint cycle_index) @trusted nothrow
    {
        try
        {
            this.db.execute("REPLACE into node_enroll_data " ~
                "(key, val) VALUES (?, ?)", "cycle_index", cycle_index);
        }
        catch (Exception ex)
        {
            log.error("ManagedDatabase operation error {}", ex);
        }
    }

    /***************************************************************************

        Update the distance of the pre-image that will be revealed next time

        Params:
            height = block height to check

        Returns:
            the distance, or unit.max if this node is not enrolled.

    ***************************************************************************/

    private uint getRevealDistance (Height height) @safe nothrow
    {
        const enrolled = this.validator_set.getEnrolledHeight(this.enroll_key);
        if (enrolled == ulong.max)
            return uint.max;

        assert(height >= enrolled);
        auto diff = cast(uint)(height - enrolled);
        auto dist = min(diff + PreimageRevealPeriod,
            this.params.ValidatorCycle - 1);
        return dist;
    }

    /***************************************************************************

        Reset all the information about an enrollment of this node

    ***************************************************************************/

    private void resetNodeEnrollment () @safe nothrow
    {
        this.enroll_key = Hash.init;
    }

    /***************************************************************************

        Gets the number of active validators at the block height.

        `block_height` is the height of the newly created block.
        If the active validators are less than the specified value,
        new blocks cannot be created.

        Params:
            block_height = the height of proposed block

        Returns:
            Returns the number of active validators when the block height is
            `block_height`.
            Returns 0 in case of error.

    ***************************************************************************/

    public ulong getValidatorCount (Height block_height) @safe nothrow
    {
        return this.validator_set.getValidatorCount(block_height);
    }

    /***************************************************************************

        Get the enrollment with the key

        Params:
            enroll_hash = key for the enrollment which has the frozen UTXO

        Returns:
            Return an `Enrollment` if the enrollment is found, otherwise
                `Enrollment.init`

    ***************************************************************************/

    public Enrollment getEnrollment (const ref Hash enroll_hash) @trusted
    {
        return this.enroll_pool.getEnrollment(enroll_hash);
    }

    /***************************************************************************

        Remove the enrollment from the enrollment pool

        Params:
            enroll_hash = key for the enrollment to remove

    ***************************************************************************/

    public void removeEnrollment (const ref Hash enroll_hash) @trusted
    {
        this.enroll_pool.remove(enroll_hash);
    }

    /***************************************************************************

        Remove all validators from the validator set

    ***************************************************************************/

    public void removeAllValidators () @trusted
    {
        this.validator_set.removeAll();
    }
}

/// tests for member functions of EnrollmentManager
unittest
{
    import agora.consensus.data.Transaction;
    import std.algorithm;

    scope utxo_set = new TestUTXOSet;

    auto gen_key_pair = WK.Keys.Genesis;
    KeyPair key_pair = KeyPair.random();

    genesisSpendable().map!(txb => txb.refund(key_pair.address).sign(TxType.Freeze))
        .each!(tx => utxo_set.put(tx));

    // create an EnrollmentManager object
    auto man = new EnrollmentManager(":memory:", key_pair,
        new immutable(ConsensusParams)());
    auto utxos = utxo_set.storage;
    Hash[] utxo_hashes = utxo_set.keys;

    // check the return value of `getEnrollmentPublicKey`
    assert(key_pair.address == man.getEnrollmentPublicKey());

    // create and add the first Enrollment object
    auto utxo_hash = utxo_hashes[0];

    // The UTXO belongs to key_pair but we sign with genesis key pair
    Enrollment fail_enroll =
        EnrollmentManager.makeEnrollment(gen_key_pair, utxo_hash, 1008);

    auto enroll = man.createEnrollment(utxo_hash);
    assert(!man.addEnrollment(fail_enroll, Height(1), utxo_set.getUTXOFinder()));
    assert(man.addEnrollment(enroll, Height(1), &utxo_set.peekUTXO));
    assert(man.enroll_pool.count() == 1);
    assert(!man.addEnrollment(enroll, Height(1), utxo_set.getUTXOFinder()));

    // create and add the second Enrollment object
    auto utxo_hash2 = utxo_hashes[1];
    auto enroll2 = man.createEnrollment(utxo_hash2);
    assert(man.addEnrollment(enroll2, Height(1), utxo_set.getUTXOFinder()));
    assert(man.enroll_pool.count() == 2);

    auto utxo_hash3 = utxo_hashes[2];
    auto enroll3 = man.createEnrollment(utxo_hash3);
    assert(man.addEnrollment(enroll3, Height(1), utxo_set.getUTXOFinder()));
    assert(man.enroll_pool.count() == 3);

    Enrollment[] enrolls;
    man.getEnrollments(enrolls, Height(1));
    assert(enrolls.length == 3);
    assert(enrolls.isStrictlyMonotonic!("a.utxo_key < b.utxo_key"));

    // get a stored Enrollment object
    Enrollment stored_enroll;
    assert((stored_enroll = man.getEnrollment(utxo_hash2)) !=
        Enrollment.init);
    assert(stored_enroll == enroll2);

    // remove an Enrollment object
    man.removeEnrollment(utxo_hash2);
    assert(man.enroll_pool.count() == 2);

    // test for getEnrollment with removed enrollment
    assert(man.getEnrollment(utxo_hash2) == Enrollment.init);

    // test for enrollment block height update
    assert(man.getEnrolledHeight(utxo_hash) == ulong.max);
    assert(man.addValidator(enroll, Height(9), &utxo_set.peekUTXO, utxos) is null);
    assert(man.getEnrolledHeight(enroll.utxo_key) == 9);
    assert(man.addValidator(enroll, Height(9), utxo_set.getUTXOFinder(), utxos) !is null);
    assert(man.getEnrolledHeight(enroll2.utxo_key) == ulong.max);
    man.getEnrollments(enrolls, Height(9));
    assert(enrolls.length == 1);
    // One Enrollment was moved to validator set
    assert(man.validator_set.count() == 1);
    assert(man.enroll_pool.count() == 1);

    man.removeEnrollment(utxo_hash);
    man.removeEnrollment(utxo_hash2);
    man.removeEnrollment(utxo_hash3);
    assert(man.getEnrollments(enrolls, Height(9)).length == 0);

    Enrollment[] ordered_enrollments;
    ordered_enrollments ~= enroll;
    ordered_enrollments ~= enroll2;
    ordered_enrollments ~= enroll3;
    // Reverse ordering
    ordered_enrollments.sort!("a.utxo_key > b.utxo_key");
    foreach (ordered_enroll; ordered_enrollments)
        assert(man.addEnrollment(ordered_enroll, Height(10),
            &utxo_set.peekUTXO));
    man.getEnrollments(enrolls, Height(man.params.ValidatorCycle + 8));
    assert(enrolls.length == 3);
    assert(enrolls.isStrictlyMonotonic!("a.utxo_key < b.utxo_key"));

    // clear up all validators
    man.clearExpiredValidators(Height(1018));

    // A validation is enrolled at the height of 10.
    PreImageInfo preimage;
    enroll = man.createEnrollment(utxo_hash);
    assert(man.addValidator(enroll, Height(10), &utxo_set.peekUTXO, utxos) is null);
    assert(man.getNextPreimage(preimage, Height(10)));
    assert(preimage.hash ==
        man.cycle.preimages[$ - 1 - man.PreimageRevealPeriod]);

    // test for getting validators' UTXO keys
    Hash[] keys;

    // validator A with the `utxo_hash` and the enrolled height of 10.
    // validator B with the 'utxo_hash2' and the enrolled height of 11.
    // validator C with the 'utxo_hash3' and no enrolled height.
    assert(man.addValidator(enroll2, Height(11), &utxo_set.peekUTXO, utxos) is null);
    man.clearExpiredValidators(Height(11));
    assert(man.validatorCount() == 2);
    assert(man.getEnrolledUTXOs(keys));
    assert(keys.length == 2);

    // set an enrolled height for validator C
    // set the block height to 1019, which means validator B is expired.
    // there is only one validator in the middle of 1020th block being made.
    assert(man.addValidator(enroll3, Height(1019), &utxo_set.peekUTXO, utxos) is null);
    man.clearExpiredValidators(Height(1019));
    assert(man.validatorCount() == 1);
    assert(man.getEnrolledUTXOs(keys));
    assert(keys.length == 1);
    assert(keys[0] == enroll3.utxo_key);

    // check the cycle count for enrollment
    assert(man.getCycleIndex() == 4);
}

/// Test for adding and getting pre-images
unittest
{
    import agora.consensus.data.Transaction;

    scope utxo_set = new TestUTXOSet;
    KeyPair key_pair = KeyPair.random();

    genesisSpendable().map!(txb => txb.refund(key_pair.address).sign(TxType.Freeze))
        .each!(tx => utxo_set.put(tx));
    UTXO[Hash] utxos = utxo_set.storage;

    auto man = new EnrollmentManager(":memory:", key_pair,
        new immutable(ConsensusParams)());
    Hash[] utxo_hashes = utxo_set.keys;

    auto utxo_hash = utxo_hashes[0];
    auto enroll = man.createEnrollment(utxo_hash);
    assert(man.addEnrollment(enroll, Height(1), utxo_set.getUTXOFinder()));

    assert(man.params.ValidatorCycle - 101 == 907); // Sanity check
    assert(man.getValidatorPreimage(utxo_hash) == PreImageInfo.init);
    assert(man.addValidator(enroll, Height(2), &utxo_set.peekUTXO, utxos) is null);
    auto preimage = PreImageInfo(utxo_hash, man.cycle.preimages[100], 907);
    assert(man.addPreimage(preimage));
    assert(man.getValidatorPreimage(utxo_hash) == preimage);
}

/// Test `PreImageCycle` consistency between seeds and preimages
unittest
{
    auto params = new immutable(ConsensusParams)();

    // Note: This was copied from `EnrollmentManager` constructor and should
    // be kept in sync with it
    auto cycle = PreImageCycle(
        /* nounce: */ 0,
        /* index:  */ 0,
        /* seeds:  */ PreImageCache(PreImageCycle.NumberOfCycles,
            params.ValidatorCycle),
        /* preimages: */ PreImageCache(params.ValidatorCycle, 1)
    );

    auto secret = Scalar.random();
    Scalar fake_secret; // Used whenever `secret` *shouldn't* be used
    foreach (uint cycleGroupCount; 0 .. 10)
    {
        foreach (outerIndex; 1 .. PreImageCycle.NumberOfCycles + 1)
        {
            // Sanity check #1
            assert(cycleGroupCount == cycle.nonce);
            assert(outerIndex - 1  == cycle.index);
            // Only provide `secret` on the first iteration
            const commitment =
                cycle.populate(outerIndex == 1 ? secret : fake_secret, true);
            const lastInCycle = outerIndex == PreImageCycle.NumberOfCycles;
            // Sanity check #2
            assert(cycleGroupCount + lastInCycle == cycle.nonce);
            if (lastInCycle)
                assert(0                         == cycle.index);
            else
                assert(outerIndex == cycle.index);
            // The commitment (last+1 in the cache, first to be revealed)
            // is the final pre-image revealed by the previous enrollment
            // (preimages[0])
            immutable SeedIndex = cycle.seeds.length
                - outerIndex * params.ValidatorCycle;
            assert(cycle.seeds.byStride[$ - outerIndex] == cycle.preimages[0]);
        }
    }

    // This check is quite expensive: 45s when it was written,
    // which doubled the total runtime of a `dub test` cycle.
    // It is versioned out now, but can be enabled for paranoid testing
    version (none)
    {
        // Reset the cycle and test that *all* values in `seeds` are represented
        // in `preimages`
        cycle.nonce = 0;
        cycle.index = 0;
        foreach (size_t cycleCount; 0 .. 5)
        {
            size_t seedIndex = cycle.seeds.length - 1;
            while (true)
            {
                const Index = seedIndex % Enrollment.ValidatorCycle;
                if (Index == (Enrollment.ValidatorCycle - 1))
                    cycle.populate(seedIndex == cycle.seeds.length ? secret :fake_secret);
                assert(cycle.seeds[seedIndex] == cycle.preimages[Index]);
                if (seedIndex == 0) break;
                seedIndex--;
            }
        }
    }
}

/// tests for `EnrollmentManager.getValidatorCount
unittest
{
    import agora.consensus.data.Transaction;

    scope utxo_set = new TestUTXOSet;

    KeyPair key_pair = KeyPair.random();

    genesisSpendable().map!(txb => txb.refund(key_pair.address).sign(TxType.Freeze))
        .each!(tx => utxo_set.put(tx));
    UTXO[Hash] utxos = utxo_set.storage;

    // create an EnrollmentManager object
    auto man = new EnrollmentManager(":memory:", key_pair,
        new immutable(ConsensusParams)());
    Hash[] utxo_hashes = utxo_set.keys;

    Height block_height = Height(2);

    // create and add the first Enrollment object
    auto utxo_hash1 = utxo_hashes[0];
    auto enrollment = man.createEnrollment(utxo_hash1);
    assert(man.addEnrollment(enrollment, block_height, utxo_set.getUTXOFinder()));
    assert(man.getValidatorCount(block_height) == 0);  // not active yet

    man.clearExpiredValidators(block_height);
    assert(man.addValidator(enrollment, block_height, &utxo_set.peekUTXO, utxos) is null);
    assert(man.getValidatorCount(block_height) == 1);  // updated

    block_height = 3;

    // create and add the second Enrollment object
    auto utxo_hash2 = utxo_hashes[1];
    enrollment = man.createEnrollment(utxo_hash2);
    assert(man.addEnrollment(enrollment, block_height, utxo_set.getUTXOFinder()));
    assert(man.getValidatorCount(block_height) == 1);  // not active yet

    man.clearExpiredValidators(block_height);
    assert(man.addValidator(enrollment, block_height, &utxo_set.peekUTXO, utxos) is null);
    assert(man.getValidatorCount(block_height) == 2);  // updated

    block_height = 4;

    // create and add the third Enrollment object
    auto utxo_hash3 = utxo_hashes[2];
    enrollment = man.createEnrollment(utxo_hash3);
    assert(man.addEnrollment(enrollment, block_height, utxo_set.getUTXOFinder()));
    assert(man.getValidatorCount(block_height) == 2);  // not active yet

    man.clearExpiredValidators(block_height);
    assert(man.addValidator(enrollment, block_height, &utxo_set.peekUTXO, utxos) is null);
    assert(man.getValidatorCount(block_height) == 3);  // updated

    block_height = 5;    // valid block height : 0 <= H < 1008
    man.clearExpiredValidators(block_height);
    assert(man.getValidatorCount(block_height) == 3);  // not cleared yet

    block_height = 1009; // valid block height : 2 <= H < 1010
    man.clearExpiredValidators(block_height);
    assert(man.getValidatorCount(block_height) == 3);

    block_height = 1010; // valid block height : 3 <= H < 1011
    man.clearExpiredValidators(block_height);
    assert(man.getValidatorCount(block_height) == 2);

    block_height = 1011; // valid block height : 4 <= H < 1012
    man.clearExpiredValidators(block_height);
    assert(man.getValidatorCount(block_height) == 1);

    block_height = 1012; // valid block height : 5 <= H < 1013
    man.clearExpiredValidators(block_height);
    assert(man.getValidatorCount(block_height) == 0);
}

// https://github.com/bpfkorea/agora/pull/1010#issuecomment-654149650
unittest
{
    // Irrelevant for this test, the seed is only derived from the private key
    // and the offset (which is 0 in both cases)
    Hash utxo;
    auto e1 = EnrollmentManager.makeEnrollment(WK.Keys.A, utxo, 10, 0);
    auto e2 = EnrollmentManager.makeEnrollment(WK.Keys.B, utxo, 10, 0);
    assert(e1.random_seed != e2.random_seed);
}

/// Test for the height when the enrollment will be available
unittest
{
    import agora.consensus.data.Transaction;

    scope utxo_set = new TestUTXOSet;
    KeyPair key_pair = KeyPair.random();
    genesisSpendable().map!(txb => txb.refund(key_pair.address).sign(TxType.Freeze))
        .each!(tx => utxo_set.put(tx));
    auto utxos = utxo_set.storage;

    // create an EnrollmentManager
    const validator_cycle = 20;
    scope man = new EnrollmentManager(":memory:", key_pair,
        new immutable(ConsensusParams)(validator_cycle));

    // create and add the first enrollment
    Enrollment[] enrolls;
    auto enroll = man.createEnrollment(utxo_set.keys[0]);
    assert(man.addEnrollment(enroll, Height(10), utxo_set.getUTXOFinder()));

    // if the current height is smaller than the available height,
    // we can get no enrollment
    man.getEnrollments(enrolls, Height(9));
    assert(enrolls.length == 0);

    // if the current height is greater than or equal to the available height,
    // we can get enrollments
    man.getEnrollments(enrolls, Height(10));
    assert(enrolls.length == 1);

    // make the enrollment a validator
    man.addValidator(enroll, Height(11), &utxo_set.peekUTXO, utxos);
    man.getEnrollments(enrolls, Height(11));
    assert(enrolls.length == 0);

    // add the enrollment that is already a validator, and check if
    // the enrollment can be nominated at the height before the cycle end
    assert(man.addEnrollment(enroll, Height(11), &utxo_set.peekUTXO));
    man.getEnrollments(enrolls, Height(validator_cycle + 9));
    assert(enrolls.length == 0);
    man.getEnrollments(enrolls, Height(validator_cycle + 10));
    assert(enrolls.length == 1);

    // make the enrollment a validator again
    man.clearExpiredValidators(Height(validator_cycle + 11));
    man.addValidator(enroll, Height(validator_cycle + 11), &utxo_set.peekUTXO, utxos);

    // add the enrollment that has the available height smaller than
    // the enrolled height of the validator, we can get no enrollment
    assert(man.addEnrollment(enroll, Height(validator_cycle + 10),
        &utxo_set.peekUTXO));
    assert(man.enroll_pool.count() == 1);
    man.getEnrollments(enrolls, Height(validator_cycle + 11));
    assert(enrolls.length == 0);
}

// test getRandomSeed()
unittest
{
    import agora.common.crypto.Schnorr;
    import agora.consensus.data.Transaction;
    import std.conv;
    import std.range;
    import std.stdio;

    scope storage = new TestUTXOSet;
    Hash[] utxos;

    // genesisSpendable returns 8 outputs
    auto pairs = iota(8).map!(idx => WK.Keys[idx]).array;

    genesisSpendable()
        .enumerate
        .map!(tup => tup.value
            .refund(pairs[tup.index].address)
            .sign(TxType.Freeze))
        .each!((tx) {
            storage.put(tx);
            utxos ~= UTXO.getHash(tx.hashFull(), 0);
        });

    auto params = new immutable(ConsensusParams);
    scope man = new EnrollmentManager(":memory:", KeyPair.random(), params);

    foreach (idx, kp; pairs)
    {
        Pair pair;
        pair = Pair.fromScalar(secretKeyToCurveScalar(kp.secret));

        auto cycle = PreImageCycle(
            0, 0, PreImageCache(PreImageCycle.NumberOfCycles, params.ValidatorCycle),
            PreImageCache(params.ValidatorCycle, 1));

        const seed = cycle.populate(pair.v, true);
        const enroll = EnrollmentManager.makeEnrollment(
            pair, utxos[idx], params.ValidatorCycle,
            seed, cycle.index);
        assert(man.addValidator(enroll, Height(1), storage.getUTXOFinder(),
            storage.storage) is null);

        auto cache = PreImageCache(PreImageCycle.NumberOfCycles, params.ValidatorCycle);
        cache.reset(hashMulti(pair.v, "consensus.preimages", 0));

        PreImageInfo preimage = { enroll_key : utxos[idx],
            distance : cast(ushort)params.ValidatorCycle,
            hash : cache[$ - params.ValidatorCycle - 1] };

        assert(man.addPreimage(preimage));
    }

    utxos.sort();  // must be sorted by enrollment key
    assert(man.getRandomSeed(utxos, Height(1)) ==
        Hash(`0xc689b81d03b1793514fd0725930db06c3b1c1de6339073f82bb4ad39948877b8c1c8e72e1afba5f86419cc900cdbf46b50fed5e0e97c610dd82c98e81574424b`),
        man.getRandomSeed(utxos, Height(1)).to!string);

    assert(man.getRandomSeed(utxos, Height(504)) ==
        Hash(`0x49008dfc5c470b580146349a2fda59901914c37001507a31bf37252102675af31898c50331407f21015b4ae04606136b857955a2fd1b0f382c5a30339d24c88c`),
        man.getRandomSeed(utxos, Height(504)).to!string);

    assert(man.getRandomSeed(utxos, Height(1008)) ==
        Hash(`0xec51f4e21932ab7269ddbf461c4339dcdc493cb9f65941ebc816ff26e097fa07e2ee914e824b17b90c7a3640ac063148eaac56bb25a00c3934a13a16984ed546`),
        man.getRandomSeed(utxos, Height(1008)).to!string);
}

// Tests for not consuming pre-images before being a validator
unittest
{
    import std.stdio;
    import std.range;
    import agora.consensus.data.Transaction;

    scope utxo_set = new TestUTXOSet;
    genesisSpendable()
        .map!(txb => txb.refund(WK.Keys[0].address).sign(TxType.Freeze))
        .each!(tx => utxo_set.put(tx));
    scope man = new EnrollmentManager(":memory:", WK.Keys[0],
        new immutable(ConsensusParams)(10));

    // create the first enrollment and add it as a validator
    auto enroll = man.createEnrollment(utxo_set.keys[0]);
    assert(man.addValidator(
            enroll, Height(2), utxo_set.getUTXOFinder(), utxo_set.storage) is null);
    auto preimages_valid = man.cycle.preimages.byStride().dup;

    // create the second enrollment
    enroll = man.createEnrollment(utxo_set.keys[0]);

    // pre-images of the current cycle have not changed
    auto preimages_enroll = man.cycle.preimages.byStride().dup;
    assert(preimages_enroll[] == preimages_valid[]);
}

// Tests for get/set a enrollment key
unittest
{
    import agora.consensus.data.Transaction;

    auto utxo_set = new TestUTXOSet;
    genesisSpendable()
        .map!(txb => txb.refund(WK.Keys.A.address).sign(TxType.Freeze))
        .each!(tx => utxo_set.put(tx));
    auto man = new EnrollmentManager(":memory:", WK.Keys.A,
        new immutable(ConsensusParams)(10));

    assert(utxo_set.length == 8);
    man.setEnrollmentKey(utxo_set.keys[3]);
    assert(man.getEnrollmentKey()[] == utxo_set.keys[3][]);
    assert(man.getEnrollmentKey()[] != utxo_set.keys[0][]);
}
