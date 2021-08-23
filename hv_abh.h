/* A Better Hash.

A C implementation of https://github.com/martinus/robin-hood-hashing
by Martin Ankerl <http://martin.ankerl.com>

Better than what we have. Not better than his. His is hard to beat.

His design is for a Robin Hood hash (ie open addressing, Robin Hood probing)
with:

* a contiguous block of memory
* hash into 2**n slots
* instead of wrapping round from the end to the start of the array when
  probing, *actually* allocate some extra slots at the end, sufficient to cover
  the maximum permitted probe length
* store metadata for free/used (with the offset from the ideal slot) in a byte
  array immediately after the data slots
* store the offset in the top n bits of the byte, use the lower 8-n bits
  (possibly 0) to store (more) bits of the key's hash in the rest.
  (where n might be 0 - n is updated dynamically whenever a probe would overflow
   the currently permitted maxiumum)
  (so m bits of the hash are used to pick the ideal slot, and a different n are
   in the metadata, meaning that misses can be rejected more often)
* sentinel byte at the end of the metadata to cause the iterator to efficiently
  terminate
* setting max_items to 0 to force a resize before even trying another allocation
* when inserting and stealing a slot, move the next items up in bulk
  (ie don't implement it as "swap the new element with the evicted element and
  carry on inserting - the rest of the elements are already in a valid probe
  order, so just update *all* their metadata bytes, and then memmove them)

it's incredibly flexible (up to, automatically chosing whether to allocate
the value object inline in the hash, or indrected via a pointer), but
implemented as a C++ template.

Whereas we need something in C. Only for small structures, so they can always
go inline. And it turns out, our keys are always pointers, and easily "hashed"
(either because they are, because they point to something that caches its
hash value, or because we fake it and explicitly store the hash value.)

The only optimisation left is to change iterator metadata processing to be
word-at-a-time when possible. And even that might not be worth it.
*/

struct Perl_ABH_Table {
    U64 salt;
    /* If cur_items and max_items are *both* 0 then we only allocated a control
       structure. All of the other entries in the struct are bogus, apart from
       entry_size, and calling many of the accessor methods for the hash will
       fail assertions.
       ("Doctor, Doctor, it hurts when I do this". "Well, don't do that then.")
       Iterators will return end immediately, fetch will fast track a not-found
       result, and insert will immediately allocate the default minimum size. */
    size_t cur_items;
    size_t max_items; /* hit this and we grow */
    /* defaults to sizeof(HE) if you don't set it before the first insert: */
    U8 entry_size;
    /* 0 for the shared string table. Defaults to HVhek_WASUTF8: */
    U8 key_mask;
    U8 official_size_log2;
    U8 key_right_shift;
    /* This is the maximum probe distance we can use without updating the
       metadata. It might not *yet* be the maximum probe distance possible for
       the official_size. */
    U8 max_probe_distance;
    /* This is the maximum probe distance possible for the official size.
       We can (re)calcuate this from other values in the struct, but it's easier
       to cache it as we have the space. */
    U8 max_probe_distance_limit;
    U8 metadata_hash_bits;
};

void Perl_ABH_build(pTHX_ Perl_ABH_Table **hashtable_p,
                    size_t entry_size,
                    size_t entries);

/* Frees the entire contents of the hash, leaving you just the hashtable itself,
   which you allocated (heap, stack, inside another struct, wherever) */
void Perl_ABH_demolish(pTHX_ Perl_ABH_Table **hashtable_p);
/* and then free memory if you allocated it */

void *Perl_ABH_lvalue_fetch(pTHX_ Perl_ABH_Table **hashtable_p,
                            const char *key, STRLEN klen, BIKESHED hash, U32 flags);

void *Perl_ABH_delete(pTHX_ Perl_ABH_Table **hashtable_p,
                      const char *key, STRLEN klen, BIKESHED hash, U32 flags);

PERL_STATIC_INLINE bool
S_ABH_is_empty(const Perl_ABH_Table *hashtable) {
    return hashtable ? hashtable->cur_items == 0 : TRUE;
}

PERL_STATIC_INLINE size_t
S_ABH_count(const Perl_ABH_Table *hashtable) {
    return hashtable ? hashtable->cur_items : 0;
}

void Perl_ABH_grow(pTHX_ Perl_ABH_Table **hashtable_p, size_t wanted);


/* for now, I'm hard coding this.
   The assumption is that with a starting size of 8 (pointer sized) elements,
   load factor of 0.75 means max chain length of 6, so need five overrun slots,
   hence also 14 real metadata slots, plus 1 sentinel, hence two 8-byte words.
   I guess we could pump it up to 0.875, but I don't know what performance would
   be like.
   Possibly even we start it at 14/16, and on each doubling drop it by 1/16
   until it's down to 8/16 (ie 50%)
*/

/* See comments in hash_allocate_common (and elsewhere) before changing any of
   these, and test with assertions enabled. The current choices permit certain
   optimisation assumptions in parts of the code. */

#define ABH_LOAD_FACTOR 0.75
#define ABH_MIN_SIZE_BASE_2 3
#define ABH_INITIAL_BITS_IN_METADATA 5

/* These six are private. We need them out here for the inline functions.
   Use them. */
PERL_STATIC_INLINE size_t Perl_ABH_kompromat(const struct Perl_ABH_Table *hashtable) {
    assert(!(hashtable->cur_items == 0 && hashtable->max_items == 0));
    return (1 << (size_t)hashtable->official_size_log2) + hashtable->max_probe_distance - 1;
}
PERL_STATIC_INLINE size_t Perl_ABH_get_official_size(const struct Perl_ABH_Table *hashtable) {
    return 1 << (size_t)hashtable->official_size_log2;
}
PERL_STATIC_INLINE size_t Perl_ABH_calc_max_items(const Perl_ABH_Table *hashtable) {
    return Perl_ABH_get_official_size(hashtable) * ABH_LOAD_FACTOR;
}

PERL_STATIC_INLINE char *Perl_ABH_entries(struct Perl_ABH_Table *hashtable) {
    assert(!(hashtable->cur_items == 0 && hashtable->max_items == 0));
    return (char *)hashtable - hashtable->entry_size;
}
PERL_STATIC_INLINE U8 *Perl_ABH_metadata(struct Perl_ABH_Table *hashtable) {
    assert(!(hashtable->cur_items == 0 && hashtable->max_items == 0));
    return (U8 *)hashtable + sizeof(struct Perl_ABH_Table);
}
PERL_STATIC_INLINE const U8 *Perl_ABH_metadata_const(const struct Perl_ABH_Table *hashtable) {
    assert(!(hashtable->cur_items == 0 && hashtable->max_items == 0));
    return (const U8 *)hashtable + sizeof(struct Perl_ABH_Table);
}

/* This setup is all private, but is needed for the inline functions */
struct Perl_ABH_loop_state {
    char *entry_raw;
    U8 *metadata;
    unsigned int metadata_increment;
    unsigned int metadata_hash_mask;
    unsigned int probe_distance_shift;
    unsigned int max_probe_distance;
    unsigned int probe_distance;
    U8 entry_size;
    U8 key_mask;
};

PERL_STATIC_INLINE BIKESHED
S_ABH_salt_and_mix(const struct Perl_ABH_Table *hashtable, BIKESHED hash_val) {
    return (hashtable->salt ^ hash_val) * 11400714819323198485ULL;
}

/* This function turns out to be quite hot. We initialise looping on a *lot* of
   hashes. Removing a branch from this function reduced the instruction dispatch
   by over 0.1% for a non-trivial program (according to cachegrind. Sure, it
   doesn't change the likely cache misses, which is the first-order driver of
   performance.)

   Inspecting annotated compiler assembly output suggests that optimisers move
   the sections of this function around in the inlined code, and hopefully don't
   initialised any values until they are used. */

PERL_STATIC_INLINE struct Perl_ABH_loop_state
S_ABH_create_loop_state(struct Perl_ABH_Table *hashtable, BIKESHED hash_val)
{
    /* "finalise" the hash by multiplying by the constant for Fibonacci bucket
       determination. */
    BIKESHED mixed = S_ABH_salt_and_mix(hashtable, hash_val);
    struct Perl_ABH_loop_state retval;
    retval.entry_size = hashtable->entry_size;
    retval.key_mask = hashtable->key_mask;
    retval.metadata_increment = 1 << hashtable->metadata_hash_bits;
    retval.metadata_hash_mask = retval.metadata_increment - 1;
    retval.probe_distance_shift = hashtable->metadata_hash_bits;
    retval.max_probe_distance = hashtable->max_probe_distance;
    size_t used_hash_bits = mixed >> hashtable->key_right_shift;
    retval.probe_distance = retval.metadata_increment | (used_hash_bits & retval.metadata_hash_mask);
    size_t bucket = used_hash_bits >> hashtable->metadata_hash_bits;
    if (!hashtable->metadata_hash_bits) {
        assert(retval.probe_distance == 1);
        assert(retval.metadata_hash_mask == 0);
        assert(bucket == used_hash_bits);
    }

    retval.entry_raw = Perl_ABH_entries(hashtable) - bucket * retval.entry_size;
    retval.metadata = Perl_ABH_metadata(hashtable) + bucket;
    return retval;
}

Perl_ABH_Table *Perl_ABH_fast_HV_copy(pTHX_ Perl_ABH_Table *source);

/* Executes the given callback function on each element of the hashtable.
 * Passes the callback (entry, arg) or (my_perl, entry, arg)
 * By declaring this inline, the optimiser may be able to inline the callback,
 * and hence eliminate the indirect function call. */

typedef U32 (ABH_FOREACH_CALLBACK)(pTHX_ void *, void *);

PERL_STATIC_INLINE U32 Perl_ABH_foreach(pTHX_ Perl_ABH_Table *hashtable,
                                        ABH_FOREACH_CALLBACK callback,
                                        void *arg) {
    if (!hashtable)
        return 0;

    size_t entries_in_use = Perl_ABH_kompromat(hashtable);
    char *entry_raw = Perl_ABH_entries(hashtable);
    U8 *metadata = Perl_ABH_metadata(hashtable);
    size_t bucket = 0;
    while (bucket < entries_in_use) {
        if (*metadata) {
            U32 retval = callback(aTHX_ (void *)entry_raw, arg);
            if (retval)
                return retval;
        }
        ++bucket;
        ++metadata;
        entry_raw -= hashtable->entry_size;
    }
    return 0;
}

/* iterators are stored as unsigned values, metadata index plus one.
 * This is clearly an internal implementation detail. Don't cheat.
 */

/* Returns an iterator that is already exhausted. This turns out to be very
 * useful to store as a default value. */
PERL_STATIC_INLINE Perl_ABH_Iterator
Perl_ABH_end(const Perl_ABH_Table *hashtable) {
    PERL_UNUSED_ARG(hashtable);
    struct Perl_ABH_Iterator iterator;
    iterator.pos = 0;
    return iterator;
}

PERL_STATIC_INLINE Perl_ABH_Iterator
Perl_ABH_next(const Perl_ABH_Table *hashtable, Perl_ABH_Iterator iterator) {
    if (iterator.pos == 0) {
        /* You naughty thing. You're calling next on an iterator that's already
         * exhausted. */
        assert(iterator.pos);
        return iterator;
    }
    while (--iterator.pos > 0) {
        if (Perl_ABH_metadata_const(hashtable)[iterator.pos - 1]) {
            return iterator;
        }
    }
    return iterator;
}

PERL_STATIC_INLINE Perl_ABH_Iterator
Perl_ABH_first(const Perl_ABH_Table *hashtable) {
    Perl_ABH_Iterator iterator;
    iterator.pos= Perl_ABH_kompromat(hashtable);
    if (Perl_ABH_metadata_const(hashtable)[iterator.pos - 1]) {
        return iterator;
    }
    return Perl_ABH_next(hashtable, iterator);
}

PERL_STATIC_INLINE void *
Perl_ABH_current(Perl_ABH_Table *hashtable, Perl_ABH_Iterator iterator) {
    /* Clearly for the production version this should be a bit more forgiving,
     * and return NULL (probably also warning. */
    assert(Perl_ABH_metadata(hashtable)[iterator.pos - 1]);
    return Perl_ABH_entries(hashtable) - hashtable->entry_size * (iterator.pos - 1);
}

PERL_STATIC_INLINE bool
Perl_ABH_at_end(const Perl_ABH_Table *hashtable, Perl_ABH_Iterator iterator) {
    PERL_UNUSED_ARG(hashtable);
    return iterator.pos == 0;
}
