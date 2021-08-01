/*    hv_abh.c
 *
 *    Copyright (C) 2020, 2021 by Nicholas Clark
 *
 *    You may distribute under the terms of either the GNU General Public
 *    License or the Artistic License, as specified in the README file.
 *
 * except for S_round_up_log_base2, adapted from the log_base2 function at
 * https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
 * -- Individually, the code snippets here are in the public domain
 * -- (unless otherwise noted)
 * This one was not marked with any special copyright restriction.
 *
 */

#include "EXTERN.h"
#define PERL_IN_HV_ABH_C
#include "perl.h"

/* What we need is to round the value rounded up to the next power of 2, and
 * then the log base 2 of that. Don't call this with v == 0. */
static U32 S_round_up_log_base2(U32 v) {
    static const U8 MultiplyDeBruijnBitPosition[32] = {
        1, 10, 2, 11, 14, 22, 3, 30, 12, 15, 17, 19, 23, 26, 4, 31,
        9, 13, 21, 29, 16, 18, 25, 8, 20, 28, 24, 7, 27, 6, 5, 32
    };

    /* this rounds (v - 1) down to one less than a power of 2 */
    --v;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;

    return MultiplyDeBruijnBitPosition[(U32)(v * 0x07C4ACDDU) >> 27];
}

static const unsigned int max_probe_distance = 255;


PERL_STATIC_INLINE size_t get_allocated_items(const Perl_ABH_Table *hashtable) {
    /* -1 because...
       probe distance of 1 is the correct bucket.
       hence for a value whose ideal slot is the last bucket, it's *in* the
       official allocation.
       probe distance of 2 is the first extra bucket beyond the official
       allocation
       probe distance of 255 is the 254th beyond the official allocation.
    */
    assert(!(hashtable->cur_items == 0 && hashtable->max_items == 0));
    return Perl_ABH_get_official_size(hashtable) + hashtable->max_probe_distance_limit - 1;
}

PERL_STATIC_INLINE void hash_demolish_internal(Perl_ABH_Table *hashtable) {
    if (hashtable->cur_items == 0 && hashtable->max_items == 0) {
        free(hashtable);
        return;
    }

    size_t allocated_items = get_allocated_items(hashtable);
    size_t entries_size = hashtable->entry_size * allocated_items;
    char *start = (char *)hashtable - entries_size;
    free(start);
}

void
Perl_ABH_demolish(pTHX_ Perl_ABH_Table **hashtable_p)
{
    hash_demolish_internal(*hashtable_p);
    *hashtable_p = NULL;
}
/* and then free memory if you allocated it */

/* round up to a multiple of the pointer size. */
PERL_STATIC_INLINE size_t round_size_up(size_t wanted) {
    return (wanted - 1 + sizeof(void *)) & ~(sizeof(void *) - 1);
}

/* Relationship between "official" size (a power of two), how many buckets are
 * actually allocated, and the sequence of
 * ((max probe distances), (bits of hash stored in the metadata))
 * max probe distance is expressed as 1 .. $n
 * but the slot used is 0 .. $n - 1
 * metadata is stored as 1 .. $n
 * with 0 meaning "emtpy"
 *
 * This table shows some sizes we don't use. Smallest allocation is 8 + 5.
 *
 *                            max probe distance
 * buckets              <--   bits of extra hash    -->
 * allocated            6    5    4    3    2    1    0
 *    4 + 2             2 (from 3)
 *    8 + 5             3    6 (from 7)
 *   16 + 11            3    7   12 (from 15)
 *   32 + 23            3    7   15   24 (from 31)
 *   64 + 47            3    7   15   31   48 (from 63)
 *  128 + 95            3    7   15   31   63   96 (from 127)
 *  256 + 191           3    7   15   31   63  127  192 (from 255)
 *  512 + 254           3    7   15   31   63  127  255 (from 255)
 * 1024 + 254           3    7   15   31   63  127  255 (from 255)
 *
 * So for sizeof(long) == 4, the sentinel byte at the end of the allocated
 * metadata never gets reached if we shift metadata long-at-a-time.
 * For sizeof(long) == 8, it would get reached and shifted once if we have a
 * hash with 8 + 5 buckets, and start with 6 bits of hash in the metadata,
 * because we likely would first hit the short max probe distance of 3, and
 * reprocess the metadata bytes from ((2 bits probe distance), (6 bits hash))
 * to ((3 bits probe distance), (5 bits hash)), and if we do that 8-at-a-time,
 * we would (also) touch the sentinel byte stored 5 in.
 *
 * So, simple, we don't start with 6 bits of hash. Max is 5 bits. Which means
 * we can never grow the probe distance on our smallest 8 + 5 allocation - we
 * always hit the probe distance limit first and resize to a 16 + 11 hash.
 */

PERL_STATIC_INLINE Perl_ABH_Table *
S_hash_allocate_common(pTHX_
                       U8 entry_size,
                       U8 key_right_shift,
                       U8 official_size_log2) {
    size_t official_size = 1 << (size_t)official_size_log2;
    size_t max_items = official_size * ABH_LOAD_FACTOR;
    U8 max_probe_distance_limit;
    if (max_probe_distance < max_items) {
        max_probe_distance_limit = max_probe_distance;
    } else {
        max_probe_distance_limit = max_items;
    }
    size_t allocated_items = official_size + max_probe_distance_limit - 1;
    size_t entries_size = entry_size * allocated_items;
    size_t metadata_size = round_size_up(allocated_items + 1);

    size_t total_size
      = entries_size + sizeof (Perl_ABH_Table) + metadata_size;
    assert(total_size == round_size_up(total_size));
    Perl_ABH_Table *hashtable
        = (Perl_ABH_Table *)((char *)malloc(total_size) + entries_size);

    hashtable->salt = jfs64_ranval(&PL_hash_salt_state);
    hashtable->official_size_log2 = official_size_log2;
    hashtable->max_items = max_items;
    hashtable->cur_items = 0;
    hashtable->metadata_hash_bits = ABH_INITIAL_BITS_IN_METADATA;
    /* ie 7: */
    U8 initial_probe_distance = (1 << (8 - ABH_INITIAL_BITS_IN_METADATA)) - 1;
    hashtable->max_probe_distance = max_probe_distance_limit > initial_probe_distance ? initial_probe_distance : max_probe_distance_limit;
    hashtable->max_probe_distance_limit = max_probe_distance_limit;
    hashtable->key_right_shift = key_right_shift;
    hashtable->entry_size = entry_size;

    U8 *metadata = (U8 *)(hashtable + 1);
    memset(metadata, 0, metadata_size);

    return hashtable;
}


void
Perl_ABH_build(pTHX_ Perl_ABH_Table **hashtable_p,
               size_t entry_size,
               size_t entries)
{
    if (UNLIKELY(entry_size == 0 || entry_size > 255
                 || entry_size & (sizeof(void *) - 1))) {
        Perl_croak(aTHX_ "panic: hash table entry_size %zu is invalid", entry_size);
    }

    if (!entries) {
        *hashtable_p = (Perl_ABH_Table *) calloc(sizeof (Perl_ABH_Table), 1);
        /* cur_items and max_items both 0 signals that we only allocated a
           control structure. */
        (*hashtable_p)->entry_size = entry_size;
    } else {
        /* Minimum size we need to allocate, given the load factor. */
        size_t min_needed = entries * (1.0 / ABH_LOAD_FACTOR);
        size_t initial_size_base2 = S_round_up_log_base2(min_needed);
        if (initial_size_base2 < ABH_MIN_SIZE_BASE_2) {
            /* "Too small" - use our original defaults. */
            initial_size_base2 = ABH_MIN_SIZE_BASE_2;
        }

        *hashtable_p = S_hash_allocate_common(aTHX_ entry_size,
                                              (8 * sizeof(U64) - initial_size_base2),
                                              initial_size_base2);
    }
    (*hashtable_p)->key_mask = ~HVhek_WASUTF8;
}

PERL_STATIC_INLINE HEK **
S_hash_insert_internal(pTHX_ Perl_ABH_Table *hashtable,
                       const char *key, STRLEN klen, BIKESHED hash, U32 flags)
{
    if (UNLIKELY(hashtable->cur_items >= hashtable->max_items)) {
        Perl_croak(aTHX_
                   "panic: hash_insert_internal has no space (%zu >= %zu) when adding %s",
                   hashtable->cur_items, hashtable->max_items, key);
    }

    U32 type = flags & HV_ABH_KEY_TYPE_MASK;

    struct Perl_ABH_loop_state ls = S_ABH_create_loop_state(hashtable, hash);
    const U32 kflags = type & ls.key_mask;

    while (1) {
        if (*ls.metadata < ls.probe_distance) {
            /* this is our slot. occupied or not, it is our rightful place. */

            if (*ls.metadata == 0) {
                /* Open goal. Score! */
            } else {
                /* make room. */

                /* Optimisation first seen in Martin Ankerl's implementation -
                   we don't need actually implement the "stealing" by swapping
                   elements and carrying on with insert. The invariant of the
                   hash is that probe distances are never out of order, and as
                   all the following elements have probe distances in order, we
                   can maintain the invariant just as well by moving everything
                   along by one. */
                U8 *find_me_a_gap = ls.metadata;
                U8 old_probe_distance = *ls.metadata;
                do {
                    U32 new_probe_distance = ls.metadata_increment + old_probe_distance;
                    if (new_probe_distance >> ls.probe_distance_shift == ls.max_probe_distance) {
                        /* Optimisation from Martin Ankerl's implementation:
                           setting this to zero forces a resize on any insert,
                           *before* the actual insert, so that we never end up
                           having to handle overflow *during* this loop. This
                           loop can always complete. */
                        hashtable->max_items = 0;
                    }
                    /* a swap: */
                    old_probe_distance = *++find_me_a_gap;
                    *find_me_a_gap = new_probe_distance;
                } while (old_probe_distance);

                size_t entries_to_move = find_me_a_gap - ls.metadata;
                size_t size_to_move = ls.entry_size * entries_to_move;
                /* When we had entries *ascending* in memory, this was
                 * memmove(entry_raw + hashtable->entry_size, entry_raw,
                 *         size_to_move);
                 * because we point to the *start* of the block of memory we
                 * want to move, and we want to move it one "entry" forwards.
                 * `entry_raw` is still a pointer to where we want to make free
                 * space, but what want to do now is move everything at it and
                 * *before* it downwards.
                 */
                char *dest = ls.entry_raw - size_to_move;
                memmove(dest, dest + ls.entry_size, size_to_move);
            }

            /* However, we can still exceed the new (lower) probe distances that
               we initially set.
               Optimisation from Martin Ankerl's implementation:
               setting this to zero forces a resize on any insert, *before* the
               actual insert, so that we never end up having to handle overflow
               *during* this loop. This loop can always complete. */
            if (ls.probe_distance >> ls.probe_distance_shift == ls.max_probe_distance) {
                if (hashtable->cur_items >= hashtable->max_items) {
                    /* We've hit the load factor limit. The next insert
                       would grow the hash anyway, so don't confuse things
                       by attempting to trigger a metadata shuffle. */
                } else {
                    hashtable->max_items = 0;
                }
            }

            /* The same test and optimisation as in the "make room" loop - we're
               about to insert something at the (current) max_probe_distance, so
               signal to the next insertion that it needs to take action first.
            */
            if (ls.probe_distance == hashtable->max_probe_distance) {
                if (hashtable->cur_items >= hashtable->max_items) {
                    /* We've hit the load factor limit. The next insert would
                       grow the hash anyway, so don't confuse things by
                       attempting to trigger a metadata shuffle. */
                } else {
                    hashtable->max_items = 0;
                }
            }

            ++hashtable->cur_items;

            *ls.metadata = ls.probe_distance;
            HEK **entry = (HEK **) ls.entry_raw;
            *entry = NULL;
            return entry;
        }
        else if (key && *ls.metadata == ls.probe_distance) {
            /* key is NULL when called from maybe_grow_hash. For that case we
               know that we can't find any duplicates already in the hash. */
            HEK **entry = (HEK **) ls.entry_raw;
            HEK *hek = *entry;
            if (HEK_HASH(hek) == hash
                && (STRLEN) HEK_LEN(hek) == klen
                && (HEK_KEY(hek) == key || memEQ(HEK_KEY(hek), key, klen))
                && (HEK_FLAGS(hek) & ls.key_mask) == kflags) {
                /* Existing entry for this key: */
                return entry;
            }
        }
        ls.probe_distance += ls.metadata_increment;
        ++ls.metadata;
        ls.entry_raw -= ls.entry_size;
        assert(ls.probe_distance < (hashtable->max_probe_distance + 1) * ls.metadata_increment);
        assert(ls.metadata < Perl_ABH_metadata(hashtable) + Perl_ABH_get_official_size(hashtable) + Perl_ABH_calc_max_items(hashtable));
        assert(ls.metadata < Perl_ABH_metadata(hashtable) + Perl_ABH_get_official_size(hashtable) + 256);
    }
}

static struct Perl_ABH_Table *
S_maybe_grow_hash(pTHX_ Perl_ABH_Table *hashtable) {
    if (UNLIKELY(hashtable->cur_items == 0 && hashtable->max_items == 0)) {
        Perl_ABH_Table *hashtable_new
            = S_hash_allocate_common(aTHX_ hashtable->entry_size,
                                     (8 * sizeof(U64) - ABH_MIN_SIZE_BASE_2),
                                     ABH_MIN_SIZE_BASE_2);
        hashtable_new->key_mask = hashtable->key_mask;
        free(hashtable);
        return hashtable_new;
    }

    /* hashtable->max_items may have been set to 0 to trigger a call into this
       function. */
    const size_t max_items = Perl_ABH_calc_max_items(hashtable);
    const U32 max_probe_distance = hashtable->max_probe_distance;
    const U32 max_probe_distance_limit = hashtable->max_probe_distance_limit;

    /* We can hit both the probe limit and the max items on the same insertion.
       In which case, upping the probe limit isn't going to save us :-)
       But if we hit the probe limit max (even without hitting the max items)
       then we don't have more space in the metadata, so we're going to have to
       grow anyway. */
    if (hashtable->cur_items < max_items
        && max_probe_distance < max_probe_distance_limit) {
        /* We hit the probe limit, not the max items count. */
        U32 new_probe_distance = 1 + 2 * (U32) max_probe_distance;
        if (new_probe_distance > max_probe_distance_limit) {
#ifdef DEBUG_SPAM
            fprintf(stderr, "grow %p %u => %u (limited to %u size %u)\n",
                    hashtable, max_probe_distance, new_probe_distance,
                    max_probe_distance_limit, hashtable->official_size_log2);
#endif
            new_probe_distance = max_probe_distance_limit;
        } else {
#ifdef DEBUG_SPAM
            fprintf(stderr, "grow %p %u => %u (limit %u, size %u)\n",
                    hashtable, max_probe_distance, new_probe_distance,
                    max_probe_distance_limit, hashtable->official_size_log2);
#endif
        }

        U8 *metadata = Perl_ABH_metadata(hashtable);
        size_t in_use_items = Perl_ABH_get_official_size(hashtable) + max_probe_distance;
        size_t metadata_size = round_size_up(in_use_items + 1);
        size_t loop_count = metadata_size / sizeof(unsigned long);
        unsigned long *p = (unsigned long *) metadata;
        /* right shift each byte by 1 bit, clearing the top bit. */
        do {
            /* 0x7F7F7F7F7F7F7F7F on 64 bit systems, 0x7F7F7F7F on 32 bit,
               but without using constants or shifts larger than 32 bits, or
               the preprocessor. (So the compiler checks all code everywhere.)
               Will break on a system with 128 bit longs. */
            *p = (*p >> 1) & (0x7F7F7F7FUL | (0x7F7F7F7FUL << (4 * sizeof(long))));
            ++p;
        } while (--loop_count);
        assert(hashtable->metadata_hash_bits);
        --hashtable->metadata_hash_bits;
        hashtable->max_probe_distance = new_probe_distance;
        /* Reset this to its proper value. */
        hashtable->max_items = max_items;
        return NULL;
    }

    size_t entries_in_use =  Perl_ABH_kompromat(hashtable);
    char *entry_raw_orig = Perl_ABH_entries(hashtable);
    U8 *metadata_orig = Perl_ABH_metadata(hashtable);
    const U8 entry_size = hashtable->entry_size;
    Perl_ABH_Table *hashtable_orig = hashtable;

    hashtable = S_hash_allocate_common(aTHX_ entry_size,
                                       hashtable_orig->key_right_shift - 1,
                                       hashtable_orig->official_size_log2 + 1);
    hashtable->key_mask = hashtable_orig->key_mask;

    char *entry_raw = entry_raw_orig;
    U8 *metadata = metadata_orig;
    size_t bucket = 0;
    while (bucket < entries_in_use) {
        if (*metadata) {
            HEK **old_entry = (HEK **) entry_raw;
            HEK **new_entry = S_hash_insert_internal(aTHX_ hashtable, NULL, 0,
                                                     (*old_entry)->hek_hash, 0);
            assert(*new_entry == NULL);

            /* The `memcpy` in the else is equivalent to this, and quite
             * possibly its implementation starts with a jump-table based on
             * size. I'd just like to give the compiler an enormous hint that
             * the pointers are going to be word aligned, and that "two
             * pointers" is the most common size, then "one pointer" */
            if (LIKELY(entry_size == sizeof(HE))) {
                HE *src = (HE *) old_entry;
                HE *dest = (HE *) new_entry;
                *dest = *src;
            }
            else if (LIKELY(entry_size == sizeof(HEK *))) {
                *new_entry = *old_entry;
            }
            else {
                memcpy(new_entry, old_entry, entry_size);
            }

            if (!hashtable->max_items) {
                /* Probably we hit the probe limit.
                   But it's just possible that one actual "grow" wasn't
                   enough. */
                Perl_ABH_Table *new_hashtable
                    = S_maybe_grow_hash(aTHX_ hashtable);
                if (new_hashtable) {
#ifdef DEBUG_SPAM
                    fprintf(stderr, "new hashtable %p => %p\n",
                            hashtable, new_hashtable);
#endif
                    hashtable = new_hashtable;
                } else {
#ifdef DEBUG_SPAM
                    fprintf(stderr, "expanded probe distance %p %u => %p %u\n",
                            hashtable_orig, hashtable_orig->max_probe_distance,
                            hashtable, max_probe_distance);
#endif
                }
            }
        }
        ++bucket;
        ++metadata;
        entry_raw -= entry_size;
    }
#ifdef DEBUG_SPAM
    fprintf(stderr, "grew %u to %u\n",
            hashtable_orig->official_size_log2,
            hashtable->official_size_log2);
#endif
    assert(hashtable->max_items);
    hash_demolish_internal(hashtable_orig);
    return hashtable;
}

void *
Perl_ABH_lvalue_fetch(pTHX_ Perl_ABH_Table **hashtable_p,
                      const char *key, STRLEN klen, BIKESHED hash, U32 flags)
{
    U32 kflags = flags & HV_ABH_KEY_TYPE_MASK;
    if (kflags == HV_ABH_KEY_HEK) {
        Perl_croak(aTHX_ "panic: hash flag HV_ABH_KEY_HEK Not Yet Implemented");
    }

    Perl_ABH_Table *hashtable = *hashtable_p;

    if (UNLIKELY(!hashtable)) {
        /* This *is* a special case, but it is a lot easier if we assume this as
         *  a default. */
        Perl_ABH_build(aTHX_ hashtable_p, sizeof(HE), 8);
        hashtable = *hashtable_p;
    }
    else if (UNLIKELY(hashtable->cur_items >= hashtable->max_items)) {
        /* We should avoid growing the hash if we don't need to.
         * It's expensive, and for hashes with iterators, growing the hash
         * invalidates iterators. Which is buggy behaviour if the fetch doesn't
         * need to create a key. */
        void *entry = Perl_ABH_fetch(aTHX_ hashtable, key, klen, hash, flags);
        if (entry) {
            return entry;
        }

        struct Perl_ABH_Table *new_hashtable = S_maybe_grow_hash(aTHX_ hashtable);
        if (new_hashtable) {
            /* We could unconditionally assign this, but that would mean CPU
               cache writes even when it was unchanged, and the address of
               hashtable will not be in the same cache lines as we are writing
               for the hash internals, so it will churn the write cache. */
            *hashtable_p = hashtable = new_hashtable;
        }
    }
    return S_hash_insert_internal(aTHX_ hashtable, key, klen, hash, flags);
}

void *
Perl_ABH_delete(pTHX_ Perl_ABH_Table **hashtable_p,
                const char *key, STRLEN klen, BIKESHED hash, U32 flags)
{
    Perl_ABH_Table *hashtable = *hashtable_p;
    if (UNLIKELY(Perl_ABH_entries(hashtable) == NULL)) {
        return NULL;
    }

    U32 type = flags & HV_ABH_KEY_TYPE_MASK;
    if (type == HV_ABH_KEY_HEK) {
        Perl_croak(aTHX_ "panic: hash flag HV_ABH_KEY_HEK Not Yet Implemented");
    }

    bool release_hek
        = (flags & HV_ABH_DELETE_ACTION_MASK) == HV_ABH_DELETE_RELEASES_HEK;
    /* Restricted hashes are really annoying: */
    bool replace_with_placeholder
        = (flags & HV_ABH_DELETE_ACTION_MASK) == HV_ABH_DELETE_TO_PLACEHOLDER;
    bool refuse_to_delete_readonly_values
        = cBOOL(flags & HV_ABH_REFUSE_TO_DELETE_READONLY_VALUES);

    struct Perl_ABH_loop_state ls = S_ABH_create_loop_state(hashtable, hash);
    const U32 kflags = type & ls.key_mask;

    while (1) {
        if (*ls.metadata == ls.probe_distance) {
            HEK **entry = (HEK **) ls.entry_raw;
            HEK *hek = *entry;
            if (HEK_HASH(hek) == hash
                && (STRLEN) HEK_LEN(hek) == klen
                && (HEK_KEY(hek) == key || memEQ(HEK_KEY(hek), key, klen))
                && (HEK_FLAGS(hek) & ls.key_mask) == kflags) {
                /* Target acquired. */

                void *retval;

                if (ls.entry_size >= sizeof(HE)) {
                    HE *he = (HE *) ls.entry_raw;
                    SV *val = he->hent_val;
                    retval = val;

                    if (replace_with_placeholder && val == &PL_sv_placeholder) {
                        /* if placeholder is here, it's already been "deleted".... */
                        return &PL_sv_placeholder;
                    }

                    if (refuse_to_delete_readonly_values && SvREADONLY(val)) {
                        /* Aaargh, restricted hashes suck.
                         * This seems the easiest way to return a sentinel value
                         * that can't be confused with anything else. */
                        return hashtable;
                    }

                    /* If a restricted hash, rather than really deleting the
                     * entry, put a placeholder there. This marks the key as
                     * being "approved", so we can still access via
                     * not-really-existing key without raising an error. */
                    if (replace_with_placeholder) {
                        he->hent_val = &PL_sv_placeholder;
                        return val;
                    }
                }
                else {
                    /* This is a hack, but I want to return something that
                       is not-NULL, and we know that this is not-NULL */
                    retval = hashtable;
                }

                if (release_hek) {
                    if (hek->hek_refcount > 1) {
                        --hek->hek_refcount;
                        return retval;
                    }
                    /* else it's either a shared hek that needs freeing, or
                     * (erroneously) it's an unshared hek. */
                    Safefree(hek);
                }
                else {
                    /* We're not in the shared string table.
                     * Writing the code this way means that we can support
                     * maps using shared keys - ie entry_size == sizeof(HEK **)
                     * no value, and only set/exists/delete are interesting. */
                    if (hek->hek_refcount > 1) {
                        --hek->hek_refcount;
                    }
                    else if (LIKELY(hek->hek_refcount == 1)) {
                        unshare_hek(hek);
                    }
                    else {
                        /* not shared keys. */
                        Safefree(hek);
                    }
                }

                U8 *metadata_target = ls.metadata;
                /* Look at the next slot */
                U8 old_probe_distance = metadata_target[1];
                /* Without this, gcc seemed always to want to recalculate this
                   for each loop iteration. Also, expressing this only in terms
                   of ls.metadata_increment avoids 1 load (albeit from cache) */
                const U8 can_move = 2 * ls.metadata_increment;
                while (old_probe_distance >= can_move) {
                    /* OK, we can move this one. */
                    *metadata_target = old_probe_distance - ls.metadata_increment;
                    /* Try the next one, etc */
                    ++metadata_target;
                    old_probe_distance = metadata_target[1];
                }
                /* metadata_target now points to the metadata for the last thing
                   we did move. (possibly still our target). */

                size_t entries_to_move = metadata_target - ls.metadata;
                if (entries_to_move) {
                    size_t size_to_move = ls.entry_size * entries_to_move;
                    /* When we had entries *ascending* in memory, this was
                     * memmove(entry_raw, entry_raw + hashtable->entry_size, ,
                     *         size_to_move);
                     * because we point to the *start* of the block of memory we
                     * want to move, and we want to move the block one "entry"
                     * backwards.
                     * `entry_raw` is still a pointer to the entry that we need
                     * to ovewrite, but now we need to move everything *before*
                     * it upwards to close the gap.
                     */
                    memmove(ls.entry_raw - size_to_move + ls.entry_size,
                            ls.entry_raw - size_to_move,
                            size_to_move);
                }
                /* and this slot is now emtpy. */
                *metadata_target = 0;
                --hashtable->cur_items;

                if (hashtable->max_items == 0
                    && hashtable->cur_items < hashtable->max_probe_distance) {
                    /* So this is a fun corner case...

                       For empty hashes we have a space optimisation to (not)
                       allocate "8" (ie 13) slots initially. Instead we only
                       allocate a control structure. However most of the
                       metadata in that is stored log base 2 (another size
                       optimisation) hence *it* can't store zero. So we mark
                       this case by setting both hashtable->cur_items == 0 &&
                       hashtable->max_items == 0
                       `max_items` zero triggers immediate allocation on any
                       insert ("no questions asked") and `cur_items` zero is the
                       true state.

                       The assumption of that commit was that it was impossible
                       for the control structure to be in that (zero,zero) state
                       as soon as any insert happened, because after that
                       max_items would only be set to zero if an insert flagged
                       up that the `max_probe_distance` might overflow on the
                       *next* insert (ie trigger that immediate allocation), and
                       if there are items allocated, then (obviously)
                       `cur_items` isn't zero.

                       What I missed was that a sequence of inserts followed by
                       a sequence of deletes can reach (zero,zero). If the
                       *last* insert hits the `max_probe_distance` limit, then
                       it sets `max_items` to zero so that the next insert will
                       allocate.

                       But what if there is no next insert?

                       Then nothing resets the `max_items`, and it remains as
                       zero.

                       And if the only write actions that happen on the hash
                       after this are to delete each entry in turn, then
                       eventually `cur_items` reaches zero too (accurately), and
                       then the "special state" flags are accidentally recreated
                       but not with the "special state" memory layout.

                       (And with enough debugging enabled the assignment to
                        `hashtable->last_delete_at` just below fails an
                        assertion in `MVM_str_hash_metadata`)

                       So clearly we need to unwind the "immediate allocation"
                       flag.

                       We certainly can't do it on *any* delete

                       We can't actually do it on *any* delete that drops a
                       probe distance below the limit because (this one is
                       subtle) worst case it's possible for
                       a) a hash to be in the state where several entries have
                          probe distances one below the threshold
                       b) a *single* insert causes 2+ of these to move up
                          (the "make room" code in insert)
                          (or 1 to move up, *and* the new insert to be at the
                           the trigger distance)
                           which sets the flag
                       c) but the immediately subsequent deletion causes only
                           *one* of these to drop back below the max.

                       The really conservative approach would only be to reset
                       if the hash is about to hit zero items.

                       But I believe that the earliest we can be *sure* that no
                       chain is longer than the limit is when the *total*
                       entries in the hash are less than that limit. Because (of
                       course), the worst case is that they are all in a row
                       contesting the same ideal bucket, and the highest probe
                       distance has to be less than the limit.

                       So here we are: */

                    hashtable->max_items = Perl_ABH_calc_max_items(hashtable);
                }

                /* Job's a good 'un. */
                return retval;
            }
        }
        /* There's a sentinel at the end. This will terminate: */
        else if (*ls.metadata < ls.probe_distance) {
            /* So, if we hit 0, the bucket is empty. "Not found".
               If we hit something with a lower probe distance then...
               consider what would have happened had this key been inserted into
               the hash table - it would have stolen this slot, and the key we
               find here now would have been displaced further on. Hence, the
               key we seek can't be in the hash table. */
            return NULL;
        }
        ls.probe_distance += ls.metadata_increment;
        ++ls.metadata;
        ls.entry_raw -= ls.entry_size;
        assert(ls.probe_distance < (hashtable->max_probe_distance + 2) * ls.metadata_increment);
        assert(ls.metadata < Perl_ABH_metadata(hashtable) + Perl_ABH_get_official_size(hashtable) + Perl_ABH_calc_max_items(hashtable));
        assert(ls.metadata < Perl_ABH_metadata(hashtable) + Perl_ABH_get_official_size(hashtable) + 256);
    }
}

/* This is not part of the public API, and subject to change at any point.
   (possibly in ways that are actually incompatible but won't generate compiler
   warnings.) */
U64
Perl_ABH_fsck(pTHX_ Perl_ABH_Table **hashtable_p, U32 mode) {
    Perl_ABH_Table *hashtable = *hashtable_p;
    const char *prefix_hashes = mode & 1 ? "# " : "";
    U32 display = (mode >> 1) & 3;
    U64 errors = 0;
    U64 seen = 0;

    if (hashtable->cur_items == 0 && hashtable->max_items == 0) {
        return 0;
    }

    size_t allocated_items = get_allocated_items(hashtable);
    const U8 metadata_hash_bits = hashtable->metadata_hash_bits;
    char *entry_raw = Perl_ABH_entries(hashtable);
    U8 *metadata = Perl_ABH_metadata(hashtable);
    size_t bucket = 0;
    I64 prev_offset = 0;
    while (bucket < allocated_items) {
        if (!*metadata) {
            /* empty slot. */
            prev_offset = 0;
            if (display == 2) {
                PerlIO_printf(PerlIO_stderr(),
                              "%s%3zX\n", prefix_hashes, bucket);
            }
        } else {
            ++seen;

            HEK **entry = (HEK **) entry_raw;

            if (!*entry) {
                if (display) {
                    PerlIO_printf(PerlIO_stderr(),
                                  "%s%3zX! NULL key\n",
                                  prefix_hashes, bucket);
                }
                ++errors;
                prev_offset = 0;
            }
            else {
                BIKESHED mixed = S_ABH_salt_and_mix(hashtable, HEK_HASH(*entry));

                size_t ideal_bucket = mixed >> hashtable->key_right_shift;
                I64 offset = 1 + bucket - ideal_bucket;
                I64 actual_bucket = *metadata >> metadata_hash_bits;
                char wrong_bucket = offset == actual_bucket ? ' ' : '?';
                char wrong_order;
                if (offset < 1) {
                    wrong_order = '<';
                } else if (offset > hashtable->max_probe_distance) {
                    wrong_order = '>';
                } else if (offset > prev_offset + 1) {
                    wrong_order = '!';
                } else {
                    wrong_order = ' ';
                }
                int error_count = (wrong_bucket != ' ') + (wrong_order != ' ');

                if (display == 2 || (display == 1 && error_count)) {
                    PerlIO_printf(PerlIO_stderr(),
                                  "%s%3zX%c%3" PRIx64 "%c%08" PRIx64 " %" HEKf "\n",
                                  prefix_hashes, bucket, wrong_bucket, offset,
                                  wrong_order, mixed, *entry);
                    errors += error_count;
                }
                prev_offset = offset;
            }
        }
        ++bucket;
        ++metadata;
        entry_raw -= hashtable->entry_size;
    }
    if (*metadata != 0) {
        ++errors;
        if (display) {
            PerlIO_printf(PerlIO_stderr(),
                          "%s    %02x!\n", prefix_hashes, *metadata);
        }
    }
    if (seen != hashtable->cur_items) {
        ++errors;
        if (display) {
            PerlIO_printf(PerlIO_stderr(),
                          "%s %" PRIx64 "u != %zu \n",
                          prefix_hashes, seen, hashtable->cur_items);
        }
    }

    return errors;
}

/*
 * ex: set ts=8 sts=4 sw=4 et:
 */
