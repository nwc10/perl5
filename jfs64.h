/* This is the "A small noncryptographic PRNG" by Bob Jenkins>, later given the
   name JFS64.
   http://burtleburtle.net/bob/rand/smallprng.html
   "I wrote this PRNG. I place it in the public domain."

   It's small, and good enough:
   https://www.pcg-random.org/posts/bob-jenkins-small-prng-passes-practrand.html
*/

struct jfs64_state {
    U64 a;
    U64 b;
    U64 c;
    U64 d;
};

PERL_STATIC_INLINE U64
jfs64_ranval( struct jfs64_state *x )
{
    U64 e = x->a - ROTL64(x->b, 7);
    x->a = x->b ^ ROTL64(x->c, 13);
    x->b = x->c + ROTL64(x->d, 37);
    x->c = x->d + e;
    x->d = e + x->a;
    return x->d;
}

PERL_STATIC_INLINE void
jfs64_raninit( struct jfs64_state *x, U64 seed )
{
    int i;
    x->a = 0xf1ea5eed;
    x->b = x->c = x->d = seed;
    for (i=0; i<20; ++i) {
        (void)jfs64_ranval(x);
    }
}
