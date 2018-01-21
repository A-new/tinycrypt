

    ROT_0a          =    9,     /* rotation constants for Phelix block function */
    ROT_1a          =   10,
    ROT_2a          =   17,
    ROT_3a          =   30,
    ROT_4a          =   13,

    ROT_0b          =   20,
    ROT_1b          =   11,
    ROT_2b          =    5,
    ROT_3b          =   15,
    ROT_4b          =   25
    };

#define MAC_MAGIC_XOR   0x912D94F1          /* magic constant for MAC */
#define AAD_MAGIC_XOR   0xAADAADAA          /* magic constant for AAD */

/* 1st half of a half block */
#define Phelix_H0(Z,xx)                                             \
            Z[0] +=(Z[3]^(xx));         Z[3] = ROTL32(Z[3],ROT_3b); \
            Z[1] += Z[4];               Z[4] = ROTL32(Z[4],ROT_4b); \
            Z[2] ^= Z[0];               Z[0] = ROTL32(Z[0],ROT_0a); \
            Z[3] ^= Z[1];               Z[1] = ROTL32(Z[1],ROT_1a); \
            Z[4] += Z[2];               Z[2] = ROTL32(Z[2],ROT_2a); 
                        
/* 2nd half of a half block */
#define Phelix_H1(Z,xx)                                             \
            Z[0] ^=(Z[3]+(xx));         Z[3] = ROTL32(Z[3],ROT_3a); \
            Z[1] ^= Z[4];               Z[4] = ROTL32(Z[4],ROT_4a); \
            Z[2] += Z[0];               Z[0] = ROTL32(Z[0],ROT_0b); \
            Z[3] += Z[1];               Z[1] = ROTL32(Z[1],ROT_1b); \
            Z[4] ^= Z[2];               Z[2] = ROTL32(Z[2],ROT_2b);