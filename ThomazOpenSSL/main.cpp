#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <iostream>

// Make wrapper classes for BigNum and elliptic curve points
// so I don't have to manually free a dozen objects every iteration.
class EcPoint {
public:
    EcPoint(EC_GROUP* group) {
        pECPoint = EC_POINT_new(group);
    };

    ~EcPoint() {
        EC_POINT_free(this->pECPoint);
    }

    EC_POINT* pECPoint;
};

class BigNum {
public:
    BigNum() {
        this->pBN = nullptr;
    };

    ~BigNum() {
        BN_free(this->pBN);
    }

    BIGNUM* pBN;
};

static const uint8_t cipherText[60] = {
    0x05, 0x57, 0xd8, 0xc1, 0xaa, 0x7d, 0x3d, 0xf8, 0xe9, 0x64, 0xdd, 0x8d, 0x84, 0x15, 0x8c, 0x6c,
    0x16, 0x16, 0xf5, 0xdc, 0x59, 0x56, 0xcd, 0x31, 0xe7, 0x83, 0x52, 0x08, 0xa8, 0x1d, 0x97, 0xbc,
    0x4a, 0xcc, 0x6e, 0xbd, 0xc6, 0x1e, 0xb2, 0x71, 0xe1, 0xc3, 0xfd, 0xef, 0x60, 0xe7, 0x9f, 0xaa,
    0x87, 0x58, 0x49, 0x13, 0x77, 0xc8, 0x2c, 0x5c, 0x6d, 0x4f, 0x2d, 0x72
};

static bool isAscii(unsigned char* buf, int count)
{
    for (int i = 0; i < count; ++i)
    {
        if (buf[i] > 127) return false;
    }

    return true;
}

int main()
{
    BN_CTX* ctx = BN_CTX_new();
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    /* Construct point P, and get x,y coordinates */
    BigNum Px;
    BigNum Py;
    BN_hex2bn(&Px.pBN, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    BN_hex2bn(&Py.pBN, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    EcPoint P(group);
    EC_POINT_set_affine_coordinates(group, P.pECPoint, Px.pBN, Py.pBN, ctx);

    /* Construct point Q, and get x,y coordinates */
    BigNum Qx;
    BigNum Qy;
    BN_hex2bn(&Qx.pBN, "49394cc5234d0c7ff6cedb672eedcca25c766f85b99e8516849a238895dd4b5d");
    BN_hex2bn(&Qy.pBN, "2b4fcd02b54a921a42560703e8f255930acf2176fc30b998e3899dcdac1ad226");
    EcPoint Q(group);
    EC_POINT_set_affine_coordinates(group, Q.pECPoint, Qx.pBN, Qy.pBN, ctx);

    /* Construct other constants defined by puzzle: k, a, b, p, and t0 (the ciphertext) */
    BigNum k;
    BN_dec2bn(&k.pBN, "12113342872023565048219014074686803499776563817452241627720106650707428480409");

    BigNum t0;
    BN_hex2bn(&t0.pBN, "f4e5e316d9eaa9e49c443cc6e3a24772045177e2a8dd717cec0f091564da");

    BigNum a;
    BigNum b;
    BN_dec2bn(&a.pBN, "-3");
    BN_hex2bn(&b.pBN, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

    BigNum p;
    BN_dec2bn(&p.pBN, "115792089210356248762697446949407573530086143415290314195533631308867097853951");

    // First try to guess si * Q.We know all but(the top) 16 - bits of(siQ)x, so brute force those bits.
    // Iterate over all possible values of x
    for (uint32_t i = 0; i < 65536; ++i)
    {
        unsigned char plainText[61];
        memcpy(plainText, cipherText, 60);
        plainText[60] = '\0';   //null terminate the string for printing convenience

        // The most significant bits for this iteration.
        BigNum msbs;    
        msbs.pBN = BN_new();
        BN_set_word(msbs.pBN, i); 

        // shift the bits to the top
        BigNum msbs_after;  
        msbs_after.pBN = BN_new();
        BN_lshift(msbs_after.pBN, msbs.pBN, 240);

        BigNum x;
        x.pBN = BN_new();
        BN_add(x.pBN, msbs_after.pBN, t0.pBN);  // Add MSBs to t0

        // Compute y^2 = x^3 + ax + b
        // First compute x^3 through x^2 * x
        BigNum x2;
        x2.pBN = BN_new();
        BN_sqr(x2.pBN, x.pBN, ctx);

        BigNum x3;
        x3.pBN = BN_new();
        BN_mul(x3.pBN, x2.pBN, x.pBN, ctx);

        BigNum ax;
        ax.pBN = BN_new();
        BN_mul(ax.pBN, a.pBN, x.pBN, ctx); //ax

        // Sum up in parts
        BigNum partial;
        partial.pBN = BN_new();
        BN_add(partial.pBN, x3.pBN, ax.pBN);

        // sum up partial sums to get y^2
        BigNum y2;
        y2.pBN = BN_new();
        BN_add(y2.pBN, partial.pBN, b.pBN);

        // Use modular square root function to compute y
        BigNum y;
        y.pBN = BN_new();
        BN_mod_sqrt(y.pBN, y2.pBN, p.pBN, ctx);

        //NOW we do elliptic curve arithmetic
        EcPoint SiQ(group);
        if (0 == EC_POINT_set_affine_coordinates(group, SiQ.pECPoint, x.pBN, y.pBN, ctx))
        {
            // If we couldn't set the coordinates, this means they're not on the curve. Skip this one.
            continue;
        }

        // second round
        EcPoint SiP(group);
        EC_POINT_mul(group, SiP.pECPoint, NULL, SiQ.pECPoint, k.pBN, ctx);

        BigNum SiPx;
        BigNum SiPy;
        SiPx.pBN = BN_new();
        SiPy.pBN = BN_new();
        EC_POINT_get_affine_coordinates(group, SiP.pECPoint, SiPx.pBN, SiPy.pBN, ctx);

        EcPoint Rii(group);
        EC_POINT_mul(group, Rii.pECPoint, NULL, Q.pECPoint, SiPx.pBN, ctx);

        BigNum Riix;
        BigNum Riiy;
        Riix.pBN = BN_new();
        Riiy.pBN = BN_new();
        EC_POINT_get_affine_coordinates(group, Rii.pECPoint, Riix.pBN, Riiy.pBN, ctx);

        // output from the round
        BigNum roundOut1;
        roundOut1.pBN = BN_new();
        BN_copy(roundOut1.pBN, Riix.pBN);
        // Remove the 16 MSBs by manually clearing each one.
        for (int i = 0; i < 16; ++i)
        {
            BN_clear_bit(roundOut1.pBN, 255 - i);
        }

        // Decode the first 30 bytes, to see if this is readable.
        uint8_t pad[60];
        BN_bn2bin(roundOut1.pBN, pad);

        for (int i = 0; i < 30; ++i)
        {
            plainText[i] ^= pad[i];
        }

        // If the first 30 bytes are not ascii, move onto the next iteration.
        if (!isAscii(plainText, 30))
        {
            continue;
        }

        // Third round
        EcPoint SiiP(group);
        EC_POINT_mul(group, SiiP.pECPoint, NULL, P.pECPoint, SiPx.pBN, ctx);

        BigNum SiiPx;
        BigNum SiiPy;
        SiiPx.pBN = BN_new();
        SiiPy.pBN = BN_new();
        EC_POINT_get_affine_coordinates(group, SiiP.pECPoint, SiiPx.pBN, SiiPy.pBN, ctx);

        EcPoint Riii(group);
        EC_POINT_mul(group, Riii.pECPoint, NULL, Q.pECPoint, SiiPx.pBN, ctx);

        BigNum Riiix;
        BigNum Riiiy;
        Riiix.pBN = BN_new();
        Riiiy.pBN = BN_new();
        EC_POINT_get_affine_coordinates(group, Riii.pECPoint, Riiix.pBN, Riiiy.pBN, ctx);

        BigNum roundOut2;
        roundOut2.pBN = BN_new();
        BN_copy(roundOut2.pBN, Riiix.pBN);
        for (int i = 0; i < 16; ++i)
        {
            BN_clear_bit(roundOut2.pBN, 255 - i);
        }

        BN_bn2bin(roundOut2.pBN, &pad[30]);

        // Decode the second half
        for (int i = 30; i < 60; ++i)
        {
            plainText[i] ^= pad[i];
        }

        // If the second half is also ascii, then we've found the plaintext message.
        if (isAscii(&plainText[30], 30))
        {
            std::cout << plainText << std::endl;
            break;
        }
    }

    return 0;
}