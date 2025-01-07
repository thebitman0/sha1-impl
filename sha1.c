#include<stdio.h>
#include<stdint.h>
#include<string.h>

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20

#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define F1(b, c, d) ((b & c) | (~b & d))
#define F2(b, c, d) (b ^ c ^ d)
#define F3(b, c, d) ((b & c) | (b & d) | (c & d))
#define F4(b, c, d) (b ^ c ^ d)

typedef struct 
{
    uint32_t h0, h1, h2, h3, h4;
    uint32_t length_low, length_high;
    uint8_t buffer[SHA1_BLOCK_SIZE];
    uint32_t buffer_length;
} SHA1_CTX;

void SHA1_Init(SHA1_CTX *context) 
{
    context->h0 = 0x67452301;
    context->h1 = 0xEFCDAB89;
    context->h2 = 0x98BADCFE;
    context->h3 = 0x10325476;
    context->h4 = 0xC3D2E1F0;

    context->length_low = 0;
    context->length_high = 0;
    context->buffer_length = 0;
}


void SHA1_Transform(SHA1_CTX *context, const uint8_t *data) 
{
    uint32_t a, b, c, d, e, f, k, temp;
    uint32_t w[80];
    int t;
    
    for (t = 0; t < 16; t++) 
    {
        w[t] = (data[t * 4] << 24) | (data[t * 4 + 1] << 16) |
               (data[t * 4 + 2] << 8) | (data[t * 4 + 3]);
    }
    for (t = 16; t < 80; t++) 
    {
        w[t] = ROTLEFT(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }

    a = context->h0;
    b = context->h1;
    c = context->h2;
    d = context->h3;
    e = context->h4;
    
    for (t = 0; t < 80; t++) 
    {
        if (t < 20) 
        {
            f = F1(b, c, d);
            k = 0x5A827999;
        } 
        else if (t < 40) 
        {
            f = F2(b, c, d);
            k = 0x6ED9EBA1;
        } 
        else if (t < 60) 
        {
            f = F3(b, c, d);
            k = 0x8F1BBCDC;
        } 
        else 
        {
            f = F4(b, c, d);
            k = 0xCA62C1D6;
        }

        temp = ROTLEFT(a, 5) + f + e + k + w[t];
        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = temp;
    }

    context->h0 += a;
    context->h1 += b;
    context->h2 += c;
    context->h3 += d;
    context->h4 += e;
}


void SHA1_Update(SHA1_CTX *context, const uint8_t *data, size_t len) 
{
    size_t i;
    context->length_low += len * 8;
    if (context->length_low < len * 8) 
    {
        context->length_high++;
    }
    context->length_high += len >> 29;

    while (len--) 
    {
        context->buffer[context->buffer_length++] = *data++;
        if (context->buffer_length == SHA1_BLOCK_SIZE) 
        {
            SHA1_Transform(context, context->buffer);
            context->buffer_length = 0;
        }
    }
}


void SHA1_Final(SHA1_CTX *context, uint8_t *digest) 
{
    uint8_t padding[SHA1_BLOCK_SIZE] = 
    {0x80};
    size_t padding_size = (context->buffer_length < 56) ? (56 - context->buffer_length) : (120 - context->buffer_length);
    
    SHA1_Update(context, padding, padding_size);
    
    uint32_t length[2] = 
    {context->length_high, context->length_low};
    SHA1_Update(context, (uint8_t *)length, 8);
    
    digest[0] = (context->h0 >> 24) & 0xFF;
    digest[1] = (context->h0 >> 16) & 0xFF;
    digest[2] = (context->h0 >> 8) & 0xFF;
    digest[3] = context->h0 & 0xFF;

    digest[4] = (context->h1 >> 24) & 0xFF;
    digest[5] = (context->h1 >> 16) & 0xFF;
    digest[6] = (context->h1 >> 8) & 0xFF;
    digest[7] = context->h1 & 0xFF;

    digest[8] = (context->h2 >> 24) & 0xFF;
    digest[9] = (context->h2 >> 16) & 0xFF;
    digest[10] = (context->h2 >> 8) & 0xFF;
    digest[11] = context->h2 & 0xFF;

    digest[12] = (context->h3 >> 24) & 0xFF;
    digest[13] = (context->h3 >> 16) & 0xFF;
    digest[14] = (context->h3 >> 8) & 0xFF;
    digest[15] = context->h3 & 0xFF;

    digest[16] = (context->h4 >> 24) & 0xFF;
    digest[17] = (context->h4 >> 16) & 0xFF;
    digest[18] = (context->h4 >> 8) & 0xFF;
    digest[19] = context->h4 & 0xFF;
}


void print_sha1_hash(uint8_t *digest) 
{
    for (int i = 0; i < SHA1_DIGEST_SIZE; i++) 
    {
        printf("%02x", digest[i]);
    }
    printf("\n");
}
