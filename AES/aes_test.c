/* 
 * Peter Phe
 * TCSS 481 - Computer Security
 * Spring 2017
 * Encryption Schemes - AES Encryption
 * Filename: aes_test.c
 * Description: The program encrypts files in either CBC or CTR modes using AES.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/aes.h>

// helper to calculate time
float timedifference_msec(struct timeval t0, struct timeval t1)
{
    return (t1.tv_sec - t0.tv_sec) * 1000.0f + (t1.tv_usec - t0.tv_usec) / 1000.0f;
}

// entry point
int main(int argc, char *argv[])
{
    // a static key to test with 6D9C879AB85D3AEFD1F7218B496EFF1A
    const static unsigned char key[] = { 0x6D, 0x9C, 0x87, 0x9A, 0xB8, 0x5D, 0x3A, 0xEF,
        0xD1, 0xF7, 0x21, 0x8B, 0x49, 0x6E, 0xFF, 0x1A };

    // static IV to test with D1F7218B496EFF1A19832a1AC791498A
    unsigned char iv[] = { 0x2E, 0x51, 0xBC, 0x15, 0xF2, 0xA8, 0xAB, 0xA6,
        0x19, 0x83, 0x2a, 0x1A, 0xC7, 0x91, 0x49, 0x8A }; 

    // check if arguments are correctly structured
    if (argc < 2)
    {
        printf("Usage: ./aes_test filename\n");
        exit(1);
    }

    // try to open the file to read in
    FILE *infile = fopen(argv[1], "rb"); 
    if (infile == NULL)
    {
        printf("Error opening file!\n");
        exit(1);
    }

    // prep for encryption tests
    int bytesRead, bytesWritten;
    struct timeval start, end;
    AES_KEY enc_key;
    AES_set_encrypt_key(key, sizeof(key)*8, &enc_key);

    // temporary buffers for reading/writing
    unsigned char plaintext[AES_BLOCK_SIZE];
    unsigned char ciphertext[AES_BLOCK_SIZE];

    // write cipher to text file
    FILE *outfile = fopen("cbc_cipher.txt", "wb");
    if (outfile == NULL)
    {
        printf("Error opening file to write!\n");
        exit(1);
    }


    // [begin CBC mode]
    printf("Encrypting with AES in CBC mode:\n");
    gettimeofday(&start, NULL);

    for (;;)
    {
        bytesRead = fread(plaintext, 1, AES_BLOCK_SIZE, infile);
        AES_cbc_encrypt(plaintext, ciphertext, bytesRead, &enc_key, iv, AES_ENCRYPT);
        bytesWritten = fwrite(ciphertext, 1, bytesRead, outfile);

        if (bytesRead < AES_BLOCK_SIZE)
            break;
    }

    gettimeofday(&end, NULL);
    printf("Complete! Duration: %f ms\n\n", timedifference_msec(start, end));
    // [end CBC mode]

    // prepare output file for CTR mode
    fclose(outfile);
    outfile = fopen("ctr_cipher.txt", "wb");
    if (outfile == NULL)
    {
        printf("Error opening file to write!\n");
        exit(1);
    }

    // prep parameters for CTR mode
    unsigned int num = 0;
    unsigned char ecount[AES_BLOCK_SIZE];
    memset(plaintext, 0, AES_BLOCK_SIZE);
    memset(ciphertext, 0, AES_BLOCK_SIZE); // clear buffers
    memset(ecount, 0, AES_BLOCK_SIZE);
    rewind(infile);

    // [begin CTR mode]
    printf("Encrypting with AES in CTR mode:\n");
    gettimeofday(&start, NULL);

    for (;;)
    {
        bytesRead = fread(plaintext, 1, AES_BLOCK_SIZE, infile);
        AES_ctr128_encrypt(plaintext, ciphertext, AES_BLOCK_SIZE, &enc_key, iv, ecount, &num);
        bytesWritten = fwrite(ciphertext, 1, bytesRead, outfile);

        if (bytesRead < AES_BLOCK_SIZE)
            break;
    }

    gettimeofday(&end, NULL);
    printf("Complete! Duration: %f ms\n\n", timedifference_msec(start, end));
    // [end CTR mode]
    

    fclose(outfile);
    fclose(infile);

    return 0;
}

