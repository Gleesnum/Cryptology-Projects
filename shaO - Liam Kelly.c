/* sha.c
 * Yongge Wang 
 *
 * Code was written: November 12, 2016-November 26, 2016
 *
 * EDITED BY LIAM KELLY STARTING 9.21.2024
 * 
 * sha.c implements SHA-1 (SHA-160), SHA256, and SHA512 for RLCE
 *
 * This code is for prototype purpose only and is not optimized
 *
 * Copyright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

#define ROTL512(a,b) (((a) << (b)) | ((a) >> (64-(b))))
#define ROTR512(a,b) (((a) >> (b)) | ((a) << (64-(b))))
#define sigma5120(x) (ROTR512(x,1) ^ ROTR512(x,8) ^ ((x) >> 7))
#define sigma5121(x) (ROTR512(x,19) ^ ROTR512(x,61) ^ ((x) >> 6))
#define Sigma5120(x) (ROTR512(x,28) ^ ROTR512(x,34) ^ ROTR512(x,39))
#define Sigma5121(x) (ROTR512(x,14) ^ ROTR512(x,18) ^ ROTR512(x,41))

void sha1_process(unsigned int[], unsigned char[]);
void sha256_process(unsigned int[], unsigned char[]);
void sha512_process(unsigned long [], unsigned char []);
int testSHA(int shatype, int numT);

int main (int argc, char *argv[]) {
  int numofT=100;
  testSHA(1,numofT);
  testSHA(2,numofT);
  testSHA(3,numofT);
  exit(0);
}


void sha_msg_pad(unsigned char message[], int size, unsigned int bitlen,
		 unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<size; i++) {
    paddedmsg[i]=message[i];
  }
  paddedmsg[size]= 0x80;
  for (i=size+1; i<64; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[63] = bitlen;
  paddedmsg[62] = bitlen >> 8;
  paddedmsg[61] = bitlen >> 16;
  paddedmsg[60] = bitlen >> 24;
  return;
}

void sha_msg_pad0(unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<64; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[63] = bitlen;
  paddedmsg[62] = bitlen >> 8;
  paddedmsg[61] = bitlen >> 16;
  paddedmsg[60] = bitlen >> 24;
  return;
}

void sha1_md(unsigned char message[], int size, unsigned int hash[5]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x67452301;
  hash[1] = 0xEFCDAB89;
  hash[2] = 0x98BADCFE;
  hash[3] = 0x10325476;
  hash[4] = 0xC3D2E1F0;
  int i;

  unsigned char msgTBH[64]; /* 64 BYTE msg to be hashed */
  unsigned char paddedMessage[64]; /* last msg block to be hashed*/

  int Q= size/64;
  int R= size%64;
  unsigned char msg[R];
  memcpy(msg, &message[64*Q], R * sizeof(unsigned char));
  
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[64*i], 64 * sizeof(unsigned char));
    sha1_process(hash, msgTBH);
  }
  if (R>55) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<64; i++) {
      msgTBH[i]=0x00;
    } 
    sha1_process(hash, msgTBH);
    sha_msg_pad0(bitlen,paddedMessage);
  } else {
    sha_msg_pad(msg, R, bitlen, paddedMessage);
  }
  sha1_process(hash, paddedMessage);
  return;
}

void sha1_process(unsigned int hash[], unsigned char msg[]) {
  const unsigned int K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
  unsigned int W[80];
  unsigned int A, B, C, D, E, T;
  int i;
  //for(i = 0; i < 16; i++) {
    //W[i] = (((unsigned) msg[i * 4]) << 24) +
      //(((unsigned) msg[i * 4 + 1]) << 16) +
      //(((unsigned) msg[i * 4 + 2]) << 8) +
    //  (((unsigned) msg[i * 4 + 3]));
  //}
  // Ths for loop can be hardcoded 
  W[0] =  (((unsigned) msg[0]) << 24)  + (((unsigned) msg[1]) << 16)  + (((unsigned) msg[2]) << 8)  + (((unsigned) msg[3]));
  W[1] =  (((unsigned) msg[4]) << 24)  + (((unsigned) msg[5]) << 16)  + (((unsigned) msg[6]) << 8)  + (((unsigned) msg[7]));  
  W[2] =  (((unsigned) msg[8]) << 24)  + (((unsigned) msg[9]) << 16)  + (((unsigned) msg[10]) << 8) + (((unsigned) msg[11]));
  W[3] =  (((unsigned) msg[12]) << 24) + (((unsigned) msg[13]) << 16) + (((unsigned) msg[14]) << 8) + (((unsigned) msg[15]));
  W[4] =  (((unsigned) msg[16]) << 24) + (((unsigned) msg[17]) << 16) + (((unsigned) msg[18]) << 8) + (((unsigned) msg[19]));
  W[5] =  (((unsigned) msg[20]) << 24) + (((unsigned) msg[21]) << 16) + (((unsigned) msg[22]) << 8) + (((unsigned) msg[23]));
  W[6] =  (((unsigned) msg[24]) << 24) + (((unsigned) msg[25]) << 16) + (((unsigned) msg[26]) << 8) + (((unsigned) msg[27]));
  W[7] =  (((unsigned) msg[28]) << 24) + (((unsigned) msg[29]) << 16) + (((unsigned) msg[30]) << 8) + (((unsigned) msg[31]));
  W[8] =  (((unsigned) msg[32]) << 24) + (((unsigned) msg[33]) << 16) + (((unsigned) msg[34]) << 8) + (((unsigned) msg[35]));
  W[9] =  (((unsigned) msg[36]) << 24) + (((unsigned) msg[37]) << 16) + (((unsigned) msg[38]) << 8) + (((unsigned) msg[39]));
  W[10] = (((unsigned) msg[40]) << 24) + (((unsigned) msg[41]) << 16) + (((unsigned) msg[42]) << 8) + (((unsigned) msg[43]));
  W[11] = (((unsigned) msg[44]) << 24) + (((unsigned) msg[45]) << 16) + (((unsigned) msg[46]) << 8) + (((unsigned) msg[47]));
  W[12] = (((unsigned) msg[48]) << 24) + (((unsigned) msg[49]) << 16) + (((unsigned) msg[50]) << 8) + (((unsigned) msg[51]));
  W[13] = (((unsigned) msg[52]) << 24) + (((unsigned) msg[53]) << 16) + (((unsigned) msg[54]) << 8) + (((unsigned) msg[55]));
  W[14] = (((unsigned) msg[56]) << 24) + (((unsigned) msg[57]) << 16) + (((unsigned) msg[58]) << 8) + (((unsigned) msg[59]));
  W[15] = (((unsigned) msg[60]) << 24) + (((unsigned) msg[61]) << 16) + (((unsigned) msg[62]) << 8) + (((unsigned) msg[63]));


//   for(i = 16; i < 80; i++) {
//     W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
//     W[i] = ROTL(W[i],1);
//   }
    W[16] = W[13] ^ W[8] ^ W[2] ^ W[0];
    W[16] = ROTL(W[16],1);
    W[17] = W[14] ^ W[9] ^ W[3] ^ W[1];
    W[17] = ROTL(W[17], 1);
    W[18] = W[15] ^ W[10] ^ W[4] ^ W[2];
    W[18] = ROTL(W[18], 1);
    W[19] = W[16] ^ W[11] ^ W[5] ^ W[3];
    W[19] = ROTL(W[19], 1);
    W[20] = W[17] ^ W[12] ^ W[6] ^ W[4];
    W[20] = ROTL(W[20], 1);
    W[21] = W[18] ^ W[13] ^ W[7] ^ W[5];
    W[21] = ROTL(W[21], 1);
    W[22] = W[19] ^ W[14] ^ W[8] ^ W[6];
    W[22] = ROTL(W[22], 1);
    W[23] = W[20] ^ W[15] ^ W[9] ^ W[7];
    W[23] = ROTL(W[23], 1);
    W[24] = W[21] ^ W[16] ^ W[10] ^ W[8];
    W[24] = ROTL(W[24], 1);
    W[25] = W[22] ^ W[17] ^ W[11] ^ W[9];
    W[25] = ROTL(W[25], 1);
    W[26] = W[23] ^ W[18] ^ W[12] ^ W[10];
    W[26] = ROTL(W[26], 1);
    W[27] = W[24] ^ W[19] ^ W[13] ^ W[11];
    W[27] = ROTL(W[27], 1);
    W[28] = W[25] ^ W[20] ^ W[14] ^ W[12];
    W[28] = ROTL(W[28], 1);
    W[29] = W[26] ^ W[21] ^ W[15] ^ W[13];
    W[29] = ROTL(W[29], 1);
    W[30] = W[27] ^ W[22] ^ W[16] ^ W[14];
    W[30] = ROTL(W[30], 1);
    W[31] = W[28] ^ W[23] ^ W[17] ^ W[15];
    W[31] = ROTL(W[31], 1);
    W[32] = W[29] ^ W[24] ^ W[18] ^ W[16];
    W[32] = ROTL(W[32], 1);
    W[33] = W[30] ^ W[25] ^ W[19] ^ W[17];
    W[33] = ROTL(W[33], 1);
    W[34] = W[31] ^ W[26] ^ W[20] ^ W[18];
    W[34] = ROTL(W[34], 1);
    W[35] = W[32] ^ W[27] ^ W[21] ^ W[19];
    W[35] = ROTL(W[35], 1);
    W[36] = W[33] ^ W[28] ^ W[22] ^ W[20];
    W[36] = ROTL(W[36], 1);
    W[37] = W[34] ^ W[29] ^ W[23] ^ W[21];
    W[37] = ROTL(W[37], 1);
    W[38] = W[35] ^ W[30] ^ W[24] ^ W[22];
    W[38] = ROTL(W[38], 1);
    W[39] = W[36] ^ W[31] ^ W[25] ^ W[23];
    W[39] = ROTL(W[39], 1);
    W[40] = W[37] ^ W[32] ^ W[26] ^ W[24];
    W[40] = ROTL(W[40], 1);
    W[41] = W[38] ^ W[33] ^ W[27] ^ W[25];
    W[41] = ROTL(W[41], 1);
    W[42] = W[39] ^ W[34] ^ W[28] ^ W[26];
    W[42] = ROTL(W[42], 1);
    W[43] = W[40] ^ W[35] ^ W[29] ^ W[27];
    W[43] = ROTL(W[43], 1);
    W[44] = W[41] ^ W[36] ^ W[30] ^ W[28];
    W[44] = ROTL(W[44], 1);
    W[45] = W[42] ^ W[37] ^ W[31] ^ W[29];
    W[45] = ROTL(W[45], 1);
    W[46] = W[43] ^ W[38] ^ W[32] ^ W[30];
    W[46] = ROTL(W[46], 1);
    W[47] = W[44] ^ W[39] ^ W[33] ^ W[31];
    W[47] = ROTL(W[47], 1);
    W[48] = W[45] ^ W[40] ^ W[34] ^ W[32];
    W[48] = ROTL(W[48], 1);
    W[49] = W[46] ^ W[41] ^ W[35] ^ W[33];
    W[49] = ROTL(W[49], 1);
    W[50] = W[47] ^ W[42] ^ W[36] ^ W[34];
    W[50] = ROTL(W[50], 1);
    W[51] = W[48] ^ W[43] ^ W[37] ^ W[35];
    W[51] = ROTL(W[51], 1);
    W[52] = W[49] ^ W[44] ^ W[38] ^ W[36];
    W[52] = ROTL(W[52], 1);
    W[53] = W[50] ^ W[45] ^ W[39] ^ W[37];
    W[53] = ROTL(W[53], 1);
    W[54] = W[51] ^ W[46] ^ W[40] ^ W[38];
    W[54] = ROTL(W[54], 1);
    W[55] = W[52] ^ W[47] ^ W[41] ^ W[39];
    W[55] = ROTL(W[55], 1);
    W[56] = W[53] ^ W[48] ^ W[42] ^ W[40];
    W[56] = ROTL(W[56], 1);
    W[57] = W[54] ^ W[49] ^ W[43] ^ W[41];
    W[57] = ROTL(W[57], 1);
    W[58] = W[55] ^ W[50] ^ W[44] ^ W[42];
    W[58] = ROTL(W[58], 1);
    W[59] = W[56] ^ W[51] ^ W[45] ^ W[43];
    W[59] = ROTL(W[59], 1);
    W[60] = W[57] ^ W[52] ^ W[46] ^ W[44];
    W[60] = ROTL(W[60], 1);
    W[61] = W[58] ^ W[53] ^ W[47] ^ W[45];
    W[61] = ROTL(W[61], 1);
    W[62] = W[59] ^ W[54] ^ W[48] ^ W[46];
    W[62] = ROTL(W[62], 1);
    W[63] = W[60] ^ W[55] ^ W[49] ^ W[47];
    W[63] = ROTL(W[63], 1);
    W[64] = W[61] ^ W[56] ^ W[50] ^ W[48];
    W[64] = ROTL(W[64], 1);
    W[65] = W[62] ^ W[57] ^ W[51] ^ W[49];
    W[65] = ROTL(W[65], 1);
    W[66] = W[63] ^ W[58] ^ W[52] ^ W[50];
    W[66] = ROTL(W[66], 1);
    W[67] = W[64] ^ W[59] ^ W[53] ^ W[51];
    W[67] = ROTL(W[67], 1);
    W[68] = W[65] ^ W[60] ^ W[54] ^ W[52];
    W[68] = ROTL(W[68], 1);
    W[69] = W[66] ^ W[61] ^ W[55] ^ W[53];
    W[69] = ROTL(W[69], 1);
    W[70] = W[67] ^ W[62] ^ W[56] ^ W[54];
    W[70] = ROTL(W[70], 1);
    W[71] = W[68] ^ W[63] ^ W[57] ^ W[55];
    W[71] = ROTL(W[71], 1);
    W[72] = W[69] ^ W[64] ^ W[58] ^ W[56];
    W[72] = ROTL(W[72], 1);
    W[73] = W[70] ^ W[65] ^ W[59] ^ W[57];
    W[73] = ROTL(W[73], 1);
    W[74] = W[71] ^ W[66] ^ W[60] ^ W[58];
    W[74] = ROTL(W[74], 1);
    W[75] = W[72] ^ W[67] ^ W[61] ^ W[59];
    W[75] = ROTL(W[75], 1);
    W[76] = W[73] ^ W[68] ^ W[62] ^ W[60];
    W[76] = ROTL(W[76], 1);
    W[77] = W[74] ^ W[69] ^ W[63] ^ W[61];
    W[77] = ROTL(W[77], 1);
    W[78] = W[75] ^ W[70] ^ W[64] ^ W[62];
    W[78] = ROTL(W[78], 1);
    W[79] = W[76] ^ W[71] ^ W[65] ^ W[63];
    W[79] = ROTL(W[79], 1);
    W[80] = W[77] ^ W[72] ^ W[66] ^ W[64];
    W[80] = ROTL(W[80], 1);

  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];

  for(i = 0; i < 20; i++) {
    T = ROTL(A,5) + ((B & C) ^ ((~B) & D)) + E + W[i] + K[0];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
  }
  for(i = 20; i < 40; i++) {
    T = ROTL(A,5) + (B^C^D) + E + W[i] + K[1];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
  }
  for(i = 40; i < 60; i++) {
    T = ROTL(A,5) + ((B & C) ^ (B & D) ^ (C & D)) + E + W[i] + K[2];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
  }
  for(i = 60; i < 80; i++) {
    T = ROTL(A,5) + (B ^ C ^ D) + E + W[i] + K[3];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = T;
    /* printf("%d: %x %x %x %x %x\n",i, A, B, C, D, E); */
  }

  hash[0] +=  A;
  hash[1] +=  B;
  hash[2] +=  C;
  hash[3] +=  D;
  hash[4] +=  E;
  return;
}

void sha256_md(unsigned char message[], int size, unsigned int hash[8]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x6A09E667;  
  hash[1] = 0xBB67AE85;
  hash[2] = 0x3C6EF372;  
  hash[3] = 0xA54FF53A;  
  hash[4] = 0x510E527F;
  hash[5] = 0x9B05688C;
  hash[6] = 0x1F83D9AB;
  hash[7] = 0x5BE0CD19;
  
  unsigned char msgTBH[64]; /* 64 BYTE msg to be hashed */
  unsigned char paddedMessage[64]; /* last msg block to be hashed*/
  int i;
  int Q= size/64;
  int R= size%64;
  unsigned char msg[R];
  memcpy(msg, &message[64*Q], R * sizeof(unsigned char));
  
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[64*i], 64 * sizeof(unsigned char));
    sha256_process(hash, msgTBH);
  }
  if (R>55) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<64; i++) {
      msgTBH[i]=0x00;
    }
    sha256_process(hash, msgTBH);
    sha_msg_pad0(bitlen,paddedMessage);
  } else {
    sha_msg_pad(msg, R, bitlen, paddedMessage);
  }
 
  sha256_process(hash, paddedMessage);
  return;
}

void sha256_process(unsigned int hash[], unsigned char msg[]) {
  const unsigned int K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
  unsigned int W[64];
  int i;
  unsigned int A, B, C, D, E, F, G, H, T1, T2;
  //for(i = 0; i < 16; i++) {
    //W[i] = (((unsigned) msg[i * 4]) << 24) +
      //(((unsigned) msg[i * 4 + 1]) << 16) +
      //(((unsigned) msg[i * 4 + 2]) << 8) +
    //  (((unsigned) msg[i * 4 + 3]));
  //}
  // Ths for loop can be hardcoded (same as previous function)
  W[0] =  (((unsigned) msg[0]) << 24)  + (((unsigned) msg[1]) << 16)  + (((unsigned) msg[2]) << 8)  + (((unsigned) msg[3]));
  W[1] =  (((unsigned) msg[4]) << 24)  + (((unsigned) msg[5]) << 16)  + (((unsigned) msg[6]) << 8)  + (((unsigned) msg[7]));  
  W[2] =  (((unsigned) msg[8]) << 24)  + (((unsigned) msg[9]) << 16)  + (((unsigned) msg[10]) << 8) + (((unsigned) msg[11]));
  W[3] =  (((unsigned) msg[12]) << 24) + (((unsigned) msg[13]) << 16) + (((unsigned) msg[14]) << 8) + (((unsigned) msg[15]));
  W[4] =  (((unsigned) msg[16]) << 24) + (((unsigned) msg[17]) << 16) + (((unsigned) msg[18]) << 8) + (((unsigned) msg[19]));
  W[5] =  (((unsigned) msg[20]) << 24) + (((unsigned) msg[21]) << 16) + (((unsigned) msg[22]) << 8) + (((unsigned) msg[23]));
  W[6] =  (((unsigned) msg[24]) << 24) + (((unsigned) msg[25]) << 16) + (((unsigned) msg[26]) << 8) + (((unsigned) msg[27]));
  W[7] =  (((unsigned) msg[28]) << 24) + (((unsigned) msg[29]) << 16) + (((unsigned) msg[30]) << 8) + (((unsigned) msg[31]));
  W[8] =  (((unsigned) msg[32]) << 24) + (((unsigned) msg[33]) << 16) + (((unsigned) msg[34]) << 8) + (((unsigned) msg[35]));
  W[9] =  (((unsigned) msg[36]) << 24) + (((unsigned) msg[37]) << 16) + (((unsigned) msg[38]) << 8) + (((unsigned) msg[39]));
  W[10] = (((unsigned) msg[40]) << 24) + (((unsigned) msg[41]) << 16) + (((unsigned) msg[42]) << 8) + (((unsigned) msg[43]));
  W[11] = (((unsigned) msg[44]) << 24) + (((unsigned) msg[45]) << 16) + (((unsigned) msg[46]) << 8) + (((unsigned) msg[47]));
  W[12] = (((unsigned) msg[48]) << 24) + (((unsigned) msg[49]) << 16) + (((unsigned) msg[50]) << 8) + (((unsigned) msg[51]));
  W[13] = (((unsigned) msg[52]) << 24) + (((unsigned) msg[53]) << 16) + (((unsigned) msg[54]) << 8) + (((unsigned) msg[55]));
  W[14] = (((unsigned) msg[56]) << 24) + (((unsigned) msg[57]) << 16) + (((unsigned) msg[58]) << 8) + (((unsigned) msg[59]));
  W[15] = (((unsigned) msg[60]) << 24) + (((unsigned) msg[61]) << 16) + (((unsigned) msg[62]) << 8) + (((unsigned) msg[63]));

//   for(i = 16; i < 64; i++) {
//     W[i] = sigma1(W[i-2])+W[i-7]+sigma0(W[i-15])+ W[i-16];
//   }
//Hardcode this for loop as well
  W[16] = sigma1(W[14])+W[9]+sigma0(W[1])  + W[0];
  W[17] = sigma1(W[15])+W[10]+sigma0(W[2]) + W[1];
  W[18] = sigma1(W[16])+W[11]+sigma0(W[3]) + W[2];
  W[19] = sigma1(W[17])+W[12]+sigma0(W[4]) + W[3];
  W[20] = sigma1(W[18])+W[13]+sigma0(W[5]) + W[4];
  W[21] = sigma1(W[19])+W[14]+sigma0(W[6]) + W[5];
  W[22] = sigma1(W[20])+W[15]+sigma0(W[7]) + W[6];
  W[23] = sigma1(W[21])+W[16]+sigma0(W[8]) + W[7];
  W[24] = sigma1(W[22])+W[17]+sigma0(W[9]) + W[8];
  W[25] = sigma1(W[23])+W[18]+sigma0(W[10])+ W[9];
  W[26] = sigma1(W[24])+W[19]+sigma0(W[11])+ W[10];
  W[27] = sigma1(W[25])+W[20]+sigma0(W[12])+ W[11];
  W[28] = sigma1(W[26])+W[21]+sigma0(W[13])+ W[12];
  W[29] = sigma1(W[27])+W[22]+sigma0(W[14])+ W[13];
  W[30] = sigma1(W[28])+W[23]+sigma0(W[15])+ W[14];
  W[31] = sigma1(W[29])+W[24]+sigma0(W[16])+ W[15];
  W[32] = sigma1(W[30])+W[25]+sigma0(W[17])+ W[16];
  W[33] = sigma1(W[31])+W[26]+sigma0(W[18])+ W[17];
  W[34] = sigma1(W[32])+W[27]+sigma0(W[19])+ W[18];
  W[35] = sigma1(W[33])+W[28]+sigma0(W[20])+ W[19];
  W[36] = sigma1(W[34])+W[29]+sigma0(W[21])+ W[20];
  W[37] = sigma1(W[35])+W[30]+sigma0(W[22])+ W[21];
  W[38] = sigma1(W[36])+W[31]+sigma0(W[23])+ W[22];
  W[39] = sigma1(W[37])+W[32]+sigma0(W[24])+ W[23];
  W[40] = sigma1(W[38])+W[33]+sigma0(W[25])+ W[24];
  W[41] = sigma1(W[39])+W[34]+sigma0(W[26])+ W[25];
  W[42] = sigma1(W[40])+W[35]+sigma0(W[27])+ W[26];
  W[43] = sigma1(W[41])+W[36]+sigma0(W[28])+ W[27];
  W[44] = sigma1(W[42])+W[37]+sigma0(W[29])+ W[28];
  W[45] = sigma1(W[43])+W[38]+sigma0(W[30])+ W[29];
  W[46] = sigma1(W[44])+W[39]+sigma0(W[31])+ W[30];
  W[47] = sigma1(W[45])+W[40]+sigma0(W[32])+ W[31];
  W[48] = sigma1(W[46])+W[41]+sigma0(W[33])+ W[32];
  W[49] = sigma1(W[47])+W[42]+sigma0(W[34])+ W[33];
  W[50] = sigma1(W[48])+W[43]+sigma0(W[35])+ W[34];
  W[51] = sigma1(W[49])+W[44]+sigma0(W[36])+ W[35];
  W[52] = sigma1(W[50])+W[45]+sigma0(W[37])+ W[36];
  W[53] = sigma1(W[51])+W[46]+sigma0(W[38])+ W[37];
  W[54] = sigma1(W[52])+W[47]+sigma0(W[39])+ W[38];
  W[55] = sigma1(W[53])+W[48]+sigma0(W[40])+ W[39];
  W[56] = sigma1(W[54])+W[49]+sigma0(W[41])+ W[40];
  W[57] = sigma1(W[55])+W[50]+sigma0(W[42])+ W[41];
  W[58] = sigma1(W[56])+W[51]+sigma0(W[43])+ W[42];
  W[59] = sigma1(W[57])+W[52]+sigma0(W[44])+ W[43];
  W[60] = sigma1(W[58])+W[53]+sigma0(W[45])+ W[44];
  W[61] = sigma1(W[59])+W[54]+sigma0(W[46])+ W[45];
  W[62] = sigma1(W[60])+W[55]+sigma0(W[47])+ W[46];
  W[63] = sigma1(W[61])+W[56]+sigma0(W[48])+ W[47];

  
  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];
  F = hash[5];
  G = hash[6];
  H = hash[7];

  for (i = 0; i < 64; ++i) {
    T1 = H + Sigma1(E) + CH(E,F,G) + K[i] + W[i];
    T2 = Sigma0(A) + MAJ(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + T1;
    D = C;
    C = B;
    B = A;
    A = T1 + T2;
  }
  
  hash[0] +=A;
  hash[1] +=B;
  hash[2] +=C;
  hash[3] +=D;
  hash[4] +=E;
  hash[5] +=F;
  hash[6] +=G;
  hash[7] +=H;
  return;
}


void sha512_msg_pad(unsigned char message[], int size, unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<size; i++) {
    paddedmsg[i]=message[i];
  }
  paddedmsg[size]= 0x80;
  for (i=size+1; i<128; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[127] = bitlen;
  paddedmsg[126] = bitlen >> 8;
  paddedmsg[125] = bitlen >> 16;
  paddedmsg[124] = bitlen >> 24;
  return;
}

void sha512_msg_pad0(unsigned int bitlen, unsigned char paddedmsg[]) {
  int i;
  for (i=0; i<128; i++) {
    paddedmsg[i]=0x00;
  }
  paddedmsg[127] = bitlen;
  paddedmsg[126] = bitlen >> 8;
  paddedmsg[125] = bitlen >> 16;
  paddedmsg[124] = bitlen >> 24;
  return;
}


void sha512_md(unsigned char message[], int size, unsigned long hash[8]) {
  unsigned int bitlen = 8*size;
  hash[0] = 0x6a09e667f3bcc908;
  hash[1] = 0xbb67ae8584caa73b;
  hash[2] = 0x3c6ef372fe94f82b;
  hash[3] = 0xa54ff53a5f1d36f1;
  hash[4] = 0x510e527fade682d1;
  hash[5] = 0x9b05688c2b3e6c1f;
  hash[6] = 0x1f83d9abfb41bd6b;
  hash[7] = 0x5be0cd19137e2179;
  
  unsigned char msgTBH[128]; /* 128 BYTE msg to be hashed */
  unsigned char paddedMessage[128]; /* last msg block to be hashed*/
  
  int Q= size/128;
  int R= size%128;
  unsigned char msg[R];
  memcpy(msg, &message[128*Q], R * sizeof(unsigned char));
  int i;
  for (i=0; i<Q; i++) {
    memcpy(msgTBH, &message[128*i], 128 * sizeof(unsigned char));
    sha512_process(hash, msgTBH);
  }
  if (R>111) {
    memcpy(msgTBH, msg, R * sizeof(unsigned char));
    msgTBH[R]=0x80;
    for (i=R+1; i<128; i++) {
      msgTBH[i]=0x00;
    }
    sha512_process(hash, msgTBH);
    sha512_msg_pad0(bitlen,paddedMessage);
  } else {
    sha512_msg_pad(msg, R, bitlen, paddedMessage);
  }
 
  sha512_process(hash, paddedMessage);
  return;
}

void sha512_process(unsigned long hash[], unsigned char msg[]) {
  const unsigned long K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
  int i;
  unsigned long W[80];
  unsigned long A, B, C, D, E, F, G, H, T1, T2;
  for(i = 0; i < 16; i++) {
    W[i] = (((unsigned long) msg[i * 8])<< 56) |
      (((unsigned long) msg[i * 8 + 1]) << 48) |
      (((unsigned long) msg[i * 8 + 2]) << 40) | 
      (((unsigned long) msg[i * 8 + 3]) << 32) |
      (((unsigned long) msg[i * 8 + 4]) << 24) |
      (((unsigned long) msg[i * 8 + 5]) << 16) | 
      (((unsigned long) msg[i * 8 + 6]) << 8)  |
      (((unsigned long) msg[i * 8 + 7]));
  }
  for(i = 16; i < 80; i++) {
    W[i] = sigma5121(W[i-2])+W[i-7]+sigma5120(W[i-15])+ W[i-16];
  }
  A = hash[0];
  B = hash[1];
  C = hash[2];
  D = hash[3];
  E = hash[4];
  F = hash[5];
  G = hash[6];
  H = hash[7];

  for (i = 0; i < 80; ++i) {
    T1 = H + Sigma5121(E) + CH(E,F,G) + K[i] + W[i];
    T2 = Sigma5120(A) + MAJ(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + T1;
    D = C;
    C = B;
    B = A;
    A = T1 + T2;
  }
  
  hash[0] +=A;
  hash[1] +=B;
  hash[2] +=C;
  hash[3] +=D;
  hash[4] +=E;
  hash[5] +=F;
  hash[6] +=G;
  hash[7] +=H;
  return;
}


int testSHA(int shatype, int numT){
  //you should not make any changes to this function. Any modification to this function
  //is considered a violaiton of the academic integrity
  unsigned int hash1[5];
  unsigned int hash2[8];
  unsigned long hash3[8];
  int size=3, i;
  clock_t start, finish;
  double seconds;
  static unsigned char msg4[1000000];
  for (i=0; i<1000000; i++)  msg4[i]='a';
  size=1000000;
  
  if (shatype==1) {
    sha1_md(msg4, size, hash1);
    if ((hash1[0] !=0x34aa973c)||(hash1[1]!=0xd4c4daa4)||(hash1[2]!=0xf61eeb2b)
	||(hash1[3]!=0xdbad2731)||(hash1[4]!=0x6534016f)) {
      printf("SHA-1 failed\n");
      return 1;
    } else {
      start = clock();
      for (i=0;i<numT;i++) sha1_md(msg4, size, hash1);
      finish = clock();
      seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
      printf("%f seconds for %d times of SHA-1\n",seconds,numT);
    }
  }
  
  if (shatype==2) {
    sha256_md(msg4, size,hash2);
    if ((hash2[0] != 0xcdc76e5c)||(hash2[1]!=0x9914fb92)||(hash2[2]!=0x81a1c7e2)
      ||(hash2[3]!=0x84d73e67)||(hash2[4]!=0xf1809a48)||(hash2[5]!=0xa497200e)
	||(hash2[6]!=0x046d39cc)||(hash2[7]!=0xc7112cd0)) {
      printf("SHA-1 failed\n");
      return 1;
    } else {
      start = clock();
      for (i=0;i<numT;i++) sha256_md(msg4, size,hash2);
      finish = clock();
      seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
      printf("%f seconds for %d times of SHA-256\n",seconds,numT);
    }
  }
  
  if (shatype==3) {
    sha512_md(msg4, size,hash3);
    if ((hash3[0] != 0xe718483d0ce76964)||(hash3[1]!=0x4e2e42c7bc15b463)||(hash3[2]!=0x8e1f98b13b204428)
      ||(hash3[3]!=0x5632a803afa973eb)||(hash3[4]!=0xde0ff244877ea60a)||(hash3[5]!=0x4cb0432ce577c31b)
	||(hash3[6]!=0xeb009c5c2c49aa2e)||(hash3[7]!=0x4eadb217ad8cc09b)) {
      printf("SHA-1 failed\n");
      return 1;
    } else {
      start = clock();
      for (i=0;i<numT;i++) sha512_md(msg4, size,hash3);
      finish = clock();
      seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
      printf("%f seconds for %d times of SHA-512\n",seconds,numT);
    }
  }
  return 0;
}
