#!/usr/bin/env python
__author__ = 'Parth'

# Homework Number: 3
# Name: Parth Patel
# ECN Login: patel344
# Due Date: February 9, 2017

from BitVector import BitVector

AES_modulus = BitVector(bitstring='100011011')

subBytesTable = []
invSubBytesTable = []

def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal=i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable, invSubBytesTable


def get_encryption_key():
    FILEIN = open("key.txt", 'r')
    key = FILEIN.read()
    key = BitVector(textstring=key)
    FILEIN.close()
    return key


def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable


def gee(keyword, round_num_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size=0)
    for i in range(4):
        newword += BitVector(intVal=byte_sub_table[rotated_word[8 * i:8 * i + 8].intValue()], size=8)
    newword[:8] ^= round_num_constant
    round_num_constant = round_num_constant.gf_multiply_modular(BitVector(intVal=0x02), AES_modulus, 8)
    return newword, round_num_constant


def gen_key_schedule_128(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 44 keywords in the key schedule for 128 bit AES.  Each keyword is 32-bits
    #  wide. The 128-bit AES uses the first four keywords to xor the input block with.
    #  Subsequently, each of the 10 round_nums uses 4 keywords from the key schedule. We will
    #  store all 44 keywords in the following list:
    key_words = [None for i in range(44)]
    round_num_constant = BitVector(intVal=0x01, size=8)
    for i in range(4):
        key_words[i] = key_bv[i * 32: i * 32 + 32]
    for i in range(4, 44):
        if i % 4 == 0:
            kwd, round_num_constant = gee(key_words[i - 1], round_num_constant, byte_sub_table)
            key_words[i] = key_words[i - 4] ^ kwd
        else:
            key_words[i] = key_words[i - 4] ^ key_words[i - 1]
    return key_words


def encrypt(inputfile, outputfile):
   #f = open('encrypted_hex.txt', 'a')
    key = get_encryption_key()
    key_words = gen_key_schedule_128(key)
    subBytesTable, _ = genTables()
    bv = BitVector(filename=inputfile)
    statearray = [[0 for x in range(4)] for x in range(4)]
    FILEOUT = open(outputfile, 'w')
    temp_shift = [0]* 4

    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(128)
        if len(bitvec) > 0:
            if len(bitvec) != 128:
                bitvec.pad_from_right(128 - len(bitvec))

            # Filling in statearray and XORing
            for i in range(4):
                for j in range(4):
                    statearray[i][j] = bitvec[32 * i + 8 * j:32 * i + 8 * (j + 1)]
                    statearray[i][j] ^= key_words[i][8 * j:8 + (8 * j)]

            for round_num in range(10):

                # SubBytes
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = BitVector(intVal=subBytesTable[int(statearray[i][j])])

                # ShiftRows
                for i in range(1,4):
                    for j in range(0,4):
                        temp_shift[(j-i)%4] = statearray[j][i]
                    for j in range (0,4):
                        statearray[j][i] = temp_shift[j]

                # ColumnMixing
                if round_num != 9:
                    two_times = BitVector(bitstring='00000010')
                    three_times = BitVector(bitstring='00000011')
                    for i in range(4):
                        temp = (two_times.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
                                           (three_times.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
                                           statearray[i][2] ^ \
                                           statearray[i][3]

                        temp1 = (two_times.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
                                           (three_times.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                                           statearray[i][3] ^ \
                                           statearray[i][0]

                        temp2 = (two_times.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                                           (three_times.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                                           statearray[i][0] ^ \
                                           statearray[i][1]

                        temp3 = (two_times.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                                           (three_times.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
                                           statearray[i][1] ^ \
                                           statearray[i][2]

                        statearray[i][0] = temp
                        statearray[i][1] = temp1
                        statearray[i][2] = temp2
                        statearray[i][3] = temp3
                    
                # Add round_num Key
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] ^= key_words[(4 * (round_num + 1)) + i][8 * j:8 + (8 * j)]

            for i in range(4):
                for j in range(4):
                    FILEOUT.write(statearray[i][j].get_hex_string_from_bitvector())
                   # f.write(statearray[i][j].get_bitvector_in_hex())
   # f.close()
    FILEOUT.close()
    return


def decrypt(inputfile, outputfile):
    #f = open('decrypted_hex.txt', 'a')
    temp_shift = [0]*4
    key = get_encryption_key()
    key_words = gen_key_schedule_128(key)
    _, invSubBytesTable = genTables()
    bv = BitVector(filename=inputfile)
    statearray = [[0 for x in range(4)] for x in range(4)]
    FILEOUT = open(outputfile, 'w')
    while bv.more_to_read:
        bitvec = bv.read_bits_from_file(128)
        if len(bitvec) > 0:
            if len(bitvec) != 128:
                bitvec.pad_from_right(128 - len(bitvec))

            # Filling in statearray and XORing
            for i in range(4):
                for j in range(4):
                    statearray[i][j] = bitvec[32 * i + 8 * j:32 * i + 8 * (j + 1)]
                    statearray[i][j] ^= key_words[-(4-i)][8 * j:8 + (8 * j)]

            for round_num in range(10,0,-1):
                # Inverse ShiftRows
                for i in range(1,4):
                    for j in range(0,4):
                        temp_shift[(j+i)%4] = statearray[j][i]
                    for j in range (0,4):
                        statearray[j][i] = temp_shift[j]
                    
                # Inverse SubBytes
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = BitVector(intVal=invSubBytesTable[int(statearray[i][j])])

                # Add round_num Key
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] ^= key_words[(4*(round_num-1))+i][8 * j:8 + (8 * j)]

                # Inverse ColumnMixing
                if round_num != 1:
                    zeroE = BitVector(bitstring='00001110')
                    zeroB = BitVector(bitstring='00001011')
                    zeroD = BitVector(bitstring='00001101')
                    zero9 = BitVector(bitstring='00001001')
                    for i in range(4):
                        temp = (zeroE.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
                               (zeroB.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
                               (zeroD.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                               (zero9.gf_multiply_modular(statearray[i][3], AES_modulus, 8))

                        temp1 = (zeroE.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
                                (zeroB.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                                (zeroD.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                                (zero9.gf_multiply_modular(statearray[i][0], AES_modulus, 8))

                        temp2 = (zeroE.gf_multiply_modular(statearray[i][2], AES_modulus, 8)) ^ \
                                (zeroB.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                                (zeroD.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
                                (zero9.gf_multiply_modular(statearray[i][1], AES_modulus, 8))

                        temp3 = (zeroE.gf_multiply_modular(statearray[i][3], AES_modulus, 8)) ^ \
                                (zeroB.gf_multiply_modular(statearray[i][0], AES_modulus, 8)) ^ \
                                (zeroD.gf_multiply_modular(statearray[i][1], AES_modulus, 8)) ^ \
                                (zero9.gf_multiply_modular(statearray[i][2], AES_modulus, 8))

                        statearray[i][0] = temp
                        statearray[i][1] = temp1
                        statearray[i][2] = temp2
                        statearray[i][3] = temp3

            for i in range(4):
                for j in range(4):
                    FILEOUT.write(statearray[i][j].get_bitvector_in_ascii())
    FILEOUT.close()
    return

if __name__ == '__main__':
    encrypt('message.txt', 'encrypted.txt')
    decrypt('encrypted.txt', 'decrypted.txt')