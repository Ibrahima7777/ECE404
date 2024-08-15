import sys
import copy
from BitVector import *

class AES():
    AES_modulus = BitVector(bitstring='100011011')
    subBytesTable = []
    invSubBytesTable = []
    
    def gen_subbytes_table(self):
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable
    
    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.gen_subbytes_table()
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = 
                                    byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8] 
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words
    
    def gen_key_schedule_128(self, key_bv):
        byte_sub_table = self.gen_subbytes_table()
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
                kwd, round_num_constant = self.gee(key_words[i - 1], round_num_constant, byte_sub_table)
                key_words[i] = key_words[i - 4] ^ kwd
            else:
                key_words[i] = key_words[i - 4] ^ key_words[i - 1]
        return key_words

    def gee(self, keyword, round_num_constant, byte_sub_table):
        '''
        This is the g() function you see in Figure 4 of Lecture 8.
        '''
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size=0)
        for i in range(4):
            newword += BitVector(intVal=byte_sub_table[rotated_word[8 * i:8 * i + 8].intValue()], size=8)
        newword[:8] ^= round_num_constant
        round_num_constant = round_num_constant.gf_multiply_modular(BitVector(intVal=0x02), self.AES_modulus, 8)
        return newword, round_num_constant
    
    def genTables(self):
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            # For the encryption SBox
            a = BitVector(intVal=i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            # For bit scrambling for the encryption SBox entries:
            a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            self.subBytesTable.append(int(a))
            # For the decryption Sbox:
            b = BitVector(intVal=i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1, b2, b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            self.invSubBytesTable.append(int(b))

    def __init__(self, keyfile:str) -> None:
        #subBytesTable = []
        # invSubBytesTeable = []
        self.genTables()
        #self.AES_modulus = BitVector(bitstring='100011011')
        FILEIN = open(keyfile, 'r')
        self.key = FILEIN.read()
        FILEIN.close()
    '''
    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        #FILEIN = open(plaintext, 'r')
        num = [0,0,0,0]
        key = BitVector(textstring = self.key)
        statearray = [[0 for x in range(4)] for x in range(4)]
        key_schedule = self.gen_key_schedule_128(key)
        bitvector = BitVector(filename=plaintext)
        cipher = open(ciphertext, 'ab')
        
        while(bitvector.more_to_read):
            bitvec = bitvector.read_bits_from_file(128)
            if len(bitvec) > 0:
                if len(bitvec) < 128:
                    bitvec.pad_from_right(128 - len(bitvec))
            for i in range(4):
                 for j in range(4):
                    statearray[i][j] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
                    statearray[i][j] = statearray[i][j] ^ key_schedule[i][8*j:8+(8*j)]
            
            for round in range(10):

                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = BitVector(intVal = self.subBytesTable[int(statearray[i][j])])

                for i in range(1,4):
                    for j in range(0,4):
                        num[(j-i)%4] = statearray[j][i]
                    for j in range(0,4):
                        statearray[j][i] = num[j]

                if round < 9:
                    M2 = BitVector(bitstring = '00000010')
                    M3 = BitVector(bitstring = '00000011')
                    for i in range(4):
                        val1 = (M2.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ statearray[i][2] ^ statearray[i][3]
                        val2 = (M2.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ statearray[i][3] ^ statearray[i][0]
                        val3 = (M2.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ statearray[i][0] ^ statearray[i][1]
                        val4 = (M2.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8)) ^ statearray[i][1] ^ statearray[i][2]

                        statearray[i][0] = val1
                        statearray[i][1] = val2
                        statearray[i][2] = val3
                        statearray[i][3] = val4

                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = statearray[i][j] ^ key_schedule[(4 * (round + 1)) + i][8*j:8+(8*j)]
                # if round == 1:
                #     print(str(statearray))
            for i in range(4):
                for j in range(4):
                    statearray[i][j].write_to_file(cipher)
                    #cipher.write(statearray[i][j].get_bitvector_in_hex())

        #FILEIN.close()
        cipher.close()
        return
             '''       
    
    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        num = [0,0,0,0]
        key = BitVector(textstring = self.key)
        statearray = [[0 for x in range(4)] for x in range(4)]
        key_schedule = self.gen_key_schedule_256(key)
        bitvector = BitVector(filename=plaintext)
        cipher = open(ciphertext, 'w')
        
        while(bitvector.more_to_read):
            bitvec = bitvector.read_bits_from_file(128)
            if len(bitvec) > 0:
                if len(bitvec) < 128:
                    bitvec.pad_from_right(128 - len(bitvec))


            for i in range(4):
                    for j in range(4):
                        statearray[i][j] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
                        statearray[i][j] = statearray[i][j] ^ key_schedule[i][8*j:8+(8*j)] # this is sus?
                    
            # bitvec ^= key_schedule[0]
            # print(bitvec.get_bitvector_in_hex())
            # pass

            for round in range(14):
                
                # Sub bytes
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = BitVector(intVal = self.subBytesTable[int(statearray[i][j])])
                # if round == 1:
                #     for i in range(4):
                #         for j in range(4):
                #             #print(f"{(statearray[j][i].get_bitvector_in_hex())}",end="")
                #             print(f"{hex(statearray[j][i].intValue())}")#,end="")
                #     exit(0)
                
                # #Shift rows:
                for i in range(1,4):
                    for j in range(0,4):
                        num[(j-i)%4] = statearray[j][i]
                    for j in range(0,4):
                        statearray[j][i] = num[j]
                        
                # new_statearray = copy.deepcopy(statearray)
                # new_statearray[0][0] = statearray[0][0]
                # new_statearray[0][1] = statearray[0][1]
                # new_statearray[0][2] = statearray[0][2]
                # new_statearray[0][3] = statearray[0][3]
                
                # new_statearray[1][0] = statearray[1][1]
                # new_statearray[1][1] = statearray[1][2]
                # new_statearray[1][2] = statearray[1][3]
                # new_statearray[1][3] = statearray[1][0]
                
                # new_statearray[2][0] = statearray[2][2]
                # new_statearray[2][1] = statearray[2][3]
                # new_statearray[2][2] = statearray[2][0]
                # new_statearray[2][3] = statearray[2][1]

                # new_statearray[3][0] = statearray[3][3]
                # new_statearray[3][1] = statearray[3][0]
                # new_statearray[3][2] = statearray[3][1]
                # new_statearray[3][3] = statearray[3][2]


                # if round == 1:
                #     for i in range(4):
                #         for j in range(4):
                #             #print(f"{(statearray[j][i].get_bitvector_in_hex())}",end="")
                #             print(f"{hex(statearray[j][i].intValue())}")#,end="")
                #     exit(0)

                if round < 13:
                    M2 = BitVector(bitstring = '00000010')
                    M3 = BitVector(bitstring = '00000011')
                    for i in range(4):
                        statearray[i][0] = (M2.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ statearray[i][2] ^ statearray[i][3]
                        statearray[i][1] = (M2.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ statearray[i][3] ^ statearray[i][0]
                        statearray[i][2] = (M2.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ statearray[i][0] ^ statearray[i][1]
                        statearray[i][3] = (M2.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8)) ^ statearray[i][1] ^ statearray[i][2]
                        # val1 = (M2.gf_multiply_modular(statearray[0][i], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[1][i], self.AES_modulus, 8)) ^ statearray[2][i] ^ statearray[3][i]
                        # val2 = (M2.gf_multiply_modular(statearray[1][i], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[2][i], self.AES_modulus, 8)) ^ statearray[3][i] ^ statearray[0][i]
                        # val3 = (M2.gf_multiply_modular(statearray[2][i], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[3][i], self.AES_modulus, 8)) ^ statearray[0][i] ^ statearray[1][i]
                        # val4 = (M2.gf_multiply_modular(statearray[3][i], self.AES_modulus, 8)) ^ (M3.gf_multiply_modular(statearray[0][i], self.AES_modulus, 8)) ^ statearray[1][i] ^ statearray[2][i]
                
                
                # Round keys:
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = statearray[i][j] ^ key_schedule[(4 * (round + 1)) + i][8*j:8+(8*j)]
                # if round == 0:
                #     print(key_schedule[1].get_bitvector_in_hex())
                
                
                state_bv = BitVector(size = 0)
                for i in range(4):
                    for j in range(4):
                        state_bv += statearray[j][i]
                
                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = state_bv[32*i + 8*j:32*i + 8*(j+1)]

                # if round == 1:
                #     for i in range(4):
                #         for j in range(4):
                #             #print(f"{(statearray[j][i].get_bitvector_in_hex())}",end="")
                #             print(f"{hex(statearray[j][i].intValue())}")#,end="")
                #     exit(0)
                
                #print(type(statearray[0][0]))
                # if round == 1:
                #     print(str(statearray))
                #     break
                       
            for i in range(4):
                for j in range(4):
                    #statearray[i][j].write_to_file(cipher)
                    #print(statearray[i][j].get_bitvector_in_hex())
                    cipher.write(statearray[i][j].get_hex_string_from_bitvector())

        #FILEIN.close()
        cipher.close()
        return
    
    '''
    def decrypt(self, ciphertext:str, decrypted:str) -> None:
        num = [0,0,0,0]
        key = BitVector(textstring = self.key)
        statearray = [[0 for x in range(4)] for x in range(4)]
        key_schedule = self.gen_key_schedule_128(key)
        bitvector = BitVector(filename=ciphertext)
        cipher = open(decrypted, 'ab')
        
        while(bitvector.more_to_read):
            bitvec = bitvector.read_bits_from_file(128)
            if len(bitvec) > 0:
                if len(bitvec) < 128:
                    bitvec.pad_from_right(128 - len(bitvec))
            for i in range(4):
                 for j in range(4):
                    statearray[i][j] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
                    statearray[i][j] = statearray[i][j] ^ key_schedule[-(4-i)][8*j:8+(8*j)]
            
            for round in range(10, 0, -1):
                for i in range(1,4):
                    for j in range(0,4):
                        num[(j-i)%4] = statearray[j][i]
                    for j in range(0,4):
                        statearray[j][i] = num[j]

                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = BitVector(intVal = self.invSubBytesTable[int(statearray[i][j])])

                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = statearray[i][j] ^ key_schedule[(4 * (round - 1)) + i][8*j:8+(8*j)]

                # for i in range(1,4):
                #     for j in range(0,4):
                #         num[(j-i)%4] = statearray[j][i]
                #     for j in range(0,4):
                #         statearray[j][i] = num[j]

                if round < 1:
                    E = BitVector(bitstring = '00001110')
                    B = BitVector(bitstring = '00001011')
                    D = BitVector(bitstring = '00001101')
                    nine = BitVector(bitstring = '00001001')

                    for i in range(4):
                        val1 = (E.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8)) ^ (B.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (D.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ (nine.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8))
                        val2 = (E.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (B.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ (D.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ (nine.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8))
                        val3 = (E.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ (B.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ (D.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (nine.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8))
                        val4 = (E.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ (B.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8)) ^ (D.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (nine.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8))

                        statearray[i][0] = val1
                        statearray[i][1] = val2
                        statearray[i][2] = val3
                        statearray[i][3] = val4

                # for i in range(4):
                #     for j in range(4):
                #         statearray[i][j] = statearray[i][j] ^ key_schedule[(4 * (round + 1)) + i][8*j:8+(8*j)]
                # if round == 1:
                #     print(str(statearray))
            for i in range(4):
                for j in range(4):
                    statearray[i][j].write_to_file(cipher)
                    #cipher.write(statearray[i][j].get_bitvector_in_hex())

        #FILEIN.close()
        cipher.close()
        return
    '''

    def decrypt(self, ciphertext:str, decrypted:str) -> None:
        num = [0,0,0,0]
        key = BitVector(textstring = self.key)
        statearray = [[0 for x in range(4)] for x in range(4)]
        key_schedule = self.gen_key_schedule_256(key)
        bitvector = BitVector(filename=ciphertext)
        cipher = open(decrypted, 'w')
        
        while(bitvector.more_to_read):
            bitvec = bitvector.read_bits_from_file(128)
            if len(bitvec) > 0:
                if len(bitvec) < 128:
                    bitvec.pad_from_right(128 - len(bitvec))
            for i in range(4):
                 for j in range(4):
                    statearray[i][j] = bitvec[32*i + 8*j:32*i + 8*(j+1)]
                    statearray[i][j] = statearray[i][j] ^ key_schedule[-(4-i)][8*j:8+(8*j)]
            
            for round in range(14, 0, -1):
                for i in range(1,4):
                    for j in range(0,4):
                        num[(j-i)%4] = statearray[j][i]
                    for j in range(0,4):
                        statearray[j][i] = num[j]

                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = BitVector(intVal = self.invSubBytesTable[int(statearray[i][j])])

                for i in range(4):
                    for j in range(4):
                        statearray[i][j] = statearray[i][j] ^ key_schedule[(4 * (round - 1)) + i][8*j:8+(8*j)]

                # for i in range(1,4):
                #     for j in range(0,4):
                #         num[(j-i)%4] = statearray[j][i]
                #     for j in range(0,4):
                #         statearray[j][i] = num[j]

                if round < 1:
                    E = BitVector(bitstring = '00001110')
                    B = BitVector(bitstring = '00001011')
                    D = BitVector(bitstring = '00001101')
                    nine = BitVector(bitstring = '00001001')

                    for i in range(4):
                        val1 = (E.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8)) ^ (B.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (D.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ (nine.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8))
                        val2 = (E.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (B.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ (D.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ (nine.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8))
                        val3 = (E.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8)) ^ (B.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ (D.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (nine.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8))
                        val4 = (E.gf_multiply_modular(statearray[i][3], self.AES_modulus, 8)) ^ (B.gf_multiply_modular(statearray[i][0], self.AES_modulus, 8)) ^ (D.gf_multiply_modular(statearray[i][1], self.AES_modulus, 8)) ^ (nine.gf_multiply_modular(statearray[i][2], self.AES_modulus, 8))

                        statearray[i][0] = val1
                        statearray[i][1] = val2
                        statearray[i][2] = val3
                        statearray[i][3] = val4

                # for i in range(4):
                #     for j in range(4):
                #         statearray[i][j] = statearray[i][j] ^ key_schedule[(4 * (round + 1)) + i][8*j:8+(8*j)]
                # if round == 1:
                #     print(str(statearray))
            for i in range(4):
                for j in range(4):
                    statearray[i][j].write_to_file(cipher)
                    #cipher.write(statearray[i][j].get_bitvector_in_ascii())

        #FILEIN.close()
        cipher.close()
        return


if __name__ == "__main__":
    cipher = AES(keyfile = sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4])
    else:
        sys.exit("Incorrect Command-Line Syntax")