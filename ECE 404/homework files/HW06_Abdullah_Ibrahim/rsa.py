from BitVector import *
import PrimeGenerator as prime
import sys
from solve_pRoot import solve_pRoot

class RSA():

    primegen = prime.PrimeGenerator(bits=128)

    def __init__(self, e, p_file:str, q_file:str) -> None:
        self.e = e

        FILEIN = open(p_file, 'r')
        self.p = FILEIN.read()
        self.p_int = int(self.p)
        FILEIN.close()

        FILEIN = open(q_file, 'r')
        self.q = FILEIN.read()
        self.q_int = int(self.q)
        FILEIN.close()
        self.n = self.p_int * self.q_int
        self.d = self.MI(e, ((self.p_int - 1) * (self.q_int - 1)))

    def MI(self, num, mod):
        '''
        This function uses ordinary integer arithmetic implementation of the
        Extended Euclid's Algorithm to find the MI of the first-arg integer
        vis-a-vis the second-arg integer.

        '''
        MOD = mod
        x, x_old = 0, 1
        y, y_old = 1, 0
        while mod:
            q = num // mod
            num, mod = mod, num % mod
            x, x_old = x_old - q * x, x
            y, y_old = y_old - q * y, y
        if num != 1:
            MI = 0
        else:
            MI = (x_old + MOD) % MOD
        return MI
    
    def gcd(a,b):
        while b:
            a, b = b, a%b
        return a
    
    # def CRT(self, encrypted_int):
    #     Vp = pow(int(encrypted_int), self.d, self.p_int)
    #     Vq = pow(int(encrypted_int), self.d, self.q_int)
    #     Xp = self.q_int * (self.MI(self.q_int, self.p_int))
    #     Xq = self.p_int * (self.MI(self.p_int, self.q_int))
    #     return int((Vp*Xp + Vq*Xq) % self.n)
    def CRT(self, encrypted_int):
        decrypted_mod_p = pow(int(encrypted_int), self.d, self.p_int)
        decrypted_mod_q = pow(int(encrypted_int), self.d, self.q_int)
        coef_p = self.q_int * self.MI(self.q_int, self.p_int)
        coef_q = self.p_int * self.MI(self.p_int, self.q_int)
        decrypted = int((decrypted_mod_p * coef_p + decrypted_mod_q * coef_q) % self.n)
        return decrypted
    
    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        #FILEIN = open(plaintext, "a")
        FILEOUT = open(ciphertext, "w")
        bitvec = BitVector(filename = plaintext)
        while bitvec.more_to_read:
            block = bitvec.read_bits_from_file(128)
            block.pad_from_right(128-len(block))
            block.pad_from_left(128)
            encrypted_block = pow(int(block), self.e, self.n)
            encrypted = BitVector(intVal = encrypted_block, size = 256)
            #encrypted.write_to_file(FILEOUT)
            FILEOUT.write(encrypted.get_hex_string_from_bitvector())
        FILEOUT.close()
        return

    # def decrypt(self, ciphertext:str, recovered_plaintext:str) -> None:
    #     FILEOUT = open(recovered_plaintext, "a")
    #     bitvec = BitVector(filename = ciphertext)
    #     while bitvec.more_to_read:
    #         block = bitvec.read_bits_from_file(128)
    #         block.pad_from_right(128-len(block))
    #         block.pad_from_left(128)
    #         encrypted_block = pow(int(block), self.e, self.n)
    #         encrypted = BitVector(intVal = encrypted_block, size = 256)
    #         #encrypted.write_to_file(FILEOUT)
    #         #FILEOUT.write(encrypted.get_hex_string_from_bitvector())
    #         mytext = encrypted.get_bitvector_in_ascii()
    #         FILEOUT.write(mytext)
    #     FILEOUT.close()
    #     return
    
    def decrypt(self, ciphertext:str, recovered_plaintext:str) -> None:
        #f = open(ciphertext, 'w')
        FILEOUT = open(recovered_plaintext, 'w')
       # bv = BitVector(filename = ciphertext)
        
        FILEIN = open(ciphertext,'r')
        bv = BitVector(hexstring = FILEIN.read())
        FILEIN.close

        output = BitVector(size=0)
        for block in range(len(bv)//256):
            bit_block = bv[256*block:256*(block+1)]
        #while bv.more_to_read:
            #bit_block = bv.read_bits_from_file(256)
            decrypt = self.CRT(int(bit_block))
            decrypted = BitVector(intVal=decrypt, size=256)[128:]
            output += decrypted

            #print(output.get_bitvector_in_ascii())
        FILEOUT.write(output.get_bitvector_in_ascii())
        FILEOUT.close()
        return
    
if __name__ == "__main__":
    cipher = RSA(e = 65537, p_file = sys.argv[3], q_file = sys.argv[4])
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[5])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[5])