from BitVector import *
import PrimeGenerator as prime
import sys
from solve_pRoot import solve_pRoot

class breakRSA(object):

    primegen = prime.PrimeGenerator(bits=128)

    def __init__(self):
        self.e = 3

        self.key_info1 = self.get_modulus()
        self.key_info2 = self.get_modulus()
        self.key_info3 = self.get_modulus()
        #d = self.MI(65537, ((p-1)*(q-1)))
        # d for each private key
        self.d1 = self.get_decryption_exp(self.key_info1[0], self.key_info1[1])
        self.d2 = self.get_decryption_exp(self.key_info2[0], self.key_info2[1])
        self.d3 = self.get_decryption_exp(self.key_info3[0], self.key_info3[1])

        self.key_info = [self.key_info1, self.key_info2, self.key_info3]
        self.d = [self.d1, self.d2, self.d3]
        
        with open(sys.argv[6], 'w') as f:
            f.write(str(self.key_info1[2]))
            f.write('\n')
            f.write(str(self.key_info2[2]))
            f.write('\n')
            f.write(str(self.key_info3[2]))
    # def __init__(self):
    #     self.e = 3
    #     self.keys = [self.generate_key() for _ in range(3)]

    #     self.key_info = [key[0] for key in self.keys]
    #     self.decryption_exponents = [key[1] for key in self.keys]

    #     self.save_key_info(sys.argv[6])

    # def generate_key(self):
    #     modulus = self.get_modulus()
    #     decryption_exp = self.get_decryption_exp(modulus[0], modulus[1])
    #     return modulus, decryption_exp

    # def save_key_info(self, filename):
    #     with open(filename, 'w') as file:
    #         file.write(str(self.key_info + self.decryption_exponents))

    def GCD(self, a, b):
        while b:
            a,b = b, a%b
        return a

    def MI(self, num, mod):
        '''
        This function uses ordinary integer arithmetic implementation of the
        Extended Euclid's Algorithm to find the MI of the first-arg integer
        vis-a-vis the second-arg integer.

        This is taken from lecture notes.
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

    def get_modulus(self):
        while True:
            prime1 = self.primegen.findPrime()
            prime2 = self.primegen.findPrime()

            gcd_prime1 = self.GCD(prime1 - 1, 65537)
            gcd_prime2 = self.GCD(prime2 - 1, 65537)

            msb_prime1, next_msb_prime1 = bin(prime1)[2:4]
            msb_prime2, next_msb_prime2 = bin(prime2)[2:4]

            if (prime1 != prime2 and 
                gcd_prime1 == gcd_prime2 == 1 and
                msb_prime1 == msb_prime2 == '1' and
                next_msb_prime1 == next_msb_prime2 == '1'):
                
                rsa_modulus = prime1 * prime2
                break

        return prime1, prime2, rsa_modulus

    def get_decryption_exp(self, p, q):
        d = self.MI(65537, ((p-1)*(q-1)))
        return d

    def fix_file(self, filename):
        with open(filename, 'r') as f:
            contents = f.readlines()[0]

        chars_to_add = (len(contents)*8) % 128

        if chars_to_add > 0:
            chars_to_add = (128 - chars_to_add) / 8
            with open(filename, 'a') as f:
                while chars_to_add > 0:
                    f.write('\n')
                    chars_to_add -= 1
        return

    def CRT(self, enc1, enc2, enc3, N):
        N1 = N / self.key_info1[2]
        N2 = N / self.key_info2[2]
        N3 = N / self.key_info3[2]

        mi1 = self.MI(N1, self.key_info1[2])
        mi2 = self.MI(N2, self.key_info2[2])
        mi3 = self.MI(N3, self.key_info3[2])

        return (enc1 * N1 * mi1 + enc2 * N2 * mi2 + enc3 * N3 * mi3) % N

    def encrypt(self, plaintext, enc1, enc2, enc3):
        enc_files = [enc1, enc2, enc3]
        for i in range(3):
            FILEOUT = open(enc_files[i], 'w')
            self.fix_file(plaintext)
            bv = BitVector(filename=plaintext)
            while bv.more_to_read:
                bit_block = bv.read_bits_from_file(128)
                bit_block.pad_from_right(128-len(bit_block))
                bit_block.pad_from_left(128)
                encrypted_int = pow(int(bit_block), self.e, self.key_info[i][2])
                encrypted = BitVector(intVal=encrypted_int, size=256)
                FILEOUT.write(encrypted.get_hex_string_from_bitvector())
            FILEOUT.close()
        return

    def crack(self, enc1, enc2, enc3, n, cracked):
        f = open(cracked, 'a')
        FILEOUT = open(sys.argv[2], 'a')
        N = int(self.key_info1[2]) * int(self.key_info2[2]) * int(self.key_info3[2])
        #enc_files = ['enc1.txt', 'enc2.txt', 'enc3.txt']
        enc_files = [enc1, enc2, enc3]
        bv = BitVector(filename=enc_files[0])
        bv2 = BitVector(filename=enc_files[1])
        bv3 = BitVector(filename=enc_files[2])
        while bv.more_to_read:
            bit_block = bv.read_bits_from_file(256)
            bit_block2 = bv2.read_bits_from_file(256)
            bit_block3 = bv3.read_bits_from_file(256)
            decrypted = self.CRT(int(bit_block), int(bit_block2), int(bit_block3), N)
            decrypted2 = solve_pRoot(3, decrypted)

            decrypted_unpadded = BitVector(intVal=decrypted2, size=256)[128:]
            #decrypted_unpadded.write_to_file(FILEOUT)
            f.write(decrypted_unpadded.get_hex_string_from_bitvector())
        FILEOUT.close()
        return
    
if __name__ == "__main__":
    cipher = breakRSA()
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext = sys.argv[2], enc1 = sys.argv[3], enc2 = sys.argv[4], enc3 = sys.argv[4])
    elif sys.argv[1] == "-c":
        cipher.crack(enc1 = sys.argv[2], enc2 = sys.argv[3], enc3 = sys.argv[4], n = sys.argv[5], cracked = sys.argv[6])