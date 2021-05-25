import string
import itertools
import time


class SubstitutionCypher:
    def __init__(self, key = "ZEBRAS"):
        ciphertext_alphabet, plaintext_alphabet = self.initalize_alphabets(key)
        self.encryption_dictionary = self.create_dictionary(plaintext_alphabet, ciphertext_alphabet)
        self.decryption_dictionary = self.create_dictionary(ciphertext_alphabet, plaintext_alphabet)

    def encrypt(self, plain_text):
        cypher_text = self.replace(plain_text, self.encryption_dictionary)
        return cypher_text

    def decrypt(self, cypher_text):
        plain_text = self.replace(cypher_text, self.decryption_dictionary)
        return plain_text

    @staticmethod
    def initalize_alphabets(key):
        plaintext_alphabet = "".join((string.ascii_letters, string.digits, string.punctuation, " "))
        ciphertext_alphabet = plaintext_alphabet
        for char in key:
            ciphertext_alphabet = ciphertext_alphabet.replace(char,"")
        ciphertext_alphabet = key+ciphertext_alphabet
        ciphertext_alphabet =(ciphertext_alphabet*3)[len(ciphertext_alphabet)+13:2*len(ciphertext_alphabet)+13]
        return (ciphertext_alphabet, plaintext_alphabet)

    @staticmethod
    def create_dictionary(str1,str2):
        return  {str1[i]:str2[i] for i in range(len(str1))}

    @staticmethod
    def replace(text, dictionary):
        result= ""
        for letter in text:
            result += dictionary[letter]
        return result


class Rsa:
    def __init__(self):
        self.e = self.d = self.p = self.q = self.phi = 0
        self.generateKeys(
            17055899557196527525682810191339089909014331959812898993437334555169285087976951946809555356817674844913188193949144165887100694620944167618997411049745043243260854998720061941490491091205087788373487296637817044103762239946752241631032791287021875863785226376406279424552454153388492970310795447866569138481,
            171994050316145327367864378293770397343246561147593187377005295591120640129800725892235968688434055779668692095961697434700708550594137135605048681344218643671046905252163983827396726536078773766353616572531688390937410451433665914394068509329532352022301339189851111636176939179510955519440490431177444857017,
        )

    def encrypt(self, m, keyPair=None):
        m = self.encode_message(m)
        keyPair = self.getPrivateKey()
        return pow(m, keyPair[0], keyPair[1])

    def decrypt(self, c, keyPair=None):
        keyPair = self.getPublicKey()
        cypher = pow(c, keyPair[0], keyPair[1])
        return self.decode_message(cypher)

    def generateKeys(self, p, q, e=3):
        self.p = p
        self.q = q

        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        self.e = e
        self.d = self.__modinv(self.e, self.phi)

        if self.phi % self.e == 0:
            raise Exception("invalid values for p and q")

    def getMaxMessageBits(self):
        return self.n.bit_length()

    def getPublicKey(self):
        return self.e, self.n

    def getPrivateKey(self):
        return self.d, self.n

    @staticmethod
    def encode_message(message: str):
        encoding = ""
        alphabet = "".join(
            (string.ascii_letters, string.digits, string.punctuation[:-5], " ")
        )
        dictionary = {alphabet[i]: i + 10 for i in range(len(alphabet))}
        for char in message:
            encoding += str(dictionary[char])
        return int(encoding)

    @staticmethod
    def decode_message(cypher: int):
        decoded = ""
        cypher = str(cypher)
        alphabet = "".join(
            (string.ascii_letters, string.digits, string.punctuation[:-5], " ")
        )
        dictionary = {i + 10: alphabet[i] for i in range(len(alphabet))}
        for i in range(0, len(cypher), 2):
            decoded += dictionary[int(cypher[i : i + 2])]
        return decoded

    def __egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.__egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def __modinv(self, a, m):
        g, x, y = self.__egcd(a, m)
        if g != 1:
            raise Exception("modular inverse does not exist")
        else:
            return x % m


class Playfair:
    def chunker(self, seq, size):
        it = iter(seq)
        while True:
            chunk = tuple(itertools.islice(it, size))
            if not chunk:
                return
            yield chunk

    def prepare_input(self, dirty):
        """
        Prepare the plaintext by up-casing it
        and separating repeated letters with X's
        """

        dirty = "".join([c.upper() for c in dirty if c in string.ascii_letters])
        clean = ""

        if len(dirty) < 2:
            return dirty

        for i in range(len(dirty) - 1):
            clean += dirty[i]

            if dirty[i] == dirty[i + 1]:
                clean += "X"

        clean += dirty[-1]

        if len(clean) & 1:
            clean += "X"

        return clean

    def generate_table(self, key):

        # I and J are used interchangeably to allow
        # us to use a 5x5 table (25 letters)
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        # we're using a list instead of a '2d' array because it makes the math
        # for setting up the table and doing the actual encoding/decoding simpler
        table = []

        # copy key chars into the table if they are in `alphabet` ignoring duplicates
        for char in key.upper():
            if char not in table and char in alphabet:
                table.append(char)

        # fill the rest of the table in with the remaining alphabet chars
        for char in alphabet:
            if char not in table:
                table.append(char)

        return table

    def encrypt(self, plaintext):
        key = "AMEGO"
        table = self.generate_table(key)
        plaintext = self.prepare_input(plaintext)
        ciphertext = ""

        # https://en.wikipedia.org/wiki/Playfair_cipher#Description
        for char1, char2 in self.chunker(plaintext, 2):
            row1, col1 = divmod(table.index(char1), 5)
            row2, col2 = divmod(table.index(char2), 5)

            if row1 == row2:
                ciphertext += table[row1 * 5 + (col1 + 1) % 5]
                ciphertext += table[row2 * 5 + (col2 + 1) % 5]
            elif col1 == col2:
                ciphertext += table[((row1 + 1) % 5) * 5 + col1]
                ciphertext += table[((row2 + 1) % 5) * 5 + col2]
            else:  # rectangle
                ciphertext += table[row1 * 5 + col2]
                ciphertext += table[row2 * 5 + col1]

        return ciphertext

    def decrypt(self, ciphertext):
        key = "AMEGO"
        table = self.generate_table(key)
        plaintext = ""

        # https://en.wikipedia.org/wiki/Playfair_cipher#Description
        for char1, char2 in self.chunker(ciphertext, 2):
            row1, col1 = divmod(table.index(char1), 5)
            row2, col2 = divmod(table.index(char2), 5)

            if row1 == row2:
                plaintext += table[row1 * 5 + (col1 - 1) % 5]
                plaintext += table[row2 * 5 + (col2 - 1) % 5]
            elif col1 == col2:
                plaintext += table[((row1 - 1) % 5) * 5 + col1]
                plaintext += table[((row2 - 1) % 5) * 5 + col2]
            else:  # rectangle
                plaintext += table[row1 * 5 + col2]
                plaintext += table[row2 * 5 + col1]

        return plaintext


def main():
    algorithms = {1: "Substitution Cypher", 2: "RSA", 3: "Playfair"}
    algorithms_ref = {1: SubstitutionCypher, 2: Rsa, 3: Playfair}
    try:
        while True:
            print("Please, select encryption algorithm")
            print(algorithms)
            algorithm = algorithms_ref[int(input())]()
            print("type the message")
            message = str(input())
            cypher = algorithm.encrypt(message)
            plain = algorithm.decrypt(cypher)
            print("message:", message)
            time.sleep(1)
            print("cypher text:", cypher)
            time.sleep(1)
            print("decryption:", plain)
            time.sleep(1)
            print("terminate with ctrl+c then enter")
            print("-----------------------------------------")
    except KeyboardInterrupt:
        print("terminated")


if __name__ == "__main__":
    main()
