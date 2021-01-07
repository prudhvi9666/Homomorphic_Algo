import random


def generate_LCM(p, q):
    """
    give lcm of p and q
    p is first prime number -1
    q is second prime number -1
    """
    return p *q // generate_gcd(p, q)[0]


def generate_gcd(a, b):
    """
    returns (g, x, y) according to the Extended Euclidean Algorithm
    such that, ax + by = g
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = generate_gcd(b % a, a)
        return (g, x - (b // a) * y, y)


def multi_inverse(lcmvalue, n):
    """
    returns x: multiplicative inverse of a
    such that, a * x = 1 (mod modu)
    """
    g, x, y = generate_gcd(lcmvalue, n)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % n


def Generate_privatekey(m, n, result):
    """
    PrivateKey object contains λ(_lambda) and μ(_mu)
    in accordance to the Paillier Cryptosystem

    args:
        m: a prime number
        n: another prime number
        result: product of p and q

    attributes:
        λ(_LCM): lowest common multiple of m-1 and n-1
        μ(_mu): modular multiplicative inverse of λ and result
    """
    _LCM = generate_LCM(m - 1, n - 1)
    _multiInversevalue = multi_inverse(_LCM, result)
    return _LCM, _multiInversevalue


def Generate_publickey(result):
    """
    Public Key object contains result and x
    in accordance to the Paillier Cryptosystem

    args:
        result: product of two equal lenght prime numbers

    attributes:
        result: product of two primes
        x: a random number such that,
        nsq = result * result
        multiplicative order of x in result^2 is a multiple of result
    """
    result = result
    nsq = result * result
    x = result + 1
    return result, x, nsq


def Main_fun(m=757, n=787):
    """
    This function is used to generate the public and private keys based on M,n values
    m and n are two prime numbers with same size
    function returns the genearted keys as tuples
    """
    result = m * n
    return Generate_publickey(result), Generate_privatekey(m, n, result)


def Encryption(pub_key, text):
    """
    Encryption( pub_key, text)

    args:
        pub_key: Paillier Public key object
        text: number to be encrypted

    returns:
        encrypted_text: encryption of text
        such that encrypted_text = (g ^ text) * (r ^ n) (mod n ^ 2)
        where, r is a random number in n such that r and n are coprime
    """

    r = random.randint(1, pub_key[0] - 1)
    while not generate_gcd(r, pub_key[0])[0] == 1:
        r = random.randint(1, pub_key[0])

    a = pow(pub_key[1], text, pub_key[-1])
    b = pow(r, pub_key[0], pub_key[-1])

    encrypted_text = (a * b) % pub_key[-1]
    return encrypted_text


def Decryption(pub_key, pri_key, encrypted_text):
    """
    Decryption( pub_key, pri_key, encrypted_text)

    args:
        pub_key: Paillier Public Key object
        pri_key: Paillier Private Key object
        encrypted_text: Encrypted Integer which was ecnrypted using the pub_key

    returns:
        text: decryption of encrypted_text
        such that text = L(encrypted_text ^ _lambda) * _mu (mod n ^ 2)
        where, L(x) = (x - 1) / n
    """

    x = pow(encrypted_text, pri_key[0], pub_key[-1])
    L = lambda x: (x - 1) // pub_key[0]

    text = (L(x) * pri_key[-1]) % pub_key[0]
    return text


def homomorphic_addition(pub_key, a, b):
    """
    adds encrypted integer a to encrypted integer b

    args:
        pub_key
        encryption of integer a
        encryption of integer b
    returns:
        encryption of sum of a and b
    """
    return (a * b) % pub_key[-1]
