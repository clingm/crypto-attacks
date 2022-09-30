import random
from sage.all import *
from sage.all_cmdline import *
from Crypto.Util.number import *

Zx = ZZ['x']; (x,) = Zx._first_ngens(1)
# R.<x> = ZZ[]
def balancedmod(f,q):
    g = list( ((f[i] + q//2) % q) - q//2 for i in range(n) )
    return Zx(g)

def cyclicconvolution(f, g):
    return (f*g) % (x**n-1)

def invertmodprime(f,p):
    T = Zx.change_ring(Integers(p)).quotient(x**n-1)
    return Zx(lift(1 / T(f)))

def invertmodpowerof2(f,q):
    assert q.is_power_of(2)
    g = invertmodprime(f,2)
    while True:
        r = balancedmod(cyclicconvolution(g,f),q)
        if r == 1: return g
        g = balancedmod(cyclicconvolution(g,2 - r),q)

""" def encrypt(message, publickey):
    r = rpoly()
    return balancedmod(cyclicconvolution(publickey, r) + message, q)
 """
def decrypt(cipher,f,fp):
    # cipher=Zx(cipher)
    a=balancedmod(cyclicconvolution(f, cipher), q)
    m=balancedmod(cyclicconvolution(fp, a),p)
    return m

def attack(publickey):
    recip3 = lift(1/Integers(q)(3))
    publickeyover3 = balancedmod(recip3 * publickey,q)
    M = matrix(2 * n)
    for i in range(n):
        M[i,i] = q
    for i in range(n):
        M[i+n,i+n] = 1
        c = cyclicconvolution(x**i,publickeyover3)
        for j in range(n):
            M[i+n,j] = c[j]
    M = M.LLL()
    for j in range(2 * n):
        try:
            f = Zx(list(M[j][n:]))
            f3 = invertmodprime(f,3)
            return (f,f3)
        except:pass
    return (f,f)

# parameters
n = 66
p = 3
q = 2**20
d = 31
assert q>(6*d+1)*p

h = 847417*x**65 + 149493*x**64 + 671215*x**63 + 940073*x**62 + 422433*x**61 + 906071*x**60 + 661777*x**59 + 213093*x**58 + 776476*x**57 + 308727*x**56 + 199931*x**55 + 256166*x**54 + 201216*x**53 + 964303*x**52 + 961341*x**51 + 216401*x**50 + 503421*x**49 + 391011*x**48 + 724233*x**47 + 834103*x**46 + 534483*x**45 + 145755*x**44 + 31514*x**43 + 633909*x**42 + 611687*x**41 + 656421*x**40 + 51098*x**39 + 23193*x**38 + 874589*x**37 + 481483*x**36 + 772432*x**35 + 596655*x**34 + 924673*x**33 + 790137*x**32 + 711581*x**31 + 795565*x**30 + 179559*x**29 + 974401*x**28 + 252177*x**27 + 712781*x**26 + 292518*x**25 + 556867*x**24 + 247625*x**23 + 131231*x**22 + 545208*x**21 + 774544*x**20 + 810813*x**19 + 997461*x**18 + 951783*x**17 + 778973*x**16 + 225243*x**15 + 241753*x**14 + 419437*x**13 + 1013119*x**12 + 847743*x**11 + 60647*x**10 + 477291*x**9 + 674781*x**8 + 245115*x**7 + 745149*x**6 + 280553*x**5 + 298381*x**4 + 849205*x**3 + 541486*x**2 + 720005*x + 21659
e = -34408*x**65 - 271875*x**64 - 72324*x**63 - 146782*x**62 - 191501*x**61 + 228014*x**60 - 236704*x**59 - 162996*x**58 - 93476*x**57 + 438756*x**56 - 340498*x**55 - 177073*x**54 + 309787*x**53 + 287611*x**52 - 13370*x**51 - 189635*x**50 + 271391*x**49 + 215846*x**48 - 286021*x**47 + 215770*x**46 + 259901*x**45 - 9022*x**44 - 410163*x**43 + 187965*x**42 - 99716*x**41 + 150105*x**40 + 161841*x**39 - 24872*x**38 - 288722*x**37 + 263847*x**36 + 142479*x**35 - 355131*x**34 - 181543*x**33 - 379836*x**32 + 206610*x**31 - 264717*x**30 - 381231*x**29 + 346552*x**28 - 59454*x**27 - 38411*x**26 - 200819*x**25 + 271459*x**24 + 169671*x**23 - 494515*x**22 - 250245*x**21 + 28462*x**20 + 485002*x**19 - 252744*x**18 + 301433*x**17 + 116488*x**16 - 359247*x**15 + 472604*x**14 + 16539*x**13 - 207870*x**12 - 137611*x**11 - 379327*x**10 + 477482*x**9 + 447007*x**8 - 368776*x**7 - 488265*x**6 - 312305*x**5 - 17292*x**4 + 372405*x**3 + 288980*x**2 + 95015*x - 99099
c = b"\x90\xd4D\xd0\x0e\x19\x04\xd2]\xd5k\x0c&\xeas\xf42T\x89\x02\x10\xa7\x1b\x04aR|<,\xa8J/\x86\xdf@wW&\xf3\x1c}\x0e\xe1\xa4\xc4'\xffw\xc8\xcaT+\x10\xacR\xc0N\x99\x83\x1d}F\x0f\x99"

# publickey,secretkey = keypair()
donald = attack(h.coefficients(sparse=False))
m = decrypt(e,donald[0],donald[1])

""" 
DASCTF example
from Crypto.Hash import SHA3_256
from Crypto.Cipher import AES
sha3 = SHA3_256.new()
sha3.update(bytes(str(Zx(m)).encode('utf-8')))
key = sha3.digest()

cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(c)
print('c = %s' % flag) """
