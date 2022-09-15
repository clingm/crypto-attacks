from sage.all import *
from sage.all_cmdline import *
import logging

def roots_of_unity(r, Fq):
    """
    Generates rth roots of unity in Fq, with r | q - 1.
    :param r: the r
    :param Fq: the field Fq
    :return: a generator generating the roots of unity
    """
    q = Fq.order()
    assert (q - 1) % r == 0, "r should divide q - 1"

    x = Fq(q - 2)
    while x ** ((q - 1) // r) == 1:
        x -= 1

    g = x ** ((q - 1) // r)
    for i in range(r):
        yield int(g ** i)


def rth_roots(delta, r, Fq):
    """
    Uses the Adleman-Manders-Miller algorithm to extract rth roots in Fq, with r | q - 1.
    More information: Cao Z. et al., "Adleman-Manders-Miller Root Extraction Method Revisited" (Section 5)
    :param delta: the rth residue delta
    :param r: the r
    :param Fq: the field Fq
    :return: a generator generating the rth roots
    """
    delta = Fq(delta)
    q = Fq.order()
    assert (q - 1) % r == 0, "r should divide q - 1"

    p = Fq(1)
    while p ** ((q - 1) // r) == 1:
        p = Fq.random_element()

    t = 0
    s = q - 1
    while s % r == 0:
        t += 1
        s //= r

    k = 1
    while (k * s + 1) % r != 0:
        k += 1
    alpha = (k * s + 1) // r

    a = p ** (pow(r, t - 1, q - 1) * s)
    b = delta ** (r * alpha - 1)
    c = p ** s
    h = 1
    for i in range(1, t):
        d = b ** pow(r, t - 1 - i, q - 1)
        logging.debug(f"Computing the discrete logarithm for i = {i}, this may take a long time...")
        j = 0 if d == 1 else -d.log(a)
        b *= (c ** r) ** j
        h *= c ** j
        c **= r

    root = int(delta ** alpha * h)
    for primitive_root in roots_of_unity(r, Fq):
        yield root * primitive_root % q