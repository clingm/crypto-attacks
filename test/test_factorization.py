import os
import sys
from unittest import TestCase

path = os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from attacks.factorization import base_conversion
from attacks.factorization import branch_and_prune
from attacks.factorization import complex_multiplication
from attacks.factorization import coppersmith
from attacks.factorization import fermat
from attacks.factorization import gaa
from attacks.factorization import implicit
from attacks.factorization import known_phi
from attacks.factorization import roca
from attacks.factorization import shor
from attacks.factorization import twin_primes
from attacks.factorization import unbalanced
from shared.partial_integer import PartialInteger


class TestFactorization(TestCase):
    def test_base_conversion(self):
        # Base 3, 3 primes.
        p = 21187083124088512843307390152364167522362269594349815270782628323431805003774795906872825415073456706499910412455608669
        q = 15684240429131529254685698284890751184639406145730291592802676915731672495230992603635422093849215077
        r = 40483766026713491645694780188316242859742718066890630967135095358496115350752613236101566589
        N = p * q * r
        p_, q_, r_ = base_conversion.factorize(N)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertIsInstance(r_, int)
        self.assertEqual(N, p_ * q_ * r_)

        # Base 11, 2 primes.
        p = 5636663100410339050591445485090234548439547400230152507623650956862470951259768771895609021439466657292113515499213261725046751664333428835212665405991848764779073407177219695916181638661604890906124870900657349291343875716114535224623986662673220278594643325664055743877053272540004735452198447411515019043760699779198474382859366389140522851725256493083967381046565218658785408508317
        q = 4637643488084848224165183518002033325616428077917519043195914958210451836010505629755906000122693190713754782092365745897354221494160410767300504260339311867766125480345877257141604490894821710144701103564244398358535542801965838493
        N = p * q
        p_, q_ = base_conversion.factorize(N)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        # Base 2^160, 2 primes.
        p = 134826985114673693079697889309176855021348273420672992955072560868299506854125722349531357991805652015840085409903545018244092326610812466869635572979608167582448469047292232170026320223391046627827365953771456829800031927295216664570456335020600113109401331922210657078827704893772556600526431969555905511427
        q = 134826985114673693079697889309176855021348273420672992955072560868299506854125722349531369708710074146994058073106677693297307972510840782905868011390507022264343887357982117805583825101045090560994075108798072667294324419540888931176108008717194960124595895067571773696162270385695412387928036333235434684421
        N = p * q
        p_, q_ = base_conversion.factorize_base_2x(N)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_branch_and_prune(self):
        # These primes aren't special.
        p = 8751082012137052188389027859252318951713906021981061489307174345160656700272217500009165375464562134835463078286247099940424978338895179976064817650525381
        q = 6705712489981460472010451576220118673766200621788838066168783990030831970269515515674361221085135530331369278172131216566093286615777148021404414538085037
        N = p * q
        e = 65537

        # 256 known, 256 unknown.
        p_bits = "10?001?????????0?1100101?10?1????10??10?00?010?1?1?101?1?0??1?10001?1?0?1??110???0????0?1??01??????100???0???????1?011?00001?1??10?1?0?1???0110?1???0?110?0????010??01????????01?0000011???1??0?11?0????0??1??00??010?110001?100111111101??0???1??1?0111?01?1?1???00?1??01?0?0000000??0?0?100??011?01100?11??10????1?0?1?1??1?0?1110?1??1????????0010????01010111?0?0?1?1?01??01????????0????10???1000?0????00???11??0011??1?1111???10?0?0?1???100111?0??011?0??0??????11??00?0?????0??1?1????01?111????0?????0?1??0?10??100??0?"
        # 256 known, 256 unknown.
        q_bits = "??0?????0??0?000?1010?11??????1?11?0???0??1???0??0?1?0?1??1?000????001?1????01????011??????1000?1?1???01??11111000?10?0?0?1??0?0??1?0???1?11?0???10?0?0010?11?0100101?????100???10?01????00?000??1?10????01??10???????111000?01??0?1?00??0?0?10??1?11?0?01??0?0???011???10?0??01???10?1?1???11??00?????1?0??00??1?0?1???001????1?001?00?1??0?110?00?11???00011?001110??00?011???01?0?????1?11?10?01011???0111??0??1?0??1011???11??00?1?0101??0???1??1?1111??0101010??0?01???1??011??10?0???111?1010?1??11??11?1011????1??01?11??"
        p_, q_ = branch_and_prune.factorize_pq(N, PartialInteger.from_bits_be(p_bits), PartialInteger.from_bits_be(q_bits))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        # 182 known, 330 unknown.
        p_bits = "?0??0?????01?1??0??0?10?1???1001?1???????0?????1??0??1??1?1??01??01???0?1?????0???0??????0?0???1??010?1?10?????0???0?1?????1?????00???1?10??11?0?11???11?????0?0??0?0??0??1??1???0?????110?100??1?1?????????1????0?1?11?0????1?0????1?1?100???1?00??0111??1???1?00????1??1?????000??110?0???0?1?1???110?01????0??0???0?1?1???00?1?10?11??????1??1?01???0??????11?100?1?1100??001????1110?1?????????????0??1??0???1??000?????0?1?1?0??00???????0???111???10?1?0?0??????0?????0??0???????11?????????1??1??0?????0??1????0??1??0??1"
        # 182 known, 330 unknown.
        q_bits = "???0????0?????0???????1??????01?1??00???10??1????0?????1?1???0??0???0?????10??????????11???1???0???0?0?1??1????0??0?0????0???????0???1???0?1???0??000?0?????1101?01??1011???0??1???0?0??0??????0?10??0?01??1?101?????????0??0??1???100?????011???????00????0010?????????1?1???01?111??1?1???1??10???????????0?01?????????????00?????0?0??1?0?110?000111?0?0????0??????10???????0??1????00??1?11???101????01110??1?1?0??????1?0???0?0?110?01???010?01?01??1???1???1??1?0??10?11?011??????1011??110????10?1???10????1?00?0?01?1?0?"
        # 364 known, 660 unknown.
        d_bits = "0???1?1?0?????????0?????0??????1???110????1101???0?00??10????0?1??00???1?1????1?0?0?1?111??1100?0???1?0?1?1????11??1???????0100????0?0??0?1????0??0?0??????0??0?0??0??010?0110??1????????0??10???00??1??0?1?10??0???1??????0?00??????1???????1??1?11?????1????????1??1?01?????011????111?????10?11?1???00?1??11?1??11?0?10??1???0???0?10???????????0???1??00???0???11???0?????0?101000?10??0?1?1????0????001???0?0??????????10?11??????0100??01?1?1100?1???0??1??01????000????????110??????1000???1?01?1?11?????0?00????10?01??0?0??11?00?0??0?00?10??01??0??0????0??10?????11???0???11??1???1?1?0?????00????1???001??????100?0????1??1?0?0?0??????1?0???0?1?00??1?????1???0?1001?????0?????0??1??0?0???10?????0???1?1???0????111?????0??????0?0?1101???0??????????????1???00?????0????1??????1?00??0??101?1???111?1000?0???0???0??11?1?1?1???????1?1???0?1??????1??0??1????01??????0?????????1????1???01???1????00??0?0???1?0?1?????0??????1???0?1?10??0?01??0?000?????0??????0???0????11???1????01?1?11??10?1???0?????0100?10?111?0?0?10??1?01????0????0????01"
        p_, q_ = branch_and_prune.factorize_pqd(N, e, PartialInteger.from_bits_be(p_bits), PartialInteger.from_bits_be(q_bits), PartialInteger.from_bits_be(d_bits))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        # 128 known, 384 unknown.
        p_bits = "1????1??0???????0?1??1?????1??01???0??????????0?????????1???????0???1???1????00??0000??01?0??0?1?0???????0?10???0?001??0???????????1???1??1?1??0??11?????00???0?????????1??0?1????????????0???0?????0?1?????11????????1?0????10??11????0????011?0??????1?0???11??0????11?????0??????11????1???????1?1?00???01???????100??1?0???????0???0?1??????1?0??????0?????1?1??01??10????01?????????1?0??00?????????????????1??????1???????????1??????????????1??001??1?010???????????????0?0?????1??????0111??????0???11???1??????1???????"
        # 128 known, 384 unknown.
        q_bits = "???0??00?????0???????1?1?0????????0?????10????????0???????1?????0?????????1??????101?0?1????0?0???????0??????1???????10?00??1???1??1?10?????10????????????01???1???0??????10???1?0?01?1?0?00??0?0?0??????????1????011???10?0???????10???0?????011??11?0????00???0101?0????10????????????11??11?????1?????0??????????110???????????????????10???????????????0?1????????????????1???????????1???10?????1?0?0????00??????0?01????1?1???0?10??1??????1??1???1???????????1?0?????1?????00??1???????1?0????1??1????01?11?10???????1?0?"
        # 256 known, 768 unknown.
        d_bits = "????1?1?0????1???0?0?????01?0????1??????????0??0??????????1?????0????????1?0???1?10??0?????1???00??0?000????1?011????????1??1???0?1?0??0??1???1????1????????????????????0????0????011?????????1????????1?????0??????1???0??0??????????1??0?????0?1???1????0??10?????????1???0???11?????1?1??????????1??00????1??1??1??0????1???1???1????0????11?11?0??????0???1?1???1?????0??????0???00?????01???????????????????0?????0???1??111???????1??????1?0?1???????0?011?01???0??0??11???0???1??0?????00?0?1??????????1??????????????0????????????????1??????1?1?1??1?1??????1?0???????0?00????1?1???????0?1??10?1??1???0??????????0??0?????????0?0?0?????1???????????0???11???10???0?0???1?1????0?0????????000?1??1????1????1???0?11?????0?????0?1?0?0?0?????0????????????10???0?????1????????1??1010??00????????01?????????????110?????1??????11??0?0???????????1????11?100???000??????????0???0????1?????00???001???00??1?00?????????1?1??0??01???1????????????0???0????????1?????01?11??0???11?0????0????11?10?1????11???????1???1?1???0???110??1??11????1?0????00??"
        # 128 known, 384 unknown.
        dp_bits = "1?????11?1???1???011?0???1????11?1??0?1?1?????1????????1?11???1??11??1??0??01????01?1?1???????10???????0???????1???0?0???1????0?????0?0???0???11???1?0?10????1??????0??????????1?1?1??1?01?01??????11???0?10???????1??????????????0???0???0????????1??????0?1?1???????0?0?????????????????111?????11?????0?????1??????1101???????????0??????????1??0?0???????1???????0??11??1?????0?1?11??11??0???????0????????????????0???00?0????????????????10??1???0?01?1?????1?????1????1??????01?11???????0???01??10?1????0????1???1??????"
        # 128 known, 384 unknown.
        dq_bits = "???1????1??0?0?1???????0?01??????0?10?1???0?0011?1????10?0?11??1?0?1????011????????0????????????????00????0?0?????1???1?????????0?1????????1????1???1??1????1??1??1??????1?????00??1??????1????1??1?0?0??00??0?1?1????????1?1???????0??1?????????????1?0???????1?????????1?????????????1??00??0???0????????1??0??0?00??????11???????1??1??????????????1??????1??10?00?????????1????0???10?00??????01???10???1??00????????0?1???????0???1???0?1?????0?1???0?00????????1?????0?????0??010??1?1??????11?????????100???1???0??1????"
        p_, q_ = branch_and_prune.factorize_pqddpdq(N, e, PartialInteger.from_bits_be(p_bits), PartialInteger.from_bits_be(q_bits), PartialInteger.from_bits_be(d_bits), PartialInteger.from_bits_be(dp_bits), PartialInteger.from_bits_be(dq_bits))
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_complex_multiplication(self):
        # Recursion limit is necessary for calculating division polynomials using sage.
        rec_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(5000)

        p = 10577468517212308916917871367410399281392767861135513107255047025555394408598222362847763634342865553142272076186583012471808986419037203678594688627595231
        q = 8925960222192297437450017303748967603715694246793735943594688849877125733026282069058422865132949625288537523520769856912162011383285034969425346137038883
        N = p * q
        D = 427
        p_, q_ = complex_multiplication.factorize(N, D)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        sys.setrecursionlimit(rec_limit)

    def test_coppersmith(self):
        p = 8294118504611118345546466080325632607801907364697312317242368417303646025896249767645395912291329182895616276681886182303417327463669722370956110678857457
        q = 11472445399871949099065671577613972926185090427303119917183801667878634389108674818205844773744056675054520407290278050115877859333328393928885760892504569
        N = p * q

        p_, q_ = coppersmith.factorize_p(N, PartialInteger.msb_of(p, 512, 280), m=6, t=6)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_, q_ = coppersmith.factorize_p(N, PartialInteger.lsb_of(p, 512, 280), m=6, t=6)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_, q_ = coppersmith.factorize_p(N, PartialInteger.lsb_and_msb_of(p, 512, 140, 140), m=6, t=6)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_hex = "????????????720e5a53f32044328cffaef96e72cf6b8cdcc983748bdb6abc6437c96d17c578326bc80d634a03c57b3e25775f6b54e9be37a70f????????????"
        p_, q_ = coppersmith.factorize_p(N, PartialInteger.from_hex_be(p_hex), m=3, t=1)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_hex = "9e5cce87????720e5a53f32044328cffaef96e72cf6b8cdcc983748bdb6abc64????6d17c578326bc80d634a03c57b3e25775f6b54e9be37a70f????ab6e16f1"
        p_, q_ = coppersmith.factorize_p(N, PartialInteger.from_hex_be(p_hex), m=4, t=1)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_, q_ = coppersmith.factorize_pq(N, PartialInteger.msb_of(p, 512, 155), PartialInteger.lsb_of(q, 512, 155), k=4)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p_, q_ = coppersmith.factorize_pq(N, PartialInteger.lsb_of(p, 512, 155), PartialInteger.msb_of(q, 512, 155), k=4)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_fermat(self):
        p = 383885088537555147258860631363598239852683844948508219667734507794290658581818891369581578137796842442514517285109997827646844102293746572763236141308659
        q = 383885088537555147258860631363598239852683844948508219667734507794290658581818891369581578137796842442514517285109997827646844102293746572763236141308451
        N = p * q
        p_, q_ = fermat.factorize(N)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        p = 59
        q = 101
        N = p * q
        p_, q_ = fermat.factorize(N)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_gaa(self):
        rp = 34381
        rq = 34023
        p = 95071251890492896215829359101175428907421221364386877469905182082459875177459986258243302560246216190552021119341405678279166840212587310541906674474311515240972185868939740063531859593844606048709104560925568301977927216150294427162519810608935523631249827019496037479563371324790366397060798445963209377357
        q = 90298295824650311663818894095620747783372649281213396245855149883068750544736749865742151003212745876322858711152862555726263459709030033799784069102281145447897017439265777617772466042518218409294380111768917907088743454681904160308248752114524063081088402900608673706746438458236567547010845749956723115239
        N = p * q
        p_, q_ = gaa.factorize(N, rp, rq)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_known_phi(self):
        # These primes aren't special.
        p = 11106026672819778415395265319351312104517763207376765038636473714941732117831488482730793398782365364840624898218935983446211558033147834146885518313145941
        q = 12793494802119353329493630005275969260540058187994460635179617401018719587481122947567147790680079651999077966705114757935833094909655872125005398075725409
        N = p * q
        phi = (p - 1) * (q - 1)
        p_, q_ = known_phi.factorize(N, phi)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

        # Multi-prime case takes longer so there's a separate method.
        p = 10193015828669388212171268316396616412166866643440710733674534917491644123135436050477232002188857603479321547506131679866357093667445348339711929671105733
        q = 8826244874397589965592244959402585690675974843434609869757034692220480232437419549416634170391846191239385439228177059214900435042874545573920364227747261
        r = 7352042777909126576764043061995108196815011736073183321111078742728938275060552442022686305342309076279692633229512445674423158310200668776459828180575601
        s = 9118676262959556930818956921827413198986277995127667203870694452397233225961924996910197904901037135372560207618442015208042298428698343225720163505153059
        N = p * q * r * s
        phi = (p - 1) * (q - 1) * (r - 1) * (s - 1)
        p_, q_, r_, s_ = known_phi.factorize_multi_prime(N, phi)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertIsInstance(r_, int)
        self.assertIsInstance(s_, int)
        self.assertEqual(N, p_ * q_ * r_ * s_)

    def test_implicit(self):
        p_bit_length = 1024
        q_bit_length = 512
        t = 684
        p1 = 114078116454996138073318170170395300151527904793534256191938789983399536922395777111499295202803369554422196999085171496293035396121701314031895628788412353005299652082324755433547975515470738465391276343421170770833007677775061536204663181723877277783535322237577024424245899108264063112142009298991310208363
        q1 = 12098618010582908146005387418068214530897837924954238474768639057877490835545707924234415267192522442378424554055618356812999593976451240454748132615211091
        p2 = 114078116454996138073318170170395300151527904793534256191938789983399536922395777111499295202803369554422196999085171496293035396121701314031895628788412353005299652082324755433547975515470738465391276343420364306790694479071514320422685064042719135179664690266371525865249047670187055110695514824881157627139
        q2 = 6947349788273330265284965959588633765145668297542467009935686733076998478802274287263210169428313906535572268083136251282544180080959668222544545924665987
        p3 = 114078116454996138073318170170395300151527904793534256191938789983399536922395777111499295202803369554422196999085171496293035396121701314031895628788412353005299652082324755433547975515470738465391276343421225512127678851876291564787861171689610002001450319286946495752591223718157676932258249173072665300213
        q3 = 9266126880388093025412332663804790639778236438889018854356539267369792799981733933428697598363851162957322580350270024369332640344413674817822906997102161
        p4 = 114078116454996138073318170170395300151527904793534256191938789983399536922395777111499295202803369554422196999085171496293035396121701314031895628788412353005299652082324755433547975515470738465391276343421356808531436971239501427225110998678228016324130962852291540962098563998522061844259409194324238072163
        q4 = 9346194396330429861097524187193981265347523161493757436812567448933497111978504926263282763464402757659318174531608519618989854444686100976857830087136899
        N = [p1 * q1, p2 * q2, p3 * q3, p4 * q4]
        for i, (p, q) in enumerate(implicit.factorize_msb(N, p_bit_length + q_bit_length, t)):
            self.assertIsInstance(p, int)
            self.assertIsInstance(q, int)
            self.assertEqual(N[i], p * q)

        p_bit_length = 1024
        q_bit_length = 512
        t = 684
        p1 = 137676848178120053804151859930883725890803026594890273621717986880391033552896124307278203769389114417028688066268898176276364165645879838855204653941267370118703755611397682095578076818071918172477401067278492828257626897251549091543352809233324240524137497086302474085899298902638892888908168338819819232793
        q1 = 13166288667078358159532363247770104519199514211373352701434198635956864629466947059508438393840310722732010695913860165840076158141600542903957511858467599
        p2 = 155941871148496045943650517403022286219330266513190620694534749227433871940120353353030481603047425408777193957891989215447984590279121382305371103889682866866611645183334486259197241694690077730091496562828758139564286098307121800141566950170972849436331381375112592397181935508950663666559821018117710798361
        q2 = 8054287780708269262514472947823359228967255917411384941738106945448488928023325871002415540629545474428145043227927492187948846465762213369395150593287629
        p3 = 146542545226083477723264700810318219628590283511298968176573337385538577833243759669492317165475590615268753085678168828004241411544898671318095131587338794716729315057151379325654916607098703691695457183186825995894712193071356602411894624624795802572705076938306979030565015683237625719989339343497095536153
        q3 = 8348967325072059612026168622784453891507881426476603640658340020341944731532364677276401286358233081971838597029494396167050440290022806685890808240656759
        p4 = 167661072178525609874536869751051800065390422834592103113971975955391615118678036572040576294964853025982786705404563191397770270731849495157247117854529039983840787661878167379723898817843318578402737767598910576316837813336887274651599847119701845895279082627804568462120651226573750359206381471191410662937
        q4 = 8145167185335505501783087854760814147233023836090931783403657001079727963955491428876064700621053935085252069162037262941731093071208640285177101456231051
        N = [p1 * q1, p2 * q2, p3 * q3, p4 * q4]
        for i, (p, q) in enumerate(implicit.factorize_lsb(N, p_bit_length + q_bit_length, t)):
            self.assertIsInstance(p, int)
            self.assertIsInstance(q, int)
            self.assertEqual(N[i], p * q)

    def test_roca(self):
        # 39th primorial
        M = 962947420735983927056946215901134429196419130606213075415963491270
        # These primes are chosen such that a' is pretty small so it doesn't take too long.
        p = 85179386137518452231354185509698113331528483782580002217930594759662020757433
        q = 121807704694511224555991770528701515984374557330058194205583818929517699002107
        N = p * q
        p_, q_ = roca.factorize(N, M, 5, 6)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_shor(self):
        # Examples from the reference paper.
        p = 1789
        q = 1847
        N = p * q
        p_, q_ = shor.factorize(N, 751228, 78)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)
        p = 12343
        q = 12391
        N = p * q
        p_, q_ = shor.factorize(N, 2, 4247705)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_twin_primes(self):
        p = 4045364040964617981493056570547683620499113851384489798802437290109120991898115799819774088264427282611552038114397865000343325953101387058967136608664301
        q = 4045364040964617981493056570547683620499113851384489798802437290109120991898115799819774088264427282611552038114397865000343325953101387058967136608664303
        N = p * q
        p_, q_ = twin_primes.factorize(N)
        self.assertIsInstance(p_, int)
        self.assertIsInstance(q_, int)
        self.assertEqual(N, p_ * q_)

    def test_unbalanced(self):
        p = 1433938093315599755046338614632963182511799724473707138946120072339529238087691812744243192529882346617371303296059072558057980700438427880048167685845684013453445681299294196910926933861675010962700117719294288854010351257154136663
        q = 64056043407867714782092549432658752846651715364072065058125051763204024699203
        N = p * q

        partial_p = PartialInteger.middle_of(p, 768, 1, 252)
        p_, q_ = unbalanced.factorize(N, partial_p, 256, m=1, t=0)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        self.assertIsInstance(q_, int)
        self.assertEqual(q, q_)

        partial_p = PartialInteger.middle_of(p, 768, 10, 244)
        p_, q_ = unbalanced.factorize(N, partial_p, 256, m=2, t=0)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        self.assertIsInstance(q_, int)
        self.assertEqual(q, q_)

        partial_p = PartialInteger.middle_of(p, 768, 128, 126)
        p_, q_ = unbalanced.factorize(N, partial_p, 256, m=2, t=0)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        self.assertIsInstance(q_, int)
        self.assertEqual(q, q_)

        partial_p = PartialInteger.msb_of(p, 768, 514)
        p_, q_ = unbalanced.factorize(N, partial_p, 256, m=2, t=0)
        self.assertIsInstance(p_, int)
        self.assertEqual(p, p_)
        self.assertIsInstance(q_, int)
        self.assertEqual(q, q_)
