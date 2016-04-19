# hints
pow(5519117190405, 2, 36620698197184150886934780417736785899286763272338791747362963184841801750327151112306249688251166942886661835559506975975707963993727412454531111131497522628925665187177482321006716251711989384331015718920870220319989803289027643830003689665702600492053982320351954323958550720798506779897617401364619613169464060947339101271843599172133534443261538683960602107804087030956000675854087181711124213887850946702876663207624764500658667089502719100806234117)

See PCTF 2011 - [Division is Hard](https://www.bpak.org/blog/wp-content/uploads/1/1334520955.pdf), PCTF 2012 - [Addition is Hard](https://eindbazen.net/2012/04/plaid-ctf-2012-addition-is-hard/), and PCTF 2014 - [Multiplication is Hard](https://github.com/ctfs/write-ups-2014/tree/master/plaid-ctf-2014/multiplication-is-hard)... 

Exponentiation was hard even in 2015.

# solution
This must reference a bug with exponentiation from 2015!
Sure enough you end up with a [blog article](https://blog.fuzzing-project.org/31-Fuzzing-Math-miscalculations-in-OpenSSLs-BN_mod_exp-CVE-2015-3193.html) documenting a bug with the BN\_mod\_exp function in openSSL.

You fetch the openSSL source and build the commit which introduced the bug
```
git clone https://github.com/openssl/openssl.git && cd openssl
git checkout 72a158703bf2b33f4eba6920302941560f7a848d
./Configure linux-x86_64
make depend
make
```

Quickly reading through the [API documentation](https://www.openssl.org/docs/manmaster/crypto/bn.html) you end up with the following code
```C
#include <openssl/bn.h>
#include <stdio.h>

int main() {
        unsigned long a = 5519117190405UL;
        unsigned long b = 2UL;
        char* dec;
        unsigned long c = 36620698197184150886934780417736785899286763272338791747362963184841801750327151112306249688251166942886661835559506975975707963993727412454531111131497522628925665187177482321006716251711989384331015718920870220319989803289027643830003689665702600492053982320351954323958550720798506779897617401364619613169464060947339101271843599172133534443261538683960602107804087030956000675854087181711124213887850946702876663207624764500658667089502719100806234117UL;
        BN_CTX * ctx = BN_CTX_new();
        BIGNUM * biga = BN_new();
        BIGNUM * bigb = BN_new();
        BIGNUM * bigc = BN_new();
        BIGNUM * bigr = BN_new();

        BN_set_word(biga, a);
        BN_set_word(bigb, b);
        BN_set_word(bigc, c);

        BN_mod_exp(bigr, biga, bigb, bigc, ctx);
        dec = BN_bn2dec((const BIGNUM*)bigr);
        printf("Results is %s\n", dec);

        BN_CTX_free(ctx);
        BN_free(biga);
        BN_free(bigb);
        BN_free(bigc);
        BN_free(bigr);
        return 0;
}
```

But of course the third argument is too large to fit in a single word. BIGNUMs can be constructed from char arrays though. The number must be converted to hexadecimal.

`echo "ibase=10; obase=16; 36620698197184150886934780417736785899286763272338791747362963184841801750327151112306249688251166942886661835559506975975707963993727412454531111131497522628925665187177482321006716251711989384331015718920870220319989803289027643830003689665702600492053982320351954323958550720798506779897617401364619613169464060947339101271843599172133534443261538683960602107804087030956000675854087181711124213887850946702876663207624764500658667089502719100806234117" | bc`

```C
#include <openssl/bn.h>
#include <stdio.h>

int main() {
        unsigned long a = 5519117190405UL;
        unsigned long b = 2UL;
        char* dec;
        int size = 189;
        unsigned char c[] = "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x27\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05";
        BN_CTX * ctx = BN_CTX_new();
        BIGNUM * biga = BN_new();
        BIGNUM * bigb = BN_new();
        BIGNUM * bigc = BN_new();
        BIGNUM * bigr = BN_new();

        BN_set_word(biga, a);
        BN_set_word(bigb, b);
        BN_bin2bn(c, size, bigc);

        BN_mod_exp(bigr, biga, bigb, bigc, ctx);
        dec = BN_bn2dec((const BIGNUM*)bigr);
        printf("Results is %s\n", dec);

        BN_CTX_free(ctx);
        BN_free(biga);
        BN_free(bigb);
        BN_free(bigc);
        BN_free(bigr);
        return 0;
}
```
Compile and run with openSSL and you get :
```
Results is 29296558557747320709547824334189428719429410617871033397890370547873441400261720889844999750600933554309329468447605580780566371194981940040330208279577761448880054049348109773576225504890042857619120715573043725452275367606729448288645285053191142223833047708268546823777056416619931113490244805925745537277253024155149478728555769085617744635667809423646431371656102168171996972335742097996336871368711496457700457126737808780754180057328662036563571229
```
Success!

For fun, running the same code against the most recent openSSL gives :
```
Results is 30460654561423981024064025
```
