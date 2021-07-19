#include <iostream>
#include <cstring>
#include <assert.h>
#include <gmpxx.h>

#define ROUNDS 0x1333337

using namespace std;

mpz_class A, B, C, P, _A, _2;
mpz_class BASE, FIELD;


class EF {
public:
	mpz_class u, v;
	EF(){};
	EF(const EF& o) {
		u = o.u;
		v = o.v;
	}
};

mpz_class F(mpz_class x) {
	return (((A * x) + B) * x + C) % P;
}

mpz_class T(mpz_class x) {
	return ((x * A) + B / 2) % P;
}

mpz_class _T(mpz_class x) {
	return (x - B / 2) * _A % P;
}

/*
EF mul(const EF &a, const EF &b) {
	EF c();
	c.u = (a.u * b.u + a.v * b.v % P * FIELD) % P;
	c.v = (a.u * b.v + a.v * b.u) % P;
	return c;
}
*/
void mul1(EF &a, const EF &b) {
	mpz_class u = a.u, v = a.v;
	a.u = (u * b.u + v * b.v % P * FIELD) % P;
	a.v = (u * b.v + v * b.u) % P;
}

void mul2(EF &a) {
	mpz_class v = a.u * a.v * 2 % P;
	a.u = (a.u * a.u + a.v * a.v % P * FIELD) % P;
	a.v = v;
}

EF pow(EF x, mpz_class n) {
	EF r;
	r.u = 1; r.v = 0;;
	while (n > 0) {
		if (n % 2 == 1) {
			//r = mul(r, x);
			mul1(r, x);
		}
		n >>= 1;
		//x = mul(x, x);
		mul2(x);
	}
	return r;
}

mpz_class pow(mpz_class x, long long n, mpz_class mod) {
	mpz_class r = 1;
	while (n) {
		if (n & 1)
			r = r * x % mod;
		n >>= 1;
		x = x * x % mod;
	}
	return r;
}

mpz_class G(mpz_class k, long long n) {
	if (!n) return k;
	FIELD = (k * k - 4) % P;
	EF x1, x2;
	x1.u = k * _2 % P;
	x1.v = _2;
	x2.u = x1.u;
	x2.v = (P - 1) * _2 % P;
	mpz_class n_ = pow(2, n - 1, P * P - 1);
	EF xn1 = pow(x1, n_);
	EF xn2 = pow(x2, n_);
	//assert((xn1.v + xn2.v) % P == 0);
	return (xn1.u + xn2.u) % P;
}

uint32_t tail(mpz_class x) {
	x = x % BASE;	
	return x.get_ui();
}

int main() {
	A = "645355246";
	B = "17587344665267433444";
	C = "16443808597681565772";
	P = "571787215471557516425591";
	_A = "111736845616070530385698";
	_2 = "285893607735778758212796";

	BASE = 0xffffffff;
	BASE = BASE + 1;

	/*
	mpz_class x = 12321;
	cout << F(F(x)) << endl;
	cout << _T(G(T(x), 3)) << endl;
	*/

	FILE *f = fopen("flag.enc", "r");
	if (f == NULL) {
		perror("fopen");
		exit(1);
	}
	fseek(f, 0, SEEK_END);
	size_t l = ftell(f);
	rewind(f);
	uint32_t *plain = (uint32_t *)new char[l + 1];
	uint32_t *cipher = (uint32_t *)new char[l + 1];
	fread(cipher, 1, l, f);
	fclose(f);
	printf("FILE SIZE: %lu\n", l);

	uint32_t check = cipher[0] ^ 1718903600LL;
	memset(plain, 0, sizeof(char) * (l + 1));

	//int i = 0x18acf1L;
	for (int i = 0; i < 0x200000; i++) {
		if (i % 0x1000 == 0) printf("now 0x%x\n", i);
		mpz_class x = i;
		x = _T(G(T(i), ROUNDS + 1));
		//cout << x << endl;
		x = F(x);
		//cout << x << endl;
		if (tail(x) != check) continue ;
		for (int j = 0; 4 * j < l; j++) {
			plain[j] = cipher[j] ^ tail(x);
			//printf("%08x %08x %08x\n", cipher[j], tail(x), plain[j]);
			x = F(x);
		}
		cout << FIELD << endl;
		printf("FOUND!\n");
		puts((const char *)plain);
	}

	return 0;
}
