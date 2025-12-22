#include <bits/stdc++.h>
using namespace std;

static uint64_t modMul(uint64_t a, uint64_t b, uint64_t m) {
    return (unsigned __int128)a * b % m;
}

static uint64_t modPow(uint64_t base, uint64_t exp, uint64_t m) {
    uint64_t res = 1;
    while (exp) {
        if (exp & 1) res = modMul(res, base, m);
        base = modMul(base, base, m);
        exp >>= 1;
    }
    return res;
}

static uint64_t findPsi(uint64_t q, uint64_t n) {
    uint64_t k = 2 * n;
    uint64_t order_factor = (q - 1) / k;
    for (uint64_t g = 2; g < q; ++g) {
        uint64_t cand = modPow(g, order_factor, q); // order divides k
        if (modPow(cand, k, q) != 1) continue;
        // ensure no smaller power gives 1, and cand^{k/2} = -1
        bool ok = true;
        uint64_t tmp_k = k;
        while (tmp_k % 2 == 0 && tmp_k > 1) {
            tmp_k /= 2;
            if (modPow(cand, tmp_k, q) == 1) { ok = false; break; }
        }
        if (!ok) continue;
        if (modPow(cand, k/2, q) != q-1) continue;
        return cand;
    }
    return 0;
}

int main() {
    vector<pair<uint64_t,uint64_t>> params = {
        {8, 7681},
        {32, 7681},
        {256, 7681},
        {512, 12289},
        {1024, 18433},
    };
    for (auto [n,q] : params) {
        cout << "n=" << n << " q=" << q << "\n";
        uint64_t k = 2*n;
        if ((q-1) % k != 0) {
            cout << "  (q-1) not divisible by 2n!" << "\n";
            continue;
        }
        uint64_t psi = findPsi(q, n);
        cout << "  psi=" << psi << "\n";
        if (psi) {
            cout << "  psi^(2n) mod q = " << modPow(psi, 2*n, q) << "\n";
            cout << "  psi^n mod q = " << modPow(psi, n, q) << " (should be q-1=" << (q-1) << ")\n";
        }
    }
}
