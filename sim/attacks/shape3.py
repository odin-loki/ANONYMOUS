import numpy as np
from shapeability import shape_cost
rng = np.random.default_rng(101)
N=120000

def lognormal_counts(sigma, n, m=10.0):
    return np.clip(np.round(rng.lognormal(np.log(m)-sigma*sigma/2, sigma, n)),0,None)
def pareto_counts(a, n, m=10.0):
    xm=m*(a-1)/a if a>1 else m*0.3
    return np.clip(np.round((rng.pareto(a,n)+1)*xm),0,None)

# find min provisioning c s.t. p99 deferral <= budget slots
def min_c(counts, budget=5.0):
    for c in np.arange(1.1, 6.05, 0.1):
        if shape_cost(counts, c)["p99"] <= budget:
            return round(float(c),1)
    return None  # not shapeable within c<=6

print("=== SHAPEABILITY THRESHOLD: min bandwidth mult c for p99 defer <= 5 slots ===\n")
print(f"{'marginal':<18}{'CV':>7}{'finite var?':>12}{'min c (bw mult)':>16}")
print("-- lognormal (finite variance, tail grows with sigma) --")
for s in [0.2,0.5,0.8,1.1,1.4,1.8]:
    x=lognormal_counts(s,N); cv=x.std()/x.mean(); c=min_c(x)
    print(f"{'lognormal s='+str(s):<18}{cv:>7.2f}{'yes':>12}{str(c) if c else '>6 (no)':>16}")
print("-- Pareto (infinite variance when a<=2) --")
for a in [3.0,2.5,2.1,1.8,1.5]:
    x=pareto_counts(a,N); cv=x.std()/x.mean(); c=min_c(x)
    fv = 'yes' if a>2 else 'NO(inf)'
    print(f"{'pareto a='+str(a):<18}{cv:>7.2f}{fv:>12}{str(c) if c else '>6 (no)':>16}")
print("\nRule of thumb: finite-variance marginals up to CV~1 shapeable at c<=2.")
print("Infinite-variance tails (Pareto a<2) are NOT shapeable at bounded cost.")
