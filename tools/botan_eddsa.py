# Teaches Botan's TLS 1.3 (3.14.1's amalgamation) to offer and verify the
# EdDSA signature schemes SMP routers' certificates use: Botan leaves
# Ed25519 and Ed448 out of its available TLS signature schemes on purpose
# (botan#2958). Usage: botan_eddsa.py botan_all.cpp
import sys
p = sys.argv[1]
s = open(p).read()
if "quay: EdDSA" in s:
    print("already patched"); sys.exit(0)
old_list = """   static const std::vector<Signature_Scheme> all_schemes = {
"""
assert s.count(old_list) == 1, "all_available_schemes"
s = s.replace(old_list, old_list + """      // quay: EdDSA, as SMP routers' certificates are signed
      EDDSA_25519,
      EDDSA_448,
""")
old_avail = """bool Signature_Scheme::is_available() const noexcept {
   switch(m_code) {
"""
assert s.count(old_avail) == 1, "is_available"
s = s.replace(old_avail, old_avail + """      case EDDSA_25519:  // quay: EdDSA
      case EDDSA_448:
         return true;
""")
open(p, "w").write(s)
print("patched")
