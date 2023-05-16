import os
import random

emoji_base = 32
encryption_bit_size = 1024
e = 65537
# seed = 0
seed = random.getrandbits(256)
# print(f"Seed = {seed}")
# 🌱 for seed or at least the variable name or add it back to emoji list
# seed = os.getenv("SEED", "SEED_NOT_SET_SEE_ADMIN")

#flag = "🚨 🚨 🚨 flag{3this-is-2a-test-flag1-for-testing} 🚨 🚨 🚨"
flag = os.getenv("FLAG", "FLAG_NOT_SET_SEE_ADMIN")
