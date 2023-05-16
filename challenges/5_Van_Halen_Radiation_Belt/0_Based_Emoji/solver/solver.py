#!/usr/bin/env python3

from pwn import *
import sys

context.log_level="debug"

class Emoji:
    def __init__(self, em, b=5, factors=None, num=999, binary=None):
        if factors is None:
            factors = [1]
        self.emoji = em
        self.factors = factors
        self.bits = b
        self.num = num
    
    def __str__(self):
        return self.emoji + ' = ' + str(self.num) + ' and has factors {' + ', '.join(str(f) for f in self.factors) + '}'
    
    def set_factors(self, f):
        self.factors = f
    
    def is_prime(self):
        if len(self.factors) <= 2:
            return True
        else:
            return False
    
    def set_binary(self):
        num_str = bin(self.num)[2:]
        left_padding = len(num_str) + (self.bits - (len(num_str) % self.bits))
        num_str = num_str.zfill(left_padding)
        self.binary = [num_str[i:i + self.bits] for i in range(0, len(num_str), self.bits)]
    
    def __eq__(self, other):
        if isinstance(other, Emoji):
            return self.num == other.num
        return NotImplemented
    
    def __ne__(self, other):
        if isinstance(other, Emoji):
            return self.num != other.num
        return NotImplemented
    
    def __lt__(self, other):
        if isinstance(other, Emoji):
            return self.num < other.num
        return NotImplemented
    
    def __le__(self, other):
        if isinstance(other, Emoji):
            return self.num <= other.num
        return NotImplemented
    
    def __gt__(self, other):
        if isinstance(other, Emoji):
            return self.num > other.num
        return NotImplemented
    
    def __ge__(self, other):
        if isinstance(other, Emoji):
            return self.num >= other.num
        return NotImplemented


def decode_emoji(emoji_str, ordered_emojis):
    bin_str = ''
    for em in emoji_str:
        bin_str = bin_str + str(bin(ordered_emojis.index(em)))[2:].zfill(5)
    return int(bin_str, 2)


def decrypt_answer(answer, ordered_emojis, e, n):
    decoded = decode_emoji(answer, ordered_emojis)
    decrypted = decrypt(decoded, ordered_emojis, e, n)
    print('\n' + decrypted.to_bytes((decrypted.bit_length() + 7) // 8, sys.byteorder).decode('utf-8') + '\n')


def decrypt(msg, ordered_emojis, e, n):
    return pow(msg, decode_emoji(e, ordered_emojis), decode_emoji(n, ordered_emojis))


def sort_emojis(ans):
    return sorted(ans, key=lambda num: num.num)


def print_ans(ans):
    for number in sort_emojis(ans):
        print(number)


def update_ans_number(em, num, ans, known_emojis):
    for i in ans:
        if i.emoji == em:
            i.num = num
            known_emojis[em] = num

    return [ans, known_emojis]


def get_new_prime(b, p:remote):
    p.recvuntil('🇪 🇽 🇮 🇹 '.encode())
    p.sendline('3⃣'.encode())
    p.recvuntil('🇭 🇴 🇼   🇲 🇦 🇳 🇾   🇧 🇮 🇹 🇸 ❓ '.encode())
    p.sendline(b.encode())
    p.recvline().decode()
    facts = p.recvline().decode()
    return facts

def update_factors(ans, known_emojis):
    for a in ans:
        updated_fact = []
        for f in a.factors:
            if f in known_emojis.keys():
                updated_fact.append(known_emojis.get(f))
            else:
                updated_fact.append(f)
        a.factors = updated_fact

    return ans

def solve(p: remote):

    ans = []
    known_emojis = {}
    ordered_emojis = []

    p.recvuntil('🇳   🟰   '.encode())
    n = p.recvline().decode().strip()
    p.recvuntil('🇪   🟰   '.encode())
    e = p.recvline().decode().strip()

    p.recvuntil('0⃣   🟰   '.encode())
    emoji = p.recvline().decode().strip()
    ans.append(Emoji(emoji, num=0, factors=[0]))
    known_emojis[emoji] = 0
    p.recvuntil('1⃣   🟰   '.encode())
    emoji = p.recvline().decode().strip()
    ans.append(Emoji(emoji, num=1))
    known_emojis[emoji] = 1
    p.recvuntil('2⃣   🟰   '.encode())
    emoji = p.recvline().decode().strip()
    ans.append(Emoji(emoji, num=2, factors=[1, 2]))
    known_emojis[emoji] = 2

    p.recvuntil('🇨   🟰   '.encode())
    encoded_flag = p.recvline().decode().strip()

    emoji_set = set()
    for emoji in encoded_flag:
        emoji_set.add(emoji)

    # print(emoji_set)
    # print(len(emoji_set))

    p.recvuntil('🇲 🇪 🇳 🇺 '.encode()).decode()


    for emoji in emoji_set:
        if emoji not in (ans[0].emoji, ans[1].emoji, ans[2].emoji):
            p.recvuntil('🇪 🇽 🇮 🇹 '.encode())
            p.sendline('1⃣'.encode())
            p.recvuntil('🇫 🇦 🇨 🇹 🇴 🇷 🇸   🇴 🇫 ❓'.encode())
            p.sendline(emoji.encode())
            p.recvline().decode()
            factors = p.recvline().decode().strip().replace('  ', '')
            fact_list = []
            for fact in factors:
                if fact in known_emojis.keys():
                    fact_list.append(known_emojis.get(fact))
                else:
                    fact_list.append(fact)
            ans.append(Emoji(emoji, factors=fact_list))

    [ans, known_emojis] = update_ans_number('📡', 4, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('💩', 8, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('🥵', 16, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('🦍', 3, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('🛸', 6, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('🌟', 9, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('💾', 27, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('💽', 12, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('💥', 24, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('💵', 18, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('🌎', 5, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('🧠', 15, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('👀', 10, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('🌛', 30, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('🤯', 25, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('📼', 20, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('🚀', 7, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('🧨', 14, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('🗿', 21, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('🍌', 28, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('🔥', 11, ans, known_emojis) # 5x for 6-bit numbers 11x for 7-bit
    [ans, known_emojis] = update_ans_number('💯', 22, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('🌝', 13, ans, known_emojis) # 4x for 6-bit numbers 9x for 7-bit
    [ans, known_emojis] = update_ans_number('🌞', 26, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('🤟', 19, ans, known_emojis) # 3x for 6-bit numbers 6x for 7-bit
    [ans, known_emojis] = update_ans_number('👽', 17, ans, known_emojis) # 3x for 6-bit numbers 7x for 7-bit
    [ans, known_emojis] = update_ans_number('🙌', 29, ans, known_emojis)
    [ans, known_emojis] = update_ans_number('👄', 31, ans, known_emojis)

    [ans, known_emojis] = update_ans_number('🧂', 23, ans, known_emojis)

    ans = update_factors(ans, known_emojis)
    # print_ans()


    # print(get_new_prime('6⃣'))

    for emoji in sort_emojis(ans):
        ordered_emojis.append(emoji.emoji)
    

    decrypt_answer(encoded_flag, ordered_emojis, e, n)

    # p.interactive()

if __name__ == "__main__":
    # get host from environment
    hostname = os.getenv("CHAL_HOST", "localhost")
    if not hostname:
        print("No HOST supplied from environment")
        sys.exit(-1)

    # get port from environment
    port = int(os.getenv("CHAL_PORT","12345"))
    if port == 0:
        print("No PORT supplied from environment")
        sys.exit(-1)

    
    # get ticket from environment
    ticket = os.getenv("TICKET")

    r = remote( hostname , port )
    
    if ticket is not None:
        # Do a ticket submission
        r.recvuntil(b"Ticket please:")
        r.sendline(bytes(ticket, 'utf-8'))

    solve(r)
