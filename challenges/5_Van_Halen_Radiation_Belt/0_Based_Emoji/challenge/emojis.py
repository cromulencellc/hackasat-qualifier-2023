from string import *
import config as c
from random import *


emojis = ["🤯", "📡", "👽", "👄", "🧠", "🌞", "🌝", "🌛",
          "🌎", "🌟", "💥", "🔥", "💩", "🦍", "🧂", "🚀",
          "🛸", "🗿", "💽", "💾", "🍌", "📼", "🥵", "💵",
          "🎉", "🧨", "💯", "🤟", "🥃", "🙌", "👀", "🛰"
          ]

alpha = ["🇦", "🇧", "🇨", "🇩", "🇪", "🇫", "🇬", "🇭", "🇮", "🇯", "🇰", "🇱", "🇲",
         "🇳", "🇴", "🇵", "🇶", "🇷", "🇸", "🇹", "🇺", "🇻", "🇼", "🇽", "🇾", "🇿"]

digs = ["0⃣", "1⃣", "2⃣", "3⃣", "4⃣", "5⃣", "6⃣", "7⃣", "8⃣", "9⃣"]


def printer(vanilla_string):
    emoji_string = ''
    for ch in vanilla_string:
        if ch in ascii_letters:
            index = ascii_letters.index(ch) % 26
            # need the space, or it'll print garbage, could try list and join
            emoji_string += alpha[index] + " "
        elif ch in digits:
            index = digits.index(ch)
            emoji_string += digs[index] + " "
        elif ch == ' ':
            emoji_string += "  "
        elif ch == "?":
            emoji_string += '❓' + " "
        elif ch == "!":
            emoji_string += '❗' + ' '
        elif ch == "=":
            emoji_string += "🟰" + ' '
        elif ch == "-":
            emoji_string += "➖" + ' '
        else:
            emoji_string += ' ' + ch + ' '
    return emoji_string


def select_emojis():
    return Random(0).sample(emojis, k=c.emoji_base)
