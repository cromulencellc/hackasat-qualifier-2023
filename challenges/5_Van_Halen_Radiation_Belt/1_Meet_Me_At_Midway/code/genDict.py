import re
import json


# Generates a code group dictionary file for input to other 
# encryption/decrytion sw.

def nextCodeGroup(currcg):
    cg = currcg + 1
    while (cg%3) != 0:
        cg += 1
        if cg > 99999:
            print("Out of key values, return zero")
            return 0

    return cg


word_list = list()
word_dict = {}

other_words = ["congradulations","challenge"]

#add digits to the word list
index = 0
while index < 10:
    word_list.append(str(index))
    index += 1

#make sure specific words are in the dictionary
for wrd in other_words:
    wrd = wrd.upper()
    word_list.append(wrd)
    
print("Reading text file, creating list of unique words in file...")
with open ("HGWellFirstMenOnTheMoon.txt", "r") as txtfile:

    for rawtxt in txtfile:
        txt = rawtxt.split()
        if len(txt) == 0:
            continue
        #print("\n--------------------------------")
        #print(f"line: {txt}")

        for wrd in txt:
            wrd = wrd.upper()

            wrd = re.sub(r"[^a-zA-Z0-9]","",wrd)
            if wrd in word_list:
            #    print(f"Rejecting duplicate: {wrd}")
                continue

            word_list.append(wrd)


codegroup = 10000
print("Building word dictionary...")
for wrd in word_list:
    word_dict[str(codegroup)] = wrd
    codegroup = nextCodeGroup(codegroup)

print("Saving dictionary to json file...")
with open("word_dictionary.json", 'w') as fp:
    json.dump(word_dict, fp)
