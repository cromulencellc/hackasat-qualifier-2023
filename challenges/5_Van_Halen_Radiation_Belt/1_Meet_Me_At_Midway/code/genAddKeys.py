import random
import json
from collections import Counter

def displayKeys(keylist):
    for row in keylist:
        for col in keylist:
            product = row * col
            print(product, end = "\t")
            break


def duplicateCharacter(input):
# creating the dictionary by using counter method having strings as key and its frequencies as value
    string = Counter(input)
   # Find the number of occurrence of a character and getting the index of it.
    for char, count in string.items():
      if (count > 1):
         return False

    return True

random.seed(12345)

randomList=list()
i = 0
while i < 365:
    # generating a random number to create 5 digit additive keys
    r=random.randint(10000,99999)
    # checking whether the generated random number is not in the
    # randomList
    if duplicateCharacter(str(r)):
        if r not in randomList:
                # appending the random number to the resultant list, if the condition is true
            randomList.append(r)
            i += 1

print(len(randomList))
print(randomList)

print(f"Saving {len(randomList)} additive keys to additive_keys.json")
jsonString = json.dumps(randomList)
jsonFile = open("additive_keys.json", "w")
jsonFile.write(jsonString)
jsonFile.close()

print("Reading list from json")
# Opening JSON file
f = open("additive_keys.json")



