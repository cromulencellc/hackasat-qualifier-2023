
outfile = open("temp.txt","w")

with open ("HGWellFirstMenOnTheMoon.txt", "r") as txtfile:
        
    for rawtxt in txtfile:
        temptxt = rawtxt.split()
        if len(temptxt) != 0:
            print(f"<{rawtxt}>")
            outfile.write(rawtxt)
outfile.close()