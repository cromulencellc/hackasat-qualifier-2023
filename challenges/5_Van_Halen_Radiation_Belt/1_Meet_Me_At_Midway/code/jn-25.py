import json
import re
import argparse


def read_codegroups(fn):
    worddict = dict()
    try:
        f = open (fn, "r")
        worddict = json.load(f)
    except:
        print("***  Error opening dictionary file.")

    return worddict


def read_additives(fn):
    addlist = list()
    try:
        f = open(fn, "r")
        addlist = json.load(f)
    except:
        print(f"***  Error opening additive key file")

    return addlist


def read_msgs(fn):
    msglist = list()
    try:
        f = open(fn,"r")
        for ln in f:
            msglist.append(ln)
    except:
        print(f"Error opening messages file")

    return msglist


class JN_25_EncodeDecode:
    def __init__(self, codes, keys, prnt):
        self.code_dict = codes
        self.key_list = keys
        
        if prnt == "full":
            print(f"num words in dictionary: {len(self.code_dict)}")
            print(f"num keys defined: {len(self.key_list)}")


    def resetAddKeyIndex(self, julianDay):
        self.keyindex = julianDay % len(self.key_list)
        self.nextAddKey = self.keyindex
        #print(f"rst: nextAddKey: {self.nextAddKey}, keyindex: {self.keyindex}")

        
    def getNextAddKey(self):
        key = self.key_list[self.nextAddKey]
        self.nextAddKey = self.nextAddKey + 1
        if (self.nextAddKey >= len(self.key_list)):
            self.nextAddKey = 0
            
        #print(f"get: nextAddKey: {self.nextAddKey}, keyindex: {self.keyindex}, key: {key}")
        return key
    

    def do_decrypt(self, encr_code, sub_key):
        decr_str = ''
        for e in range(len(encr_code)):
            dc = (int(encr_code[e])-int(sub_key[e]))%10
            decr_str = decr_str + str(dc)

        return(decr_str)


    def do_encrypt(self, code_group, add_key):
        encr_str = ''
        for d in range(len(code_group)):
            ec = (int(code_group[d]) + int(add_key[d])) % 10
            encr_str = encr_str + str(ec)

        return encr_str


    def cvt_msg2codes( self, msg ):
        cg_list = msg.split()
        coded_msg = list()
        for wrd in cg_list:
            wrd = re.sub(r"[^a-zA-Z0-9]","",wrd)
            found = False
            for d in self.code_dict:
                if (wrd == self.code_dict[d]):
                    coded_msg.append(d)
                    found = True
                    break
            if found == False:
                print(f"{wrd} not found in dictionary")

        return coded_msg

    
    def encode_msg( self, in_msg ):
        coded_msg = self.cvt_msg2codes( in_msg )
        if (coded_msg == []):
            print(f"Could not code {in_msg} into code groups")

        return coded_msg
    

    def decode_msg( self, enc_msg ):
        dec_msg = ""
        for enc_gp in enc_msg:
            for d in self.code_dict:
                if (enc_gp == d):
                    dec_msg = dec_msg + self.code_dict[d] + " "
                    break
        
        return dec_msg


    def encrypt_msg( self, msg ):
        full_msg = list()
        for i in range(len(msg)):
            code_gp = msg[i]
            add_key = str(self.getNextAddKey())
            #print(f"en: {self.nextAddKey}:{add_key}")
            ency = self.do_encrypt(code_gp,add_key)

            full_msg.append(ency)

        return full_msg


    def decrypt_msg( self, en_msg ):
        full_msg = list()
        for i in range(len(en_msg)):
            code_gp = en_msg[i]
            add_key = str(self.getNextAddKey())
            #print(f"de: {self.nextAddKey}:{add_key}")
            dec = self.do_decrypt(code_gp,add_key)

            full_msg.append(dec)

        return full_msg


def run(args):

    codefile = args.dict
    keyfile = args.keys
    julianday = int(args.jday)
    rundays = int(args.days)
    printstyle = args.p
    msgs = list()
    if args.mlist == None:
        msgs.append(args.msg)
    else:
        msgs = read_msgs(args.mlist)
        if len(msgs) == 0:
            print(f"No messages read from {args.mlist}")
            #return

    code_dict = read_codegroups(codefile)
    key_list = read_additives(keyfile)

    do_JS = JN_25_EncodeDecode(code_dict,key_list, printstyle)
    
    jday = julianday-1
    lastday = (julianday+rundays)-1
    enMsgList = list()

    for msg in msgs:
        #print(f"run: jday: {jday}")
        msg = msg.upper()
        do_JS.resetAddKeyIndex(jday)
        coded_msg = do_JS.encode_msg(msg)
        encrypted_msg = do_JS.encrypt_msg(coded_msg)
        enMsgList.append(encrypted_msg)
        do_JS.resetAddKeyIndex(jday)
        decrypted_msg = do_JS.decrypt_msg(encrypted_msg)
        decoded_msg = do_JS.decode_msg(decrypted_msg)

        if printstyle == "full":
            print(f"Today is {jday+1}")
            print(f"plain text: {msg}")
            print(f"julian day: {jday}")
            print(f"encoded:    {coded_msg}")
            print(f"encrypted:  {encrypted_msg}")
            print(f"decrypted:  {decrypted_msg}")
            print(f"decoded txt {decoded_msg}")
        else:
            print(f"{encrypted_msg}")
        
        jday += 1



if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--msg", default='start Now is the time for all great space mathematicians to come out and play stop')
    parser.add_argument("--mlist", default=None)
    parser.add_argument("--dict", default='code/data/word_dictionary.json')
    parser.add_argument("--keys", default='code/data/additive_keys.json')
    parser.add_argument("--jday", default=1)
    parser.add_argument("--days", default=1)
    parser.add_argument("--p", default='full')
    args = parser.parse_args()

    run(args)
