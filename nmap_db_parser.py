# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
import sys
import re
import pandas as pd
import numpy as np
import itertools
from nmap_db_parser_responses_format import *

# %%
probes_sent_dict = {
    'SEQ': re.compile(r'SEQ\((?P<SEQ>.*)\)'),
    'OPS': re.compile(r'OPS\((?P<OPS>.*)\)'),
    'WIN': re.compile(r'WIN\((?P<WIN>.*)\)'),
    'ECN': re.compile(r'ECN\((?P<ECN>.*)\)'),
    'T1': re.compile(r'T1\((?P<T1>.*)\)'),
    'T2': re.compile(r'T2\((?P<T2>.*)\)'),
    'T3': re.compile(r'T3\((?P<T3>.*)\)'),
    'T4': re.compile(r'T4\((?P<T4>.*)\)'),
    'T5': re.compile(r'T5\((?P<T5>.*)\)'),
    'T6': re.compile(r'T6\((?P<T6>.*)\)'),
    'T7': re.compile(r'T7\((?P<T7>.*)\)'),
    'U1': re.compile(r'U1\((?P<U1>.*)\)'),
    'IE': re.compile(r'IE\((?P<IE>.*)\)'),
}

test_parser = re.compile(r'(?P<key>.*)=(?P<value>.*)')

fingerprint_template = {
    'Class.vendor':[np.nan],
    'Class.OSfamily':[np.nan],
    'Class.OSgen':[np.nan],
    'Class.device':[np.nan],

    'SEQ.SP':[np.nan],
    'SEQ.GCD':[np.nan],
    'SEQ.ISR':[np.nan],
    'SEQ.TI':[np.nan],
    'SEQ.CI':[np.nan],
    'SEQ.II':[np.nan],
    'SEQ.SS':[np.nan],
    'SEQ.TS':[np.nan],

    'OPS.O1':[np.nan],
    'OPS.O2':[np.nan],
    'OPS.O3':[np.nan],
    'OPS.O4':[np.nan],
    'OPS.O5':[np.nan],
    'OPS.O6':[np.nan],

    'WIN.W1':[np.nan],
    'WIN.W2':[np.nan],
    'WIN.W3':[np.nan],
    'WIN.W4':[np.nan],
    'WIN.W5':[np.nan],
    'WIN.W6':[np.nan],

    'ECN.R':[np.nan],
    'ECN.DF':[np.nan],
    'ECN.T':[np.nan],
    'ECN.TG':[np.nan],
    'ECN.W':[np.nan],
    'ECN.O':[np.nan],
    'ECN.CC':[np.nan],
    'ECN.Q':[np.nan],

    'T1.R':[np.nan],
    'T1.DF':[np.nan],
    'T1.T':[np.nan],
    'T1.TG':[np.nan],
    'T1.S':[np.nan],
    'T1.A':[np.nan],
    'T1.F':[np.nan],
    'T1.RD':[np.nan],
    'T1.Q':[np.nan],

    'T2.R':[np.nan],
    'T2.DF':[np.nan],
    'T2.T':[np.nan],
    'T2.TG':[np.nan],
    'T2.W':[np.nan],
    'T2.S':[np.nan],
    'T2.A':[np.nan],
    'T2.F':[np.nan],
    'T2.O':[np.nan],
    'T2.RD':[np.nan],
    'T2.Q':[np.nan],

    'T3.R':[np.nan],
    'T3.DF':[np.nan],
    'T3.T':[np.nan],
    'T3.TG':[np.nan],
    'T3.W':[np.nan],
    'T3.S':[np.nan],
    'T3.A':[np.nan],
    'T3.F':[np.nan],
    'T3.O':[np.nan],
    'T3.RD':[np.nan],
    'T3.Q':[np.nan],

    'T4.R':[np.nan],
    'T4.DF':[np.nan],
    'T4.T':[np.nan],
    'T4.TG':[np.nan],
    'T4.W':[np.nan],
    'T4.S':[np.nan],
    'T4.A':[np.nan],
    'T4.F':[np.nan],
    'T4.O':[np.nan],
    'T4.RD':[np.nan],
    'T4.Q':[np.nan],

    'T5.R':[np.nan],
    'T5.DF':[np.nan],
    'T5.T':[np.nan],
    'T5.TG':[np.nan],
    'T5.W':[np.nan],
    'T5.S':[np.nan],
    'T5.A':[np.nan],
    'T5.F':[np.nan],
    'T5.O':[np.nan],
    'T5.RD':[np.nan],
    'T5.Q':[np.nan],

    'T6.R':[np.nan],
    'T6.DF':[np.nan],
    'T6.T':[np.nan],
    'T6.TG':[np.nan],
    'T6.W':[np.nan],
    'T6.S':[np.nan],
    'T6.A':[np.nan],
    'T6.F':[np.nan],
    'T6.O':[np.nan],
    'T6.RD':[np.nan],
    'T6.Q':[np.nan],

    'T7.R':[np.nan],
    'T7.DF':[np.nan],
    'T7.T':[np.nan],
    'T7.TG':[np.nan],
    'T7.W':[np.nan],
    'T7.S':[np.nan],
    'T7.A':[np.nan],
    'T7.F':[np.nan],
    'T7.O':[np.nan],
    'T7.RD':[np.nan],
    'T7.Q':[np.nan],

    'U1.R':[np.nan],
    'U1.DF':[np.nan],
    'U1.T':[np.nan],
    'U1.TG':[np.nan],
    'U1.IPL':[np.nan],
    'U1.UN':[np.nan],
    'U1.RIPL':[np.nan],
    'U1.RID':[np.nan],
    'U1.RIPCK':[np.nan],
    'U1.RUCK':[np.nan],
    'U1.RUD':[np.nan],

    'IE.R':[np.nan],
    'IE.DFI':[np.nan],
    'IE.T':[np.nan],
    'IE.TG':[np.nan],
    'IE.CD':[np.nan],
}

responses_format_dict = {
    # 'Class.vendor':np.nan,
    # 'Class.OSfamily':np.nan,
    # 'Class.OSgen':np.nan,
    # 'Class.device':np.nan,

    'SEQ.SP': hex_value,  # <hex_value>
    'SEQ.GCD': hex_value,  # <hex_value>
    'SEQ.ISR': hex_value,  # <hex_value>

    # 'SEQ.TI': SEQ_TI, #
    # 'SEQ.CI': SEQ_CI, # Z , RD , RI , BI , I , <hex_value>
    # 'SEQ.II': SEQ_II, #

    # 'SEQ.SS':np.nan, # S , O
    # 'SEQ.TS':np.nan, # U , 0 , 1 , 7 , 8 , <hex_value>

    # 'OPS.O1':np.nan, # 
    # 'OPS.O2':np.nan, # 
    # 'OPS.O3':np.nan, # Order of the TCP header options
    # 'OPS.O4':np.nan, # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    # 'OPS.O5':np.nan, #
    # 'OPS.O6':np.nan, #

    'WIN.W1':hex_value, #
    'WIN.W2':hex_value, #
    'WIN.W3':hex_value, # <hex_value>
    'WIN.W4':hex_value, #
    'WIN.W5':hex_value, #
    'WIN.W6':hex_value, #

    # 'ECN.R':np.nan, # Y , N
    # 'ECN.DF':np.nan, # Y , N
    'ECN.T':hex_value, # <hex_value>
    'ECN.TG':hex_value, # <hex_value>
    'ECN.W':hex_value, # <hex_value>
    # 'ECN.O':np.nan, # # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    # 'ECN.CC':np.nan, # N , S , Y , O
    # 'ECN.Q':np.nan, # [RU]{2}

    # 'T1.R':np.nan, # Y , N
    # 'T1.DF':np.nan, # Y , N
    'T1.T':hex_value, # <hex_value>
    'T1.TG':hex_value, # <hex_value>
    # 'T1.S':np.nan, # Z , A , A+ , O
    # 'T1.A':np.nan, # Z , S , S+ , O
    # 'T1.F':np.nan, # E , U , A , P , R , S , F (in this order)
    # 'T1.RD':np.nan, # 0 , <CRC32_hex_value>
    # 'T1.Q':np.nan, # [RU]{2}

    # 'T2.R':np.nan, # Y , N
    # 'T2.DF':np.nan, # Y , N
    'T2.T':hex_value, # <hex_value>
    'T2.TG':hex_value, # <hex_value>
    'T2.W':hex_value, # <hex_value>
    # 'T2.S':np.nan, # Z , A , A+ , O
    # 'T2.A':np.nan, # Z , S , S+ , O
    # 'T2.F':np.nan, # E , U , A , P , R , S , F (in this order)
    # 'T2.O':np.nan, # # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    # 'T2.RD':np.nan, # 0 , <CRC32_hex_value>
    # 'T2.Q':np.nan, # [RU]{2}

    # 'T3.R':np.nan, # Y , N
    # 'T3.DF':np.nan, # Y , N
    'T3.T':hex_value, # <hex_value>
    'T3.TG':hex_value, # <hex_value>
    'T3.W':hex_value, # <hex_value>
    # 'T3.S':np.nan, # Z , A , A+ , O
    # 'T3.A':np.nan, # Z , S , S+ , O
    # 'T3.F':np.nan, # E , U , A , P , R , S , F (in this order)
    # 'T3.O':np.nan, # # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    # 'T3.RD':np.nan, # 0 , <CRC32_hex_value>
    # 'T3.Q':np.nan, # [RU]{2}

    # 'T4.R':np.nan, # Y , N
    # 'T4.DF':np.nan, # Y , N
    'T4.T':hex_value, # <hex_value>
    'T4.TG':hex_value, # <hex_value>
    'T4.W':hex_value, # <hex_value>
    # 'T4.S':np.nan, # Z , A , A+ , O
    # 'T4.A':np.nan, # Z , S , S+ , O
    # 'T4.F':np.nan, # E , U , A , P , R , S , F (in this order)
    # 'T4.O':np.nan, # # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    # 'T4.RD':np.nan, # 0 , <CRC32_hex_value>
    # 'T4.Q':np.nan, # [RU]{2}

    # 'T5.R':np.nan, # Y , N
    # 'T5.DF':np.nan, # Y , N
    'T5.T':hex_value, # <hex_value>
    'T5.TG':hex_value, # <hex_value>
    'T5.W':hex_value, # <hex_value>
    # 'T5.S':np.nan, # Z , A , A+ , O
    # 'T5.A':np.nan, # Z , S , S+ , O
    # 'T5.F':np.nan, # E , U , A , P , R , S , F (in this order)
    # 'T5.O':np.nan, # # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    # 'T5.RD':np.nan, # 0 , <CRC32_hex_value>
    # 'T5.Q':np.nan, # [RU]{2}

    # 'T6.R':np.nan, # Y , N
    # 'T6.DF':np.nan, # Y , N
    'T6.T':hex_value, # <hex_value>
    'T6.TG':hex_value, # <hex_value>
    'T6.W':hex_value, # <hex_value>
    # 'T6.S':np.nan, # Z , A , A+ , O
    # 'T6.A':np.nan, # Z , S , S+ , O
    # 'T6.F':np.nan, # E , U , A , P , R , S , F (in this order)
    # 'T6.O':np.nan, # # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    # 'T6.RD':np.nan, # 0 , <CRC32_hex_value>
    # 'T6.Q':np.nan, # [RU]{2}

    # 'T7.R':np.nan, # Y , N
    # 'T7.DF':np.nan, # Y , N
    'T7.T':hex_value, # <hex_value>
    'T7.TG':hex_value, # <hex_value>
    'T7.W':hex_value, # <hex_value>
    # 'T7.S':np.nan, # Z , A , A+ , O
    # 'T7.A':np.nan, # Z , S , S+ , O
    # 'T7.F':np.nan, # E , U , A , P , R , S , F (in this order)
    # 'T7.O':np.nan, # # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    # 'T7.RD':np.nan, # 0 , <CRC32_hex_value>
    # 'T7.Q':np.nan, # [RU]{2}

    # 'U1.R':np.nan, # Y , N
    # 'U1.DF':np.nan, # Y , N
    'U1.T':hex_value, # <hex_value>
    'U1.TG':hex_value, # <hex_value>
    'U1.IPL':hex_value, # <hex_value>
    'U1.UN':hex_value, # <hex_value>
    # 'U1.RIPL':np.nan, # <hex_value> , G
    # 'U1.RID':np.nan, # G , <hex_value>
    # 'U1.RIPCK':np.nan, # G , Z , I
    # 'U1.RUCK':np.nan, # G , <hex_value>
    # 'U1.RUD':np.nan, # G , I

    # 'IE.R':np.nan, # Y , N
    # 'IE.DFI':np.nan, # N , S , Y , O
    'IE.T':hex_value, # <hex_value>
    'IE.TG':hex_value, # <hex_value>
    # 'IE.CD':np.nan, # Z , S , <hex_value> , O
}

# %%
def _debug_output(dataset,f_added,f_skkipped,comb_added,comb_skkipped,classes_skkipped):
    print("\nDATASET:")
    print("Size (Bytes / MB):")
    print(sys.getsizeof(dataset), end=" / ")
    print(sys.getsizeof(dataset)/1048576)
    print("Rows:")
    print(f'{len(dataset):,}')
    print("Columns:") 
    columns=len(dataset[0])
    not_equal=False
    for row in dataset:
        if len(row)!=columns:
            not_equal=True
    if not_equal:
        print("Not same columns in all rows")
    else:
        print(columns)
    print()
    print("FINGERPRINTS: {:,}".format(f_added+f_skkipped))
    print("Added:")
    print(f_added)
    print("Skkipped: {}".format(f_skkipped))
    print()
    for clas in sorted(classes_skkipped, key=lambda tup: tup[1]):
        print('{0: <45}{1:,}'.format(clas[0],clas[1]))
    print()
    print("COMBINATIONS: {:,}".format(comb_added+comb_skkipped))
    print("Rows:")
    print(f'{len(dataset):,}')
    print("Combinations added:")
    print(f'{comb_added:,}')
    print("Combinations skipped:")
    print(f'{comb_skkipped:,}')

# %%
def _parse_probe(line):
    line = line.strip()
    for key, rx in probes_sent_dict.items():
        match = rx.search(line)
        if match:
            return key, match.group(key)

    return None, None


# %%
def _parse_entry_class(entry_class):

    entry_class = entry_class.split("|")

    return [entry_class[0],entry_class[1],entry_class[2],entry_class[3]]


# %%
def _parse_value(in_value):
    
    return in_value.replace(" ",'').split('|')


# %%
def _parse_fingerprint(fingerprint,dataset,max_comb,in_classes):

    fingerprint = [line for line in fingerprint if line[0]!="#" and not line.startswith("Fingerprint") and not line.startswith("CPE")]

    entry_classes = []
    probes = []
    for line in fingerprint:
        if line.startswith("Class"):
            line = line.replace("Class",'').replace(" ",'')
            if in_classes is None or line in in_classes:
                entry_classes.append(_parse_entry_class(line))
        else:
            probes.append(line)

    local_template = fingerprint_template.copy()
    for probe in probes:
            
            probe_key, probe_responses = _parse_probe(probe)

            for test in probe_responses.split('%'):

                match = test_parser.search(test)

                if match:
                    test_key = match.group('key')
                    test_value = match.group('value')
                    id = probe_key + "." + test_key

                    test_value = _parse_value(test_value)

                    if not isinstance(test_value,list):
                        test_value=[test_value]

                    if id in responses_format_dict:
                        test_value = [responses_format_dict[id](cell) for cell in test_value]

                    local_template[id] = test_value
                else:
                    if test!="":
                        raise Exception("The test does not exist")

    aux = list(local_template.values())

    number_of_options = 1
    for value in aux:
        number_of_options*=len(value)

    if number_of_options > max_comb:
        return 0,len(entry_classes),0,number_of_options*(len(entry_classes)),[(entry[0]+" "+entry[1]+" "+entry[2]+" "+entry[3],number_of_options*(len(entry_classes))) for entry in entry_classes]

    combinations = list(itertools.product(*aux))

    for entry_class in entry_classes:
        for combination in combinations:
            combination = list(combination)
            combination[0] = entry_class[0]
            combination[1] = entry_class[1]
            combination[2] = entry_class[2]
            combination[3] = entry_class[3]
            dataset.append(combination)

    return len(entry_classes),0,number_of_options*len(entry_classes),0,[]

    

# %%
def parse_database(filepath,max_comb,classes,debug):

    with open(filepath, 'r') as database_file:
        dataset = []
        
        fingerprints = database_file.read().split('\n\n')

        count=1
        f_added=0
        f_skkipped=0
        comb_added=0
        comb_skkipped=0
        classes_skkipped=[]
        for fingerprint in fingerprints:
        
            aux1, aux2, aux3, aux4, aux5 = _parse_fingerprint(fingerprint.splitlines(),dataset,max_comb,classes)
            f_added+=aux1
            f_skkipped+=aux2
            comb_added+=aux3
            comb_skkipped+=aux4
            for value in aux5:
                classes_skkipped.append(value) 
            count+=1
            
            if debug:
                if count % 100 == 0:
                    print("Fingerprint number -> {}".format(count))

    if debug:
        print(f'{"Fingerprint parser DONE": <200} ')
        _debug_output(dataset,f_added,f_skkipped,comb_added,comb_skkipped,classes_skkipped)

    #return pd.DataFrame(dataset)
    return dataset


# %%
def parse_in_classes(filepath):
    with open(filepath, 'r') as database_file:
        classes = database_file.read().split('\n')

        in_classes=[]
        for clas in classes:
            in_classes.append(clas)

    return in_classes
# %%
# classes_in = parse_in_classes("os-classes-db79-IN.txt")
# dataset = parse_database("db7.9.txt",100000,classes_in,True)
# df = pd.DataFrame(dataset)
# print()
# print(dataset)