# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'

import random
import sys
import numpy as np

# %%
def string_to_hex (string):
    x = int(string, 16)
    return x

# %%

def hex_value (string):
    if "-" in string:
        values = string.split("-")
        #return [string_to_hex(values[0]),string_to_hex(values[1])]
        return random.randint(string_to_hex(values[0]),string_to_hex(values[1]))
    elif ">" in string :
        return random.randint(string_to_hex(string[1:]),sys.maxsize)
    elif "<" in string:
        return random.randint(0,string_to_hex(string[1:]))
    elif string == "":
        return np.nan
    else:
        return string_to_hex(string)
