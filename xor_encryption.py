def xor_strings(str1, str2):
    max_length = max(len(str1), len(str2))
    str1 = str1.ljust(max_length)
    str2 = str2.ljust(max_length)
    result = ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(str1, str2))
 
    return result
