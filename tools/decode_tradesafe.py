# -*- coding: utf-8 -*-
ALPHABET = "oPbsG4EvU8gyd02B3q6fIVWXYZaCcMeTKhxnwzmjApRrDtuHkiLlN1O9F5S7JQ+/"
DEC = {c: i for i, c in enumerate(ALPHABET)}

def de_decode(s):
    s = s.replace(" ", "+").strip()
    vals = []
    for c in s:
        if c == "=":
            break
        v = DEC.get(c)
        if v is not None:
            vals.append(v)
    out = bytearray(); acc = 0; bits = 0
    for v in vals:
        acc = (acc << 6) | v
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)

# tradesafe 请求 blob (抓包中)
req = "cs1OaX81c1QnCOqz8jYQdnok0loOdsYmcX0pZsNld6ZzMn14dsY1ynG5yn3OynGk26ZtYWdQdl3SdsUS2sYS3fISdlcS3lKmMWzwBfdidsd10fIi06Zkcs1AZXhpCx5zeEI78jPhMEKQqbIl36I13LVsqbVP3LVb3xVP2bVs3xVbdLVs2bV4qbVb3LVEq6I13LVsqbVP3LVb3xVP2bVs3xVbdLI139hpYWqhCx5zeEImCW31Bf4EqG3lqw4E2f8PdIYF0sVs0sw90w3F2IYO0nGi2GdF8jPOBfUkdnUk0sU58jVkeEzhZE4uBXVk"
raw = de_decode(req)
print(f"tradesafe请求: {len(raw)} 字节")
print(raw.decode("gbk", "replace"))
print()
print("hex:", raw.hex(" "))
