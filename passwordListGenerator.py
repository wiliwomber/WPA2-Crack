from pathlib import Path
from time import time
import random


RANDALPHA = ")[f!}LH'ha@$^ZXvrneMKt:0 mE~{Nl<c\\OjW;iBAT(gUd4?._/5Ju3|9%*wPC]+k=xSQzq7RD6`21I8bGs-oY>&py#,VF"

pwfile = Path('passwordlist.txt')

content = ''

day = 60 * 60 * 24
month = day * 31

start = int(time()) - (19 * month)
end = int(time()) - (14 * month)//2

for i in range(start, end):
    password = ''
    random.seed(i)
    for n in range(8):
        password += RANDALPHA[random.randint(0, len(RANDALPHA)-1)]
    content += password + '\n'
    current_progress = (i - start)/(end-start)
    print("Progress: {}%".format(round(current_progress * 100, 3)), end='\r')

pwfile.write_text(content)
