from io import BytesIO
from lxml import etree

import requests

url = 'https://nostarch.com'
get_request = requests.get(url)
content = get_request.content

parser = etree.HTMLParser()
content = etree.parse(BytesIO(content), parser=parser)
for link in content.findall('//a'): #Looks for all anchor elements from within the parsed html
    print(f"{link.get('href')}->{link.text}")

    
