from bs4 import BeautifulSoup as bs 
import requests
url = 'https://nostarch.com'
get_request = requests.get(url)

tree = bs(get_request.text, 'html.parser') # Parse into tree
print(str(tree)+"\n\n")
for link in tree.find_all('a'):  # Once again - looking for our anchor elements
    print(f"{link.get('href')} \n\t -> {link.text}")