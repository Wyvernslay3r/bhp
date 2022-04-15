import queue
import requests
import threading
import sys

AGENT = 'Ethans-Agent'
EXTENSION = ['.php','.bak','.orig','.inc']
TARGET = "http://testphp.vulnweb.com"
THREADS = 50
WORDLIST = "./chapter5/wordlist/all.txt"

def get_words(resume=None):
    with open(WORDLIST) as file:
        raw_words = file.read()
    
    found_resume = False
    
    words_queue = queue.Queue()
    for word in raw_words.split():
        if resume is not None:
            if found_resume:
                extend_words(words_queue, word)

            elif word == resume:
                found_resume = True
                print(f"Resuming from: {resume}")
        else:
            print(word)
            extend_words(words_queue, word)
    return words_queue



def extend_words(words:queue, word:str):
    #In the book this was a nested function - however when passing in the queue as a parameter,
    #it continues to work acceptably, beyond needing to be nested. 
    if "." in word:
        words.put(f'/{word}')
    else:
        words.put(f'/{word}/')
    
    for extension in EXTENSION:
        words.put(f'/{word}{extension}')

def dir_buster(words_gueue):
    headers = {'User-Agent':AGENT}
    while not words_gueue.empty():
        url = f'{TARGET}{words_gueue.get()}' #Specify Target and URL from words queue
        try:
            r = requests.get(url, headers=headers)
        except requests.exceptions.ConnectionError:
            sys.stderr.write('x'); sys.stderr.flush()
            continue

        if r.status_code == 200:
            print(f'Success: {r.status_code} => {url}')
        elif r.status_code == 404:
            sys.stderr.write('.');sys.stderr.flush()
            #Far to verbose for our usecase - would be fine for logging but stdout
            #print(f'Failure - Not found: {r.status_code} => {url}')
            
        else:
            print(f'{r.status_code} => {url}')

if __name__ == '__main__':
    words_queue = get_words()
    print("Press return to continue...")

    sys.stdin.readline()
    for _ in range(THREADS):
        t = threading.Thread(target=dir_buster, args=(words_queue,))
        t.start()



