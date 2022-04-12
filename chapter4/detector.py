from ast import Continue
import cv2 
import os


ROOT = '~/Desktop/Pictures'
FACES = '~/Desktop/Faces'
TRAIN = '~/Desktop/Training'

def detect(srcdir = ROOT, targetdir=FACES, trainingdir=TRAIN):
    for fname in os.listdir(srcdir):
        if not fname.upper().endswith('.JPG'):
            continue
        
        fullname = os.path.join(srcdir,fname)
        newname = os.path.join(targetdir, fname)
        
        img = cv2.imread(fullname)
        if img is None:
            continue

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        training = os.path.join(trainingdir, 'haarcascade_frontalface_alt.xml') #XML Dataset found here - http://eclecti.cc/files/2008/03/haarcascade_frontalface_alt.xml
        cascade = cv2.CascadeClassifier(training)

        rects = cascade.detectMultiScale(gray, 1.3, 5)
        try:
            if rects.any():
                print('Face Detected...')
                rects[:,2:]+=rects[:,:2]
        except AttributeError:
            print(f"No faces found in {fname} ")
            continue

        #Highlight the Face in the Image
        for x1, y1, x2, y2 in rects:
            cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)
        cv2.imwrite(newname, img)

if __name__ =='__main__':
    detect()