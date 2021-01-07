import os

import numpy as np
from PIL import Image
import cv2
import Libraries.generate_keys as GenKey
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

# Flask utils
from flask import Flask, redirect, url_for, request, render_template
from werkzeug.utils import secure_filename
from gevent.pywsgi import WSGIServer

# Define a flask app
app = Flask(__name__)


print('Model loaded. Check http://127.0.0.1:5000/')

def EncryptImage(pub_key, img):
    """
    args:
        pub_key: Paillier PublicKey object
        img: PIL Image object

    returns:
        encrypted_img: Encryption of img
    Encrypts an image
    """

    encrypted_img = np.asarray(img)
    shape = encrypted_img.shape
    encrypted_img = encrypted_img.flatten().tolist()
    encrypted_img = [GenKey.Encryption(pub_key, pixels) for pixels in encrypted_img]

    return np.asarray(encrypted_img).reshape(shape)


def DecryptImage(pub_key, pri_key, encrypted_img):
    """
    args:
        pub_key: Paillier PublicKey object
        pri_key: Paillier PrivateKey object
        encrypted_img: encryption of Image

    returns:
        Image object which is the decryption of encrypted_image
    Decrypts ecnrypted image
    """
    shape = encrypted_img.shape
    orig_img = encrypted_img.flatten().tolist()
    orig_img = [GenKey.Decryption(pub_key, pri_key, pixels) for pixels in orig_img]
    orig_img = [pixels if pixels < 255 else 255 for pixels in orig_img]
    orig_img = [pixels if pixels > 0 else 0 for pixels in orig_img]

    return Image.fromarray(np.asarray(orig_img).reshape(shape).astype(np.uint8))


@app.route('/', methods=['GET'])
def index():
    # Main page
    return render_template('home.html')


@app.route('/predict', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # Get the file from post request
        f = request.files['file']

        # Save the file to ./uploads
        basepath = os.path.dirname(__file__)
        file_path = os.path.join(
            basepath, 'uploads', secure_filename(f.filename))
        f.save(file_path)   
        # Generating The Keys 
        keysData = GenKey.Main_fun()
        #keysData = str(keysData) + file_path
        img = Image.open(file_path)
        img = cv2.resize(np.asarray(img), (512, 512))
        
        edata = EncryptImage(pub_key=keysData[0], img=img)
        ddata = DecryptImage(pub_key=keysData[0], pri_key=keysData[1], encrypted_img=edata)
        plt.subplot(121)
        plt.imshow(edata.astype('uint8'), cmap='gray'), plt.title("encrypted image")
        plt.subplot(122)
        plt.imshow(ddata, cmap='gray'), plt.title("decrypted image")
        plt.show()
        return str(keysData)
    return None

if __name__ == '__main__':
    # app.run(port=5002, debug=True)

    # Serve the app with gevent
    http_server = WSGIServer(('', 8000), app)
    http_server.serve_forever()
    app.run()
