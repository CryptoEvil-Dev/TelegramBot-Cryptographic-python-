import os
from Cryptodome import Hash
from Cryptodome.Hash import HMAC
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives import ciphers
import telebot
import pyAesCrypt


import stegano
from stegano import *
from Cryptodome.Cipher import DES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
import hashlib

import datetime
#from typing import Hashable


bot = telebot.TeleBot("I NEED YOUR TELEGRAM_TOKEN")

@bot.message_handler(commands=['help'])
def helper(message):
    bot.send_message(message.chat.id, """

    ----------------------Шифрование---------------------------------------

    /crypt_aes - зашифровать документ по AES
    /decrypt_aes - расшифровать AES документ
    /crypt_rsa - зашифровать документ по RSA
    /decrypt_rsa - расшифровать RSA документ
    /crypt_rsa_key - зашифровать документ по существующему ключу(публичному)
    /crypt_des - зашифровать документ по DES (размер ключа должен быть равен 8 байт)
    /decrypt_des - расшифровать документ по DES

    /crypt_stegano - Зашифровать сообщение в картинке (PNG) (Проблемы с кирилицой)
    /decrypt_stegano - Расшифровать сообщение из картинки (PNG) (Проблемы с кирилицой)

    ----------------------Хеширование---------------------------------------

    /hash_md5 - Захешировать сообщение в MD5
    /hash_sha256 - Захешировать сообщение в SHA256
    /hash_sha224 - Захешировать сообщение в SHA224
    /hash_sha1 - Захешировать сообщение в SHA1
    /hash_sha384 - Захешировать сообщение в SHA384
    /hash_sha512 - Захешировать сообщение в SHA512

    /hash_sha3_512 - Захешировать сообщение в SHA3_512
    /hash_sha3_224 - Захешировать сообщение в SHA3_224
    /hash_sha3_256 - Захешировать сообщение в SHA3_256
    /hash_sha3_384 - Захешировать сообщение в SHA3_384

    /hash_eq - Сравнение хеш-сумм
    """)


@bot.message_handler(commands=['manual'])
def manuals(message):
    bot.send_message(message.chat.id, """

    /manual_aes - Документация по алгоритму AES
    /manual_rsa -  Документация по алгоритму RSA
    /manual_des - Документация по алгоритму DES
    /manual_stegano - Документация по Стеганографии
    /manual_hash -  Документация по алгоритмам хеширования
    
    
    """)

@bot.message_handler(commands=['start'])
def start(message):
    bot.send_message(message.chat.id, """Привет, я могу зашифровать твой сообщение через такие виды шифрования как RSA и AES. 
    А также я могу захешировать твоё сообщение и скрыть сообщение в изображении напиши /help что бы увидеть команды. 
    /manual для получения документации""")












@bot.message_handler(commands=['crypt_aes'])
def crypt_aes_step1(message):
    bot.send_message(message.chat.id, "Хорошо, пришли мне пароль для файла")
    bot.register_next_step_handler(message, crypt_aes_step2)
def crypt_aes_step2(message):
    global password
    password = message.text
    bot.send_message(message.chat.id, "Отлично, теперь пришли мне файл, я его зашифрую")
    bot.register_next_step_handler(message, crypt_aes_step3)

def crypt_aes_step3(message):
    try:
        noWWW = datetime.datetime.now()

        chat_id = message.chat.id
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        src = 'doc/' + message.document.file_name
        with open(src, 'wb') as new_file:
            new_file.write(downloaded_file)
        pyAesCrypt.encryptFile(src, src+'.aes', password, 256*1024)
        doc = open(src+'.aes','rb')
        bot.send_document(message.chat.id, doc)
        doc.close()
        os.remove(src)
        os.remove(src+'.aes')

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)

    except Exception as e:
        bot.reply_to(message, e)

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)
        

@bot.message_handler(commands=['decrypt_aes'])

def decrypt_aes_step1(message):
    bot.send_message(message.chat.id, "Хорошо, пришли мне пароль для файла")
    bot.register_next_step_handler(message, decrypt_aes_step2)

def decrypt_aes_step2(message):
    global password
    password = message.text
    bot.send_message(message.chat.id, "Отлично, теперь пришли мне файл, для расшифровки")
    bot.register_next_step_handler(message, decrypt_aes_step3)

def decrypt_aes_step3(message):
    try:

        noWWW = datetime.datetime.now()

        chat_id = message.chat.id
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        src = 'doc/' + message.document.file_name
        with open(src, 'wb') as new_file:
            new_file.write(downloaded_file)
        src2 = src[0: -1]
        src2 = src2[0: -1]
        src2 = src2[0: -1]
        src2 = src2[0: -1]
        pyAesCrypt.decryptFile(src, src2, password, 256*1024)
        doc = open(src2,'rb')
        bot.send_document(message.chat.id, doc)
        doc.close()
        os.remove(src)
        os.remove(src2)

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)

    except Exception as e:
        bot.reply_to(message, e)

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)





@bot.message_handler(commands=['crypt_rsa'])
def crypt_rsa_step1(message):
    bot.send_message(message.chat.id, "Я зашифрую твой файл через RSA, пришли мне файл")
    bot.register_next_step_handler(message, crypt_rsa_step2)



def crypt_rsa_step2(message):
    try:

        noWWW = datetime.datetime.now()

        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        src = 'doc/' + message.document.file_name
        with open(src, 'wb') as new_file:
                new_file.write(downloaded_file)



        key = RSA.generate(2048)
        private_key = key.export_key()
        file_out = open("doc/private.pem", "wb")
        file_out.write(private_key)
        file_out.close()

        f_out = open("doc/private.pem", "rb")
        bot.send_document(message.chat.id, f_out)
        f_out.close()

        public_key = key.publickey().export_key()
        file_out = open("doc/receiver.pem", "wb")
        file_out.write(public_key)
        file_out.close()

        f_out = open("doc/receiver.pem", "rb")
        bot.send_document(message.chat.id, f_out)
        f_out.close()


        data = downloaded_file
        file_out = open(src+'.rsa', "wb")

        recipient_key = RSA.import_key(open("doc/receiver.pem").read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
        file_out.close()
        f_out = open(src+'.rsa', 'rb')
        bot.send_document(message.chat.id, f_out)
        f_out.close()
        bot.send_message(message.chat.id, """private.pem - Приватный ключ, для расшифрования
        receiver.pem - Публичный ключ, для шифрования""")

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)
        

    except Exception as e:
        bot.reply_to(message, e)


        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)




    
@bot.message_handler(commands=['decrypt_rsa'])
def decrypt_rsa_step1(message):
    bot.send_message(message.chat.id, "Пришли мне приватный ключ для расшифровки")
    bot.register_next_step_handler(message, decrypt_rsa_step2)
def decrypt_rsa_step2(message):
    try:
        global srckey

        file_info = bot.get_file(message.document.file_id)
        downloaded_key = bot.download_file(file_info.file_path)
        srckey = 'doc/' + message.document.file_name
        with open(srckey, 'wb') as new_file:
            new_file.write(downloaded_key)

        bot.send_message(message.chat.id, "Теперь зашифрованый файл")
        bot.register_next_step_handler(message, decrypt_rsa_step3)
    except Exception as e:
        bot.reply_to(message, e)
def decrypt_rsa_step3(message):
    try:

        noWWW = datetime.datetime.now()

        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        src = 'doc/' + message.document.file_name
        with open(src, 'wb') as new_file:
            new_file.write(downloaded_file)



        file_in = open(src, "rb")

        private_key = RSA.import_key(open(srckey).read())

        enc_session_key, nonce, tag, ciphertext = \
            [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        #bot.send_document(message.chat.id, data)

        src2 = src[0: -1]
        src2 = src2[0: -1]
        src2 = src2[0: -1]
        src2 = src2[0: -1]

        f_out = open(src2, 'wb')
        f_out.write(data)
        f_out.close()
        f_out = open(src2, 'rb')
        bot.send_document(message.chat.id, f_out)
        f_out.close()

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)
        
    except Exception as e:
        bot.reply_to(message, e)


        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)





@bot.message_handler(commands=['crypt_rsa_key'])
def crypt_rsa_key_step1(message):
    bot.send_message(message.chat.id, "Пришли мне публичный ключ")
    bot.register_next_step_handler(message, crypt_rsa_key_step2)

    

def crypt_rsa_key_step2(message):
    try:

        global srckey

        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        srckey = 'doc/' + message.document.file_name
        with open(srckey, 'wb') as new_file:
            new_file.write(downloaded_file)

    except Exception as e:
        bot.reply_to(message, e)



    bot.send_message(message.chat.id, "Теперь пришли мне файл")
    bot.register_next_step_handler(message, crypt_rsa_key_step3)

def crypt_rsa_key_step3(message):

    try:

        noWWW = datetime.datetime.now()

        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        src = 'doc/' + message.document.file_name
        with open(src, 'wb') as new_file:
            new_file.write(downloaded_file)


        data = downloaded_file
        file_out = open(src + '.rsa', "wb")

        recipient_key = RSA.import_key(open(srckey).read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
        file_out.close()

        f_out = open(src+'.rsa', 'rb')
        bot.send_document(message.chat.id, f_out)
        f_out.close()

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)

    except Exception as e:
        bot.reply_to(message, e)

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)





@bot.message_handler(commands=['crypt_des'])
def crypt_des_step1(message):
    bot.send_message(message.chat.id, """Шифрование DES, придумайте 8 байтный ключ 
    (1 символ латиницы - 1 байт, 1 сивол кирилицы - 2 байта)""")
    bot.register_next_step_handler(message, crypt_des_step2)
def crypt_des_step2(message):
    try:
        global password
        password = message.text
        bot.send_message(message.chat.id, "Теперь пришли мне файл")
        bot.register_next_step_handler(message, crypt_des_step3)
    except Exception as e:
        bot.reply_to(message, e)
def crypt_des_step3(message):
    try:
        noWWW = datetime.datetime.now()
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        src = 'doc/' + message.document.file_name
        with open(src, 'wb') as new_file:
            new_file.write(downloaded_file)

        key = str(password).encode()
    
        def pad(text):
            while len(text) % 8 != 0:
                text += b' '
            return text
        des = DES.new(key, DES.MODE_ECB)
        text = downloaded_file
        padded_text = pad(text)
        encrypted_text = des.encrypt(padded_text)
        f_out = open(src+'.des', 'wb')
        f_out.write(encrypted_text)
        f_out.close()
        f_out = open(src+'.des', 'rb')
        bot.send_document(message.chat.id, f_out)
        f_out.close()
        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)
    except Exception as e:
        bot.reply_to(message, e)

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)


@bot.message_handler(commands=['decrypt_des'])
def decrypt_des_step1(message):
    bot.send_message(message.chat.id, "Пришли мне 8 байтный ключ от файла")
    bot.register_next_step_handler(message, decrypt_des_step2)
def decrypt_des_step2(message):
    global password
    password = message.text
    bot.send_message(message.chat.id, "Теперь пришли мне файл")
    bot.register_next_step_handler(message, decrypt_des_step3)
def decrypt_des_step3(message):

    try:

        noWWW = datetime.datetime.now()

        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        src = 'doc/' + message.document.file_name
        with open(src, 'wb') as new_file:
            new_file.write(downloaded_file)

        key = str(password).encode()
        des = DES.new(key, DES.MODE_ECB)
        data = des.decrypt(downloaded_file)

        src2 = src[0: -1]
        src2 = src2[0: -1]
        src2 = src2[0: -1]
        src2 = src2[0: -1]

        f_out = open(src2, 'wb')
        f_out.write(data)
        f_out.close()
        f_out = open(src2, 'rb')
        bot.send_document(message.chat.id, f_out)
        f_out.close()

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)

    except Exception as e:
        bot.reply_to(message, e)

        theNNN = datetime.datetime.now()
        delta = noWWW - theNNN
        print(delta.microseconds)








@bot.message_handler(commands=['crypt_stegano'])
def crypt_stegano_step1(message):
    bot.send_message(message.chat.id, "Пришли мне картинку (png) в которую хочешь зашифровать своё сообщение")
    bot.register_next_step_handler(message, crypt_stegano_step2)
def crypt_stegano_step2(message):

    try:
        global srcimg
        global f_inf

        f_inf = message.document.file_name

        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        srcimg = 'doc/' + message.document.file_name
        with open(srcimg, 'wb') as new_file:
            new_file.write(downloaded_file)



        bot.send_message(message.chat.id, "Теперь пришли мне текст")
        bot.register_next_step_handler(message, crypt_stegano_step3)
    except Exception as e:
        bot.reply_to(message, e)
def crypt_stegano_step3(message):

    try:
        src2 = 'doc/stegano_' + f_inf
        secret = stegano.lsb.hide(srcimg, message.text)
        secret.save(src2)


        f_out = open(src2, 'rb')
        bot.send_document(message.chat.id, f_out)
        f_out.close()
    except Exception as e:
        bot.reply_to(message, e)
    
@bot.message_handler(commands=['decrypt_stegano'])
def decrypt_stegano_step1(message):
    bot.send_message(message.chat.id, "Пришли мне зашифрованное изображение")
    bot.register_next_step_handler(message, decrypt_stegano_step2)
def decrypt_stegano_step2(message):

    try:
        global srcc

        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        srcc = 'doc/' + message.document.file_name
        with open(srcc, 'wb') as new_file:
            new_file.write(downloaded_file)

        bot.send_message(message.chat.id, "Теперь пришли незашифрованное изображение")
        bot.register_next_step_handler(message, decrypt_stegano_step3)
    except Exception as e:
        bot.reply_to(message, e)
def decrypt_stegano_step3(message):
    
    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        src = 'doc/' + message.document.file_name
        with open(src, 'wb') as new_file:
            new_file.write(downloaded_file)

        secret = lsb.hide(src, srcc)
        result = lsb.reveal(srcc)

        bot.send_message(message.chat.id, result)
    except Exception as e:
        bot.reply_to(message, e)









    
@bot.message_handler(commands=['hash_md5'])
def hash_md5_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_md5_step2)
def hash_md5_step2(message):
    res = hashlib.md5(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())

@bot.message_handler(commands=['hash_sha256'])
def hash_sha256_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_sha256_step2)
def hash_sha256_step2(message):
    res = hashlib.sha256(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())

@bot.message_handler(commands=['hash_sha224'])
def hash_sha224_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_sha224_step2)
def hash_sha224_step2(message):
    res = hashlib.sha224(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())

@bot.message_handler(commands=['hash_sha1'])
def hash_sha1_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_sha1_step2)
def hash_sha1_step2(message):
    res = hashlib.sha1(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())

@bot.message_handler(commands=['hash_sha384'])
def hash_sha384_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_sha384_step2)
def hash_sha384_step2(message):
    res = hashlib.sha384(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())

@bot.message_handler(commands=['hash_sha512'])
def hash_sha512_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_sha512_step2)
def hash_sha512_step2(message):
    res = hashlib.sha512(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())


@bot.message_handler(commands=['hash_sha3_512'])
def hash_sha3_512_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_sha3_512_step2)
def hash_sha3_512_step2(message):
    res = hashlib.sha3_512(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())

@bot.message_handler(commands=['hash_sha3_224'])
def hash_sha3_224_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_sha3_224_step2)
def hash_sha3_224_step2(message):
    res = hashlib.sha3_224(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())

@bot.message_handler(commands=['hash_sha3_256'])
def hash_sha3_256_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_sha3_256_step2)
def hash_sha3_256_step2(message):
    res = hashlib.sha3_256(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())

@bot.message_handler(commands=['hash_sha3_384'])
def hash_sha3_384_step1(message):
    bot.send_message(message.chat.id, "Пришли мне текст который надо захешировать")
    bot.register_next_step_handler(message, hash_sha3_384_step2)
def hash_sha3_384_step2(message):
    res = hashlib.sha3_384(str(message.text).encode())
    result = res.digest()
    bot.send_message(message.chat.id, result.hex())


    


@bot.message_handler(commands=['hash_eq'])
def hash_eq(message):
    bot.send_message(message.chat.id, "Сравнение хеш-сумм, пришлите мне первую хеш сумму")
    bot.register_next_step_handler(message, hash_eq2)
def hash_eq2(message):
    global hash1
    hash1 = message.text
    bot.send_message(message.chat.id, "Теперь пришлите мне вторую хеш-сумму")
    bot.register_next_step_handler(message, hash_eq3)
def hash_eq3(message):
    try:
        hash2 = message.text
        if(hash1 == hash2):
            bot.send_message(message.chat.id, "Одинаковые хеш-суммы")
        else:
            bot.send_message(message.chat.id, "Разные хеш-суммы")
    except Exception as ex:
        bot.send_message(message.chat.id, ex)







################################ Мануальная Зона ###################################################################


@bot.message_handler(commands=['manual_aes'])
def manual_aes(message):
    bot.send_message(message.chat.id, """ 
    Описание:
    AES- Advanced Encryption Standard; также Rijndael (Рейндал) - симметричный алгоритм блочного шифрования (размер блока 128 бит, ключ 128/192/256 бит), 
    принятый в качестве стандарта шифрования правительством США по результатам конкурса AES. 
    Этот алгоритм хорошо проанализирован и сейчас широко используется, как это было с его предшественником DES. 
    Национальный институт стандартов и технологий США (National Institute of Standards and Technology, NIST) опубликовал спецификацию AES 26 ноября 2001 года после пятилетнего периода, в ходе которого были созданы и оценены 15 кандидатур. 
    26 мая 2002 года AES был объявлен стандартом шифрования. 
    По состоянию на 2009 год AES является одним из самых распространённых алгоритмов симметричного шифрования. 
    Поддержка ускорения AES была введена фирмой Intel в семейство процессоров x86 начиная с Arrandale в 2010 году, а затем на процессорах Sandy Bridge; фирмой AMD — в Bulldozer с 2011 года.

    """)
    bot.send_message(message.chat.id, """
    
    Принцип работы AES шифрования:

    Шифрование

    В начале шифровывания input копируется в массив State по правилу 
    """)
    img = open('Manual/AES/1.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    После этого к State применяется процедура AddRoundKey(), и затем State проходит через процедуру трансформации (раунд) 10, 12, или 14 раз (в зависимости от длинны ключа), 
    при этом надо учесть, что последний раунд несколько отличается от предыдущих. 
    В итоге, после завершения последнего раунда трансформации, State копируется в output по правилу 
    
    """)
    img = open('Manual/AES/2.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Отдельные трансформации SubBytes(), ShiftRows(), MixColumns() и AddRoundKey() - обрабатывают State. 
    Массив w[] - содержит key schedule.

    """)

    bot.send_message(message.chat.id, """

    SubBytes()

    Процедура SubBytes() обрабатывает каждый байт состояния, независимо производя нелинейную замену байтов, используя таблицу замен (S-box). 
    Такая операция обеспечивает нелинейность алгоритма шифрования. Построение S-box состоит из двух шагов. 
    Во-первых, производится взятие обратного числа в поле Галуа GF(2 ^8). Во вторых, к каждому байту b, из которых состоит S-box, применяется следующая операция

    """)

    img = open('Manual/AES/3.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    img = open('Manual/AES/il_4.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """ 

    ShiftRows()

    ShiftRows работает со строками State. 
    При этой трансформации строки состояния циклически сдвигаются на r байт по горизонтали в зависимости от номера строки. 
    Для нулевой строки r = 0, для первой строки r = 1 Б и т. д. 
    Таким образом, каждая колонка выходного состояния после применения процедуры ShiftRows состоит из байтов из каждой колонки начального состояния. 
    Для алгоритма Rijndael паттерн смещения строк для 128- и 192-битных строк одинаков. 
    Однако для блока размером 256 бит отличается от предыдущих тем, что 2-е, 3-и и 4-е строки смещаются на 1, 3 и 4 байта соответственно. 
    Это замечание не относится к AES, так как он использует алгоритм Rijndael только с 128-битными блоками, независимо от размера ключа.
    """)
    img = open('Manual/AES/il_1.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    MixColumns()

    В процедуре MixColumns четыре байта каждой колонки State смешиваются, используя для этого обратимую линейную трансформацию. 
    MixColumns обрабатывает состояния по колонкам, трактуя каждую из них как полином третьей степени. 
    Над этими полиномами производится умножение в 
    GF(2^8) по модулю x^4 + 1 на фиксированый многочлен 
    c(x) = 3x^3 + x^2 + x + 2
    Вместе с ShiftRows MixColumns вносит диффузию в шифр
    """)
    
    img = open('Manual/AES/il_2.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """

    AddRoundKey()

    В процедуре AddRoundKey RoundKey каждого раунда объединяется со State. 
    Для каждого раунда Roundkey получается из CipherKey c помощью процедуры KeyExpansion; каждый RoundKey такого же размера, что и State. 
    Процедура производит побитовый XOR каждого байта State с каждым байтом RoundKey.
    
    """)

    img = open('Manual/AES/il_3.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, "Алгоритм генерации раундовых ключей")
    bot.send_message(message.chat.id, """
    
    Алгоритм AES, используя процедуру KeyExpansion() и подавая в неё Cipher Key, K, получает ключи для всех раундов. 
    Всего получается Nb*(Nr + 1) слов: изначально для алгоритма требуется набор из Nb слов, и каждому из Nr раундов требуется Nb ключевых набора данных. 
    Полученный массив ключей для раундов обозначается как

    """)

    img = open('Manual/AES/4.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Функция SubWord() берёт четырёхбайтовое входное слово и применяет S-box к каждому из четырёх байтов. 
    То, что получилось, подаётся на выход. На вход RotWord() подаётся слово
    [a0, a1, a2, a3] которое она циклически переставляет и возвращает
    [a1, a2, a3, a0]
    Массив слов, постоянный для данного раунда,
    Rcon[i], содержит значения
    
    """)
    img = open('Manual/AES/5.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Из рисунка можно видеть, что первые Nk слов расширенного ключа заполнены Cipher Key. В каждое последующее слово, w[i],
    кладёт значение, полученное при операции XOR w[i - 1] и w[i - Nk],
    те XOR’а предыдущего и на Nk позиций раньше слов. 
    Для слов, позиция которых кратна Nk, перед XOR’ом к w[i-1] применяется трансформация, за которой следует XOR с константой раунда Rcon[i]. 
    Указанная выше трансформация состоит из циклического сдвига байтов в слове (RotWord()),
     за которой следует процедура SubWord() — то же самое, что и SubBytes(), 
     только входные и выходные данные будут размером в слово.


     Важно заметить, что процедура KeyExpansion() для 256-битного Cipher Key немного отличается от тех, которые применяются для 128- и 192- битных шифроключей. Если Nk=8 и i-4 кратно Nk, то SubWord() применяется к w[i-1] до XOR’а.
    """)
    bot.send_message(message.chat.id, """
    
    Алгоритм выбора раундового ключа

    На каждой итерации i раундовый ключ для операции AddRoundKey выбирается из массива
    """)
    img = open('Manual/AES/6.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()














@bot.message_handler(commands=['manual_rsa'])
def manual_rsa(message):
    bot.send_message(message.chat.id, """
    
    Описание:

    RSA (аббревиатура от фамилий Rivest, Shamir и Adleman) — криптографический алгоритм с открытым ключом, 
    основывающийся на вычислительной сложности задачи факторизации больших целых чисел.

    Криптосистема RSA стала первой системой, пригодной и для шифрования, и для цифровой подписи. 
    Алгоритм используется в большом числе криптографических приложений, включая PGP, S/MIME, TLS/SSL, IPSEC/IKE и других.
    
    Криптографические системы с открытым ключом используют так называемые односторонние функции, 
    которые обладают следующим свойством:

    Если известно x, то f(x) вычислить относительно просто
    Если известно y = f(x), то для вычисления x нет простого (эффективного) пути



    Под односторонностью понимается не теоретическая однонаправленность, а практическая невозможность вычислить обратное значение, используя современные вычислительные средства, за обозримый интервал времени.

    В основу криптографической системы с открытым ключом RSA положена сложность задачи факторизации произведения двух больших простых чисел. Для шифрования используется операция возведения в степень по модулю большого числа. Для дешифрования (обратной операции) за разумное время необходимо уметь вычислять функцию Эйлера от данного большого числа, для чего необходимо знать разложение числа на простые множители.

    В криптографической системе с открытым ключом каждый участник располагает как открытым ключом (англ. public key), 
    так и закрытым ключом (англ. private key). 
    В криптографической системе RSA каждый ключ состоит из пары целых чисел. 
    Каждый участник создаёт свой открытый и закрытый ключ самостоятельно. 
    Закрытый ключ каждый из них держит в секрете, а открытые ключи можно сообщать кому угодно или даже публиковать их. 
    Открытый и закрытый ключи каждого участника обмена сообщениями в криптосистеме RSA образуют «согласованную пару» 
    в том смысле, что они являются взаимно обратными, то есть:
    
    """)
    img = open('Manual/RSA/1.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Алгоритм создания открытого и секретного ключей

    RSA-ключи генерируются следующим образом:

    1) выбираются два различных случайных простых числа p и q заданного размера (например, 1024 бита каждое);
    2) вычисляется их произведение n = p * q, которое называется модулем;
    3) вычисляется значение функции Эйлера от числа n:
    
    """)
    img = open('Manual/RSA/2.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, "4) выбирается целое число ")
    img = open('Manual/RSA/3.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()
    bot.send_message(message.chat.id, " взаимно простое со значением функции")
    img = open('Manual/RSA/4.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()
    bot.send_message(message.chat.id, """
    
    число e называется открытой экспонентой (англ. public exponent);
    обычно в качестве e берут простые числа, содержащие небольшое количество единичных бит в двоичной записи, 
    например, простые из чисел Ферма: 17, 257 или 65537, так как в этом случае время, необходимое для шифрования с использованием быстрого возведения в степень, будет меньше;
    слишком малые значения e, например 3, потенциально могут ослабить безопасность схемы RSA.
    
    5) вычисляется число d, мультипликативно обратное к числу e по модулю 
    """)
    img = open('Manual/RSA/4.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, "то есть число, удовлетворяющее сравнению:")
    img = open('Manual/RSA/5.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    (число d называется секретной экспонентой; обычно оно вычисляется при помощи расширенного алгоритма Евклида);

    6) пара (e,n)  публикуется в качестве открытого ключа RSA (англ. RSA public key);
    7) пара (d,n) играет роль закрытого ключа RSA (англ. RSA private key) и держится в секрете.
    
    """)

    bot.send_message(message.chat.id, """
    
    Шифрование и расшифрование

    Предположим, Боб хочет послать Алисе сообщение m.
    Сообщениями являются целые числа в интервале от 0 до n - 1, то есть m Є Zn
    
    """)

    img = open('Manual/RSA/6.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Наиболее используемым в настоящее время является смешанный алгоритм шифрования, 
    в котором сначала шифруется сеансовый ключ, а потом уже с его помощью участники шифруют свои сообщения симметричными системами. 
    После завершения сеанса, сеансовый ключ, как правило, уничтожается.

    Алгоритм шифрования сеансового ключа выглядит следующим образом:
    
    """)

    img = open('Manual/RSA/7.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, "В случае, когда сеансовый ключ больше, чем модуль n, сеансовый ключ разбивают на блоки нужной длины (в случае необходимости дополняют нулями) и шифруют каждый блок.")

    bot.send_message(message.chat.id, """
    
    Цифровая подпись

    Система RSA может использоваться не только для шифрования, но и для цифровой подписи.

    Предположим, что Алисе (стороне A) нужно отправить Бобу (стороне B) сообщение m, подтверждённое электронной цифровой подписью.
    
    """)

    img = open('Manual/RSA/8.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Поскольку цифровая подпись обеспечивает как аутентификацию автора сообщения, так и подтверждение целостности содержимого подписанного сообщения, 
    она служит аналогом подписи, сделанной от руки в конце рукописного документа.

    Важное свойство цифровой подписи заключается в том, что её может проверить каждый, 
    кто имеет доступ к открытому ключу её автора. 
    Один из участников обмена сообщениями после проверки подлинности цифровой подписи может передать подписанное сообщение ещё кому-то, 
    кто тоже в состоянии проверить эту подпись. 
    Например, сторона A может переслать стороне B электронный чек. 
    После того как сторона B проверит подпись стороны A на чеке, она может передать его в свой банк, 
    служащие которого также имеют возможность проверить подпись и осуществить соответствующую денежную операцию.

    Заметим, что подписанное сообщение m не зашифровано. 
    Оно пересылается в исходном виде и его содержимое не защищено от нарушения конфиденциальности. 
    Путём совместного применения представленных выше схем шифрования и цифровой подписи в системе RSA можно создавать сообщения, 
    которые будут и зашифрованы, и содержать цифровую подпись. 
    Для этого автор сначала должен добавить к сообщению свою цифровую подпись, 
    а затем — зашифровать получившуюся в результате пару (состоящую из самого сообщения и подписи к нему) с помощью открытого ключа, принадлежащего получателю. 
    Получатель расшифровывает полученное сообщение с помощью своего секретного ключа. Если проводить аналогию с пересылкой обычных бумажных документов, 
    то этот процесс похож на то, как если бы автор документа поставил под ним свою печать, 
    а затем положил его в бумажный конверт и запечатал, с тем чтобы конверт был распечатан только тем человеком, кому адресовано сообщение.
    
    """)















@bot.message_handler(commands=['manual_des'])
def manual_des(message):
    bot.send_message(message.chat.id, """
    
    Описание:

    DES (англ. Data Encryption Standard) — алгоритм для симметричного шифрования, 
    разработанный фирмой IBM и утверждённый правительством США в 1977 году как официальный стандарт (FIPS 46-3). 
    Размер блока для DES равен 64 битам. В основе алгоритма лежит сеть Фейстеля с 16 циклами (раундами) и ключом, имеющим длину 56 бит. 
    Алгоритм использует комбинацию нелинейных (S-блоки) и линейных (перестановки E, IP, IP-1) преобразований. 
    Для DES рекомендовано несколько режимов:

    ECB (англ. electronic code book) — режим «электронной кодовой книги» (простая замена);
    CBC (англ. cipher block chaining) — режим сцепления блоков;
    CFB (англ. cipher feed back) — режим обратной связи по шифротексту;
    OFB (англ. output feed back) — режим обратной связи по выходу;
    Counter Mode (CTR) — режим счётчика.

    Прямым развитием DES в настоящее время является алгоритм Triple DES (3DES). 
    В 3DES шифрование/расшифровка выполняются путём троекратного выполнения алгоритма DES.
    """)

    bot.send_message(message.chat.id, """
    
    Блочный шифр:

    Входными данными для блочного шифра служат:

    блок размером n бит;
    ключ размером k бит.
    На выходе (после применения шифрующих преобразований) получается зашифрованный блок размером n бит, 
    причём незначительные различия входных данных, как правило, приводят к существенному изменению результата.

    Блочные шифры реализуются путём многократного применения к блокам исходного текста некоторых базовых преобразований.

    Базовые преобразования:

    сложное преобразование на одной локальной части блока;
    простое преобразование между частями блока.
    Так как преобразования производятся поблочно, требуется разделение исходных данных на блоки необходимого размера. 
    При этом формат исходных данных не имеет значения (будь то текстовые документы, изображения или другие файлы). 
    Данные должны интерпретироваться в двоичном виде (как последовательность нулей и единиц) и только после этого должны разбиваться на блоки. 
    Все вышеперечисленное может осуществляться как программными, так и аппаратными средствами.
    
    
    """)
    img = open('Manual/DES/1.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    img = open('Manual/DES/1.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Преобразования сетью Фейстеля

    Это преобразование над векторами (блоками), представляющими собой левую и правую половины регистра сдвига. 
    В алгоритме DES используются прямое преобразование сетью Фейстеля в шифровании (см. Рис.1)
     и обратное преобразование сетью Фейстеля в расшифровании (см. Рис.2).
    """)

    img = open('Manual/DES/3.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    Схема шифрования алгоритма DES


    Схема шифрования алгоритма DES указана на Рис.3.
    Исходный текст — блок 64 бит.
    Процесс шифрования состоит из начальной перестановки, 16 циклов шифрования и конечной перестановки.


    Начальная перестановка


    Исходный текст T (блок 64 бит) преобразуется c помощью начальной перестановки IP которая определяется таблицей 1:
    """)
    img = open('Manual/DES/tab_1.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    По таблице первые 3 бита результирующего блока IP(T) после начальной перестановки IP 
    являются битами 58, 50, 42 входного блока T, а его 3 последние бита являются битами 23, 15, 7 входного блока.
    
    """)

    bot.send_message(message.chat.id, """
    
    Циклы шифрования

    Полученный после начальной перестановки 64-битовый блок IP(T) участвует в 16 циклах преобразования Фейстеля.

    — 16 циклов преобразования Фейстеля:

    Разбить IP(T) на две части L_0, R_0, где L_0, R_0 - соответственно 32 старших битов и 32 младших битов блока T_0 IP(T)= L_0 R_0

    Пусть T_i-1 = L_i-1 R_i-1  результат (i-1) итерации, тогда результат i-ой итерации
    T_i = L_i R_i определяется:
    """)

    img = open('Manual/DES/4.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Левая половина Li равна правой половине предыдущего вектора L_i-1 R_i-1. А правая половина R_i — это битовое сложение
    """)
    img = open('Manual/DES/5.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    По модулю 2
    В 16-циклах преобразования Фейстеля функция f играет роль шифрования. Рассмотрим подробно функцию f.
    """)

    bot.send_message(message.chat.id, """
    
    Генерирование ключей k_i

    Ключи k_i получаются из начального ключа k (56 бит = 7 байтов или 7 символов в ASCII) следующим образом. 
    Добавляются биты в позиции 8, 16, 24, 32, 40, 48, 56, 64 ключа k таким образом, чтобы каждый байт содержал нечетное число единиц. 
    Это используется для обнаружения ошибок при обмене и хранении ключей. 
    Затем делают перестановку для расширенного ключа (кроме добавляемых битов 8, 16, 24, 32, 40, 48, 56, 64). 
    Такая перестановка определена в таблице ниже.
    """)
    img = open('Manual/DES/tab_2.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Эта перестановка определяется двумя блоками C_0 и D_0 по 28 бит каждый. Первые 3 бита C_0 есть биты 57, 49, 41 расширенного ключа. 
    А первые три бита D_0 есть биты 63, 55, 47 расширенного ключа. 
    C_i, D_i i=1,2,3…получаются из C_i-1, D_i-1 одним или двумя левыми циклическими сдвигами согласно таблице ниже.
    """)

    img = open('Manual/DES/tab_3.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Ключ k_i, i=1,…16 состоит из 48 бит, выбранных из битов вектора C_i D_i (56 бит) согласно таблице ниже. 
    Первый и второй биты k_i есть биты 14, 17 вектора C_i D_i
    
    """)
    img = open('Manual/DES/tab_4.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    Схема расшифрования

    При расшифровании данных все действия выполняются в обратном порядке. 
    В 16 циклах расшифрования, в отличие от шифрования c помощью прямого преобразования сетью Фейстеля, 
    здесь используется обратное преобразование сетью Фейстеля.
    """)

    img = open('Manual/DES/6.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Схема расшифрования указана на рисунке ниже.
    Ключ k_i, i=16,…,1, функция f, перестановка IP и IP^-1 такие же, как и в процессе шифрования. 
    Алгоритм генерации ключей зависит только от ключа пользователя, поэтому при расшифровании они идентичны.
    """)

    img = open('Manual/DES/7.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()













@bot.message_handler(commands=['manual_stegano'])
def manual_stegano(message):
    bot.send_message(message.chat.id, """
    
    Стеганогра́фия (от греч. στεγανός «скрытый» + γράφω «пишу»; букв. «тайнопись») — способ передачи или хранения информации с учётом сохранения в тайне самого факта такой передачи (хранения). 
    Этот термин ввёл в 1499 году аббат бенедиктинского монастыря Св. Мартина в Шпонгейме Иоганн Тритемий в своём трактате «Стеганография» (лат. Steganographia), 
    зашифрованном под магическую книгу.
    В отличие от криптографии, которая скрывает содержимое тайного сообщения, 
    стеганография скрывает сам факт его существования. 
    Как правило, сообщение будет выглядеть как что-либо иное, 
    например, как изображение, статья, список покупок, письмо или судоку. 
    Стеганографию обычно используют совместно с методами криптографии, таким образом, дополняя её.
    Преимущество стеганографии над чистой криптографией состоит в том, что сообщения не привлекают к себе внимания. 
    Сообщения, факт шифрования которых не скрыт, вызывают подозрение и могут быть сами по себе уличающими в тех странах, в которых запрещена криптография. 
    Таким образом, криптография защищает содержание сообщения, а стеганография защищает сам факт наличия каких-либо скрытых посланий.
    
    В настоящее время под стеганографией чаще всего понимают скрытие информации в текстовых, графических либо аудиофайлах путём использования специального программного обеспечения.
    """)

    bot.send_message(message.chat.id, """
    
    Метод LSB

    LSB (Least Significant Bit, наименьший значащий бит (НЗБ)) — суть этого метода заключается в замене последних значащих битов в контейнере (изображения, аудио или видеозаписи) на биты скрываемого сообщения. 
    Разница между пустым и заполненным контейнерами должна быть не ощутима для органов восприятия человека.

    Суть метода заключается в следующем: Допустим, имеется 8-битное изображение в градациях серого. 
    00h (00000000b) обозначает чёрный цвет, FFh (11111111b) — белый. 
    Всего имеется 256 градаций (2^8). 
    Также предположим, что сообщение состоит из 1 байта — например, 01101011b. 
    При использовании 2 младших бит в описаниях пикселей, нам потребуется 4 пикселя. 
    Допустим, они чёрного цвета. Тогда пиксели, содержащие скрытое сообщение, будут выглядеть следующим образом: 00000001 00000010 00000010 00000011. 
    Тогда цвет пикселей изменится: первого — на 1/255, второго и третьего — на 2/255 и четвёртого — на 3/255. 
    Такие градации, мало того, что незаметны для человека, могут вообще не отобразиться при использовании низкокачественных устройств вывода.

    Методы LSB являются неустойчивыми ко всем видам атак и могут быть использованы только при отсутствии шума в канале передачи данных.

    Обнаружение LSB-кодированного стего осуществляется по аномальным характеристикам распределения значений диапазона младших битов отсчётов цифрового сигнала.

    Все методы LSB являются, как правило, аддитивными (А17 (Cox), L18D (Lange)).

    Другие методы скрытия информации в графических файлах ориентированы на форматы файлов с потерей, к примеру, JPEG. 
    В отличие от LSB, они более устойчивы к геометрическим преобразованиям. 
    Это получается за счёт варьирования в широком диапазоне качества изображения, что приводит к невозможности определения источника изображения.
    
    """)



@bot.message_handler(commands=['manual_hash'])
def manual_hash(message):
    bot.send_message(message.chat.id, """
    
    Хеш-функция (англ. hash function от hash — «превращать в фарш», «мешанина»), или функция свёртки — функция, осуществляющая преобразование массива входных данных 
    произвольной длины в выходную битовую строку установленной длины, выполняемое определённым алгоритмом. 
    Преобразование, производимое хеш-функцией, называется хешированием. 
    Исходные данные называются входным массивом, «ключом» или «сообщением». 
    Результат преобразования называется «хешем», «хеш-кодом», «хеш-суммой», «сводкой сообщения».

    Хеш-функции применяются в следующих случаях:

    1) при построении ассоциативных массивов;

    2) при поиске дубликатов в сериях наборов данных;

    3)при построении уникальных идентификаторов для наборов данных;

    4)при вычислении контрольных сумм от данных (сигнала) для последующего обнаружения в них ошибок (возникших случайно или внесённых намеренно), возникающих при хранении и/или передаче данных;

    5) при сохранении паролей в системах защиты в виде хеш-кода (для восстановления пароля по хеш-коду требуется функция, являющаяся обратной по отношению к использованной хеш-функции);

    6) при выработке электронной подписи (на практике часто подписывается не само сообщение, а его «хеш-образ»);

    и др.

    В общем случае (согласно принципу Дирихле) нет однозначного соответствия между хеш-кодом и исходными данными. 
    Возвращаемые хеш-функцией значения менее разнообразны, чем значения входного массива. 
    Случай, при котором хеш-функция преобразует более чем один массив входных данных в одинаковые сводки, называется «коллизией». 
    Вероятность возникновения коллизий используется для оценки качества хеш-функций.

    Существует множество алгоритмов хеширования, отличающихся различными свойствами. Примеры свойств:

    1) Разрядность
    2) Вычислительная сложность
    3) Криптостойкость

    Выбор той или иной хеш-функции определяется спецификой решаемой задачи. 
    Простейшим примером хеш-функции может служить «обрамление» данных циклическим избыточным кодом (англ. CRC, cyclic redundancy code).
    
    «Хорошая» хеш-функция должна удовлетворять двум свойствам:

    1) быстрое вычисление;
    2) минимальное количество «коллизий».

    Введём обозначения:

    K - Количество ключей
    h(k) - хеш-функция , имеющая неболее 5 различных значений (выходных данных)

    то есть:
    """)

    img = open('Manual/hash/1.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    В качестве примера «плохой» хеш-функции можно привести функцию с M=1000, 
    которая десятизначному натуральному числу K сопоставляет три цифры, 
    выбранные из середины двадцатизначного квадрата числа K. 
    Казалось бы, значения «хеш-кодов» должны равномерно распределяться между «000» и «999», 
    но для «реальных» данных это справедливо лишь в том случае, 
    если «ключи» не имеют «большого» количества нулей слева или справа.

    Рассмотрим несколько простых и надёжных реализаций «хеш-функций».
    
    """)

    bot.send_message(message.chat.id, """
    
    Хеш-функции, основанные на делении

    1. «Хеш-код» как остаток от деления на число всех возможных «хешей»
    Хеш-функция может вычислять «хеш» как остаток от деления входных данных на M:

    h(k)=k mod M

    Где M - количество всех возможных «хешей» (выходных данных).
    При этом очевидно, что при чётном M значение функции будет чётным при чётном k и нечётным — при нечётном k. 
    Также не следует использовать в качестве M степень основания системы счисления компьютера, 
    так как «хеш-код» будет зависеть только от нескольких цифр числа k, 
    расположенных справа, что приведёт к большому количеству коллизий. 
    На практике обычно выбирают простое M; 
    в большинстве случаев этот выбор вполне удовлетворителен.
    """)

    bot.send_message(message.chat.id, """
    
    2) 'Хеш-код' как набор коэффициентов получаемого полинома

    Хеш-функция может выполнять деление входных данных на полином по модулю два. 
    В данном методе M должна являться степенью двойки, а бинарные ключи (K = k_n-1 k_n-2 ... k_0) 
    представляются в виде полиномов, в качестве 'хеш-кода' 'берутся' 
    значения коэффициентов полинома, полученного как остаток от деления входных данных K на заранее выбранный полином P степени m:
    """)

    img = open('Manual/hash/2.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, "При правильном выборе P(x) гарантируется отсутствие коллизий между почти одинаковыми ключами")

    bot.send_message(message.chat.id, """
    
    «Хеш-функции», основанные на умножении

    Обозначим символом w количество чисел, представимых машинным словом. Например, для 32-разрядных компьютеров, совместимых с IBM PC, w = 2^32.

    Выберем некую константу A так, чтобы A была взаимно простой с w. Тогда хеш-функция, использующая умножение, может иметь следующий вид:
    """)

    img = open('Manual/hash/3.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    В этом случае на компьютере с двоичной системой счисления M является степенью двойки, 
    и h(K) будет состоять из старших битов правой половины произведения A*K.

    Одним из преимуществ хеш-функций, основанных на делении и умножении, 
    является выгодное использование неслучайности реальных ключей. 
    Например, если ключи представляют собой арифметическую прогрессию (например, последовательность имён «Имя 1», «Имя 2», «Имя 3»), 
    хеш-функция, использующая умножение, отобразит арифметическую прогрессию в приближенно арифметическую прогрессию различных хеш-значений, 
    что уменьшит количество коллизий по сравнению со случайной ситуацией.

    Одной из хеш-функций, использующих умножение, является хеш-функция, использующая хеширование Фибоначчи. 
    Хеширование Фибоначчи основано на свойствах золотого сечения. 
    В качестве константы A здесь выбирается целое число, ближайшее к ф^-1 * w и взаимно простое с w, 
    где ф  — это золотое сечение
    """)

    bot.send_message(message.chat.id, """
    
    Хеширование строк переменной длины

    Вышеизложенные методы применимы и в том случае, если необходимо рассматривать ключи, 
    состоящие из нескольких слов, или ключи переменной длины.

    Например, можно скомбинировать слова в одно при помощи сложения по модулю w или операции «исключающее или». 
    Одним из алгоритмов, работающих по такому принципу, является хеш-функция Пирсона.

    Хеширование Пирсона — алгоритм, предложенный Питером Пирсоном (англ. Peter Pearson) 
    для процессоров с 8-битовыми регистрами, задачей которого является быстрое преобразование строки произвольной длины в хеш-код. 
    На вход функция получает слово W, состоящее из n символов, каждый размером 1 байт, и возвращает значение в диапазоне от 0 до 255. 
    При этом значение хеш-кода зависит от каждого символа входного слова.

    Алгоритм можно описать следующим псевдокодом, который получает на вход строку W и использует таблицу перестановок T:
    
    """)

    bot.send_message(message.chat.id, """
    h := 0
    for each c in W loop
        index := h xor c
        h := T[index]
    end loop
    return h
    """)

    bot.send_message(message.chat.id, """
    
    Среди преимуществ алгоритма:

    простоту вычисления;
    отсутствие таких входных данных, для которых вероятность коллизии наибольшая;
    возможность модификации в идеальную хеш-функцию.
    В качестве альтернативного способа хеширования ключей K, состоящих из l символов (K = x1x2...x1), можно предложить вычисление
    """)

    img = open('Manual/hash/4.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Идеальное хеширование

    Идеальной хеш-функцией (англ. perfect hash function) называется такая функция, 
    которая отображает каждый ключ из набора S во множество целых чисел без коллизий. 
    В математике такое преобразование называется инъективным отображением.

    Описание
    """)

    img = open('Manual/hash/5.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()

    bot.send_message(message.chat.id, """
    
    Идеальное хеширование применяется, если требуется присвоить уникальный идентификатор ключу без сохранения какой-либо информации о ключе. 
    Пример использования идеального (или скорее k-идеального) хеширования: 
    размещение хешей, связанных с данными, хранящимися в большой и медленной памяти, в небольшой и быстрой памяти. 
    Размер блока можно выбрать таким, чтобы необходимые данные считывались из медленной памяти за один запрос. 
    Подобный подход используется, например, в аппаратных маршрутизаторах. 
    Также идеальное хеширование используется для ускорения работы алгоритмов на графах, 
    если представление графа не умещается в основной памяти.

    
    """)

    bot.send_message(message.chat.id, """
    
    Универсальное хеширование

    Универсальным хешированием называется хеширование, при котором используется не одна конкретная хеш-функция, 
    а происходит выбор хеш-функции из заданного семейства по случайному алгоритму. 
    Универсальное хеширование обычно отличается низким числом коллизий, применяется, например, 
    при реализации хеш-таблиц и в криптографии.

    Описание

    Предположим, что требуется отобразить ключи из пространства U в числа [m]. 
    На входе алгоритм получает данные из некоторого набора S Є U размерностью n. 
    Набор заранее неизвестен. Как правило, алгоритм должен обеспечить наименьшее число коллизий, чего трудно добиться, 
    используя какую-то определённую хеш-функцию. Число коллизий можно уменьшить, 
    если каждый раз при хешировании выбирать хеш-функцию случайным образом. 
    Хеш-функция выбирается из определённого набора хеш-функций, называемого универсальным семейством
    """)

    img = open('Manual/hash/6.png', 'rb')
    bot.send_photo(message.from_user.id, img)
    img.close()













@bot.message_handler(content_types=['text'])

def Unregistred(message):
    bot.send_message(message.chat.id, "Неправильная команда. Введите /help или /manual для получения информации")

bot.polling()