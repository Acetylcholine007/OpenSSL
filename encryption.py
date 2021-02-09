import os

def aes_encrypt(filename, mode):
    parts = filename.split(".")
    os.system(f'openssl enc -aes-256-{mode} -in {filename} -out {parts[0]}_enc_{mode}.{parts[-1]}')

def aes_decrypt(filename, mode):
    parts = filename.split(".")
    name = parts[0][:-4]
    os.system(f'openssl enc -aes-256-{mode} -d -in {parts[0]}_{mode}.{parts[-1]} -out {name}_new.{parts[-1]}')

def rsa():
    pass

def sha(filename, version):
    parts = filename.split(".")
    os.system(f'openssl dgst -sha{version} -out {parts[0]}_sha{version}.bin {filename}')

def ecdsa():
    pass

def main():
    #aes_encrypt("Hello.txt", "ecb")
    #aes_encrypt("Hello.txt", "cbc")
    #aes_decrypt("Hello_enc.txt", "ecb")

    sha("Hello.txt", 1)
    sha("Hello.txt", 256)
    sha("Hello.txt", 512)

if __name__ == '__main__':
    main()