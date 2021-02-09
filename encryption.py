import os

#==============================================PRIMITIVE OPERATIONS===========================================================
def aes_encrypt(filename, mode, pass_type = 'n', password = '', bit = '128'):
    if pass_type == 'f':
        os.system(f'openssl enc -aes-{bit}-{mode} -salt -in {filename} -out {filename}.enc -pass file:{password}')
    elif pass_type == 'p':
        os.system(f'openssl enc -aes-{bit}-{mode} -salt -in {filename} -out {filename}.enc -pass pass:{password}')
    elif pass_type == 'n':
        os.system(f'openssl enc -aes-{bit}-{mode} -salt -in {filename} -out {filename}.enc')

def aes_decrypt(filename, mode, pass_type = 'n', password = '', bit = '128'):
    parts = filename.split(".")
    if pass_type == 'f':
        os.system(f'openssl enc -d -aes-{bit}-{mode} -in {filename} -out {parts[0]}_new.{parts[-2]} -pass file:{password}')
    elif pass_type == 'p':
        os.system(f'openssl enc -d -aes-{bit}-{mode} -in {filename} -out {parts[0]}_new.{parts[-2]} -pass pass:{password}')
    elif pass_type == 'n':
        os.system(f'openssl enc -d -aes-{bit}-{mode} -in {filename} -out {parts[0]}_new.{parts[-2]}')

def rsa_encrypt(password_file, key = "key"):
    os.system(f'openssl rsautl -encrypt -inkey {key} -pubin -in {password_file} -out {password_file}.enc')

def rsa_decrypt(password_file, key):
    parts = password_file.split(".")
    os.system(f'openssl rsautl -decrypt -inkey {key} -in {password_file} -out {parts[0]}_new.{parts[-2]}')

def gen_keypair(filename = "key", bit = "2048"):
    os.system(f'openssl genrsa -out {filename}-prv.pem {bit}')
    os.system(f'openssl rsa -in {filename}-prv.pem -pubout -out {filename}-pub.pem')

def gen_ECkeys(prv_filename, pub_filename, ec_curve = "secp384r1"):
    os.system(f'openssl ecparam -name {ec_curve} -genkey -noout -out {prv_filename}')
    os.system(f'openssl ec -in {prv_filename} -pubout -out {pub_filename}')

def gen_password(filename = "password"):
    os.system(f'openssl rand -out {filename}.bin -hex 64')

def sha(filename, version):
    parts = filename.split(".")
    os.system(f'openssl dgst -sha{version} -out {parts[0]}_sha{version}.bin {filename}')

def ecdsa_sign(target_filename, prv_filename):
    os.system(f'openssl dgst -sha256 -sign {prv_filename} {target_filename} > signature.bin')

def ecdsa_verify(target_filename, pub_filename, signature):
    os.system(f'openssl dgst -sha256 -verify {pub_filename} -signature {signature} {target_filename}')

#==============================================SIMPLIFIED OPERATIONS===========================================================

def simplify():
    print("a. Generate Password\nb. AES\nc. RSA\nd. Hash\ne. ECDSA\n")
    operation = input("Choose what you want to do: ")

    if operation == 'a':
        gen_password(input("Enter filename: "))

    elif operation == 'b':
        sub = input("a. Encrypt\nb. Decrypt\nChoose one: ")
        if sub == 'a':
            filename = input("Enter filename: ")
            mode = input("Enter AES mode ecb / cbc : ")
            with_pass = input("Has password file? y/n : ")
            if with_pass == 'y':
                aes_encrypt(filename, mode, 'f', input("Enter password filename: "))
            else:
                aes_encrypt(filename, mode)

        elif sub == 'b':
            filename = input("Enter filename: ")
            mode = input("Enter AES mode ecb / cbc : ")
            with_pass = input("Has password file? y/n : ")
            if with_pass == 'y':
                aes_decrypt(filename, mode, 'f', input("Enter password filename: "))
            else:
                aes_decrypt(filename, mode)

    elif operation == 'c':
        sub = input("a. Encrypt\nb. Decrypt\nChoose one: ")
        path = os.path.join(os.getcwd(), "KeyPair")
        if sub == 'a':
            has_pub_key = input("Do you have public key? y/n : ")
            gen_password("password")
            if has_pub_key == 'n':
                os.mkdir(path)
                gen_keypair(os.path.join(path, "key"))
                aes_encrypt(input("Enter filename to be encrypted: "), "cbc", 'f', "password.bin")
                rsa_encrypt("password.bin", os.path.join(path, "key-pub.pem"))

            elif has_pub_key == 'y':
                aes_encrypt(input("Enter filename to be encrypted: "), "cbc", 'f', "password.bin")
                rsa_encrypt("password.bin", input("Enter public key filename: "))

        elif sub == 'b':
            passname = input("Enter encrypted password filename: ")
            parts = passname.split(".")
            rsa_decrypt(passname, input("Enter private key filename: "))
            aes_decrypt(input("Enter filename to be decrypted: "), "cbc", 'f', f'{parts[0]}_new.{parts[-2]}')

    elif operation == 'd':
        sha(input("Enter filename: "), input("Enter version 1 / 256 / 512 : "))

    elif operation == 'e':
        sub = input("a. Sign\nb. Verify\nChoose one: ")
        path = os.path.join(os.getcwd(), "ECpair")
        if sub == 'a':
            has_pub_key = input("Do you have EC public key? y/n : ")
            if has_pub_key == 'n':
                os.mkdir(path)
                gen_ECkeys(os.path.join(path, "private.pem"), os.path.join(path, "public.pem"))
                ecdsa_sign(input("Enter filename to be signed: "), os.path.join(path, "private.pem"))
            elif has_pub_key == 'y':
                ecdsa_sign(input("Enter filename to be signed: "), input("Enter private key filename: "))
        elif sub == 'b':
            ecdsa_verify(input("Enter filename to be verified: "), input("Enter public key filename: "), input("Enter signature filename: "))
def main():
    simplify()


if __name__ == '__main__':
    main()