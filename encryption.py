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
        os.system(f'openssl enc -d -aes-{bit}-{mode} -in {filename}.enc -out {parts[0]}_new.{parts[-1]} -pass file:{password}')
    elif pass_type == 'p':
        os.system(f'openssl enc -d -aes-{bit}-{mode} -in {filename}.enc -out {parts[0]}_new.{parts[-1]} -pass pass:{password}')
    elif pass_type == 'n':
        os.system(f'openssl enc -d -aes-{bit}-{mode} -in {filename}.enc -out {parts[0]}_new.{parts[-1]}')

def keypair_gen(filename = "key", bit = "2048"):
    os.system(f'openssl genrsa -out {filename}-prv.pem {bit}')
    os.system(f'openssl rsa -in {filename}-prv.pem -pubout -out {filename}-pub.pem')

def password_gen(filename = "password"):
    os.system(f'openssl rand -out {filename}.bin -hex 64')

def rsa_encrypt(password_file, key = "key"):
    os.system(f'openssl rsautl -encrypt -inkey {key}-pub.pem -pubin -in {password_file} -out {password_file}.enc')

def rsa_decrypt(password_file, key = "key"):
    parts = password_file.split(".")
    os.system(f'openssl rsautl -decrypt -inkey {key}-prv.pem -in {password_file}.enc -out {parts[0]}_new.{parts[-1]}')

def sha(filename, version):
    parts = filename.split(".")
    os.system(f'openssl dgst -sha{version} -out {parts[0]}_sha{version}.bin {filename}')

def ecdsa():
    pass

#==============================================SIMPLIFIED OPERATIONS===========================================================

def simplify():
    print("a. Generate Password\nb. AES\nc. RSA\nd. Hash\ne. ECDSA\n")
    operation = input("Choose what you want to do: ")

    if operation == 'a':
        password_gen(input("Enter filename: "))

    elif operation == 'b':
        sub = input("a. Encrypt\nb. Decrypt\nChoose one: ")
        if sub == 'a':
            filename = input("Enter filename: ")
            mode = input("Enter AES mode: ")
            with_pass = input("Has password file? y/n : ")
            if with_pass == 'y':
                aes_encrypt(filename, mode, 'f', input("Enter password filename: "))
            else:
                aes_encrypt(filename, mode)

        elif sub == 'b':
            filename = input("Enter filename: ")
            mode = input("Enter AES mode: ")
            with_pass = input("Has password file? y/n : ")
            if with_pass == 'y':
                aes_decrypt(filename, mode, 'f', input("Enter password filename: "))
            else:
                aes_decrypt(filename, mode)

    elif operation == 'c':
        sub = input("a. Encrypt\nb. Decrypt\nChoose one: ")
        path = os.path.join(os.getcwd(), "RSA")
        if sub == 'a':
            os.mkdir(path)
            keypair_gen(os.path.join(path, "key"))
            password_gen(os.path.join(path, "password"))
            aes_encrypt(input("Enter filename: "), "cbc", 'f', os.path.join(path, "password.bin"))
            rsa_encrypt(os.path.join(path, "password.bin"), os.path.join(path, "key"))
        elif sub == 'b':
            rsa_decrypt(os.path.join(path, "password.bin"), os.path.join(path, "key"))
            aes_decrypt(input("Enter filename: "), "cbc", 'f', os.path.join(path, "password_new.bin"))

    elif operation == 'd':
        sha(input("Enter filename: "), input("Enter version: "))

    elif operation == 'e':
        pass

def main():
    #aes_encrypt("Hello.txt", "ecb", "p", "1234")
    #aes_encrypt("Hello.txt", "cbc")
    #aes_decrypt("Hello.txt", "ecb")

    #sha("Hello.txt", 1)
    #sha("Hello.txt", 256)
    #sha("Hello.txt", 512)

    #rsa_encrypt("password.bin")
    #rsa_decrypt("password.bin")
    simplify()


if __name__ == '__main__':
    main()