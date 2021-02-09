import os
#==============================================PRIMITIVE OPERATIONS===========================================================
def aes_encrypt(filename, mode, pass_type = 'n', password = '', bit = '128'):
    if pass_type == 'f':
        os.system(f'openssl enc -aes-{bit}-{mode} -salt -in {filename} -out {filename}.enc -pass file:{password}')
    elif pass_type == 'p':
        os.system(f'openssl enc -aes-{bit}-{mode} -salt -in {filename} -out {filename}.enc -pass pass:{password}')

def aes_decrypt(filename, mode, pass_type = 'n', password = '', bit = '128'):
    parts = filename.split(".")
    if pass_type == 'f':
        os.system(f'openssl enc -d -aes-{bit}-{mode} -in {filename} -out {parts[0]}_new.{parts[-2]} -pass file:{password}')
    elif pass_type == 'p':
        os.system(f'openssl enc -d -aes-{bit}-{mode} -in {filename} -out {parts[0]}_new.{parts[-2]} -pass pass:{password}')

def rsa_encrypt(password_file, key = "key"):
    os.system(f'openssl rsautl -encrypt -inkey {key} -pubin -in {password_file} -out {password_file}.enc')

def rsa_decrypt(password_file, key):
    parts = password_file.split(".")
    os.system(f'openssl rsautl -decrypt -inkey {key} -in {password_file} -out {parts[0]}_new.{parts[-2]}')

def gen_keypair(prv_filename, pub_filename, bit = "2048"):
    os.system(f'openssl genrsa -out {prv_filename} {bit}')
    os.system(f'openssl rsa -in {prv_filename} -pubout -out {pub_filename}')

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

def interface():
    while True:
        os.system('cls')
        print("a. Generate Password File\nb. Generate RSA keypair\nc. Generate EC keypair\nd. AES\ne. RSA\nf. Hash\ng. ECDSA\nh. Close")
        operation = input("Choose what you want to do: ")

        if operation == 'a':
            pass_name = input("Enter password filename only, i.e. do not include a file extension, to generate the file: ")
            gen_password(pass_name)
            print(f"\nYour password file \"{pass_name}.bin\" was generated\n")

        elif operation == 'b':
            path = os.path.join(os.getcwd(), "KeyPair")
            os.mkdir(path)
            gen_keypair(os.path.join(path, "private.pem"), os.path.join(path, "public.pem"))
            print(f"\nYour RSA key pair is now at your \"{path}\" directory\n")
        
        elif operation == 'c':
            path = os.path.join(os.getcwd(), "ECpair")
            os.mkdir(path)
            gen_ECkeys(os.path.join(path, "private.pem"), os.path.join(path, "public.pem"))
            print(f"\nYour EC key pair is now at your \"{path}\" directory\n")

        elif operation == 'd':
            sub = input("a. Encrypt\nb. Decrypt\nChoose one: ")
            if sub == 'a':
                filename = input("Enter filename to be encrypted: ")
                mode = input("Enter AES mode ecb / cbc : ")
                has_pass_file = input("Do you want to use a password file? y/n : ")
                if has_pass_file == 'y':
                    aes_encrypt(filename, mode, 'f', input("Enter password filename: "))
                else:
                    aes_encrypt(filename, mode, 'p', input("Enter type-in password: "))
                print(f'\n"{filename}.enc" generated and can now be sent\n')

            elif sub == 'b':
                filename = input("Enter filename to be decrypted: ")
                mode = input("Enter AES mode ecb / cbc : ")
                has_pass_file = input("Has password file? y/n : ")
                if has_pass_file == 'y':
                    aes_decrypt(filename, mode, 'f', input("Enter password filename: "))
                else:
                    aes_decrypt(filename, mode, 'p', input("Enter type-in password: "))
                print(f'\n"{filename}" now decrypted into a new file\n')

        elif operation == 'e':
            sub = input("a. Encrypt\nb. Decrypt\nChoose one: ")
            path = os.path.join(os.getcwd(), "KeyPair")
            if sub == 'a':
                has_pub_key = input("Do you have public key? y/n : ")
                if has_pub_key == 'n':
                    os.mkdir(path)
                    gen_keypair(os.path.join(path, "private.pem"), os.path.join(path, "public.pem"))
                
                has_password = input("Do you have password? y/n : ")
                if has_password == 'n':
                    gen_password(input("Enter password filename only, i.e. do not include a file extension, to generate the file: "))

                target_file = input("Enter filename to be encrypted: ")
                pass_file = input("Enter generated password filename: ")

                aes_encrypt(target_file, "cbc", 'f', pass_file)
                rsa_encrypt(pass_file, input("Enter public key filename: "))

                print(f'\nYou can now send back the "{target_file}.enc" and "{pass_file}.enc" \ngiven that the receiving end has the key pair and you only have the public key\n')

            elif sub == 'b':
                passname = input("Enter encrypted password filename: ")
                parts = passname.split(".")
                rsa_decrypt(passname, input("Enter private key filename: "))
                filename = input("Enter filename to be decrypted: ")
                aes_decrypt(filename, "cbc", 'f', f'{parts[0]}_new.{parts[-2]}')

                print(f'\n"{filename}" now decrypted into a new file\n')

        elif operation == 'f':
            filename = input("Enter filename: ")
            version = input("Enter version 1 / 256 / 512 : ")
            sha(filename, version)
            print(f'"{filename}" has was generated using sha{version}')

        elif operation == 'g':
            sub = input("a. Sign\nb. Verify\nChoose one: ")
            path = os.path.join(os.getcwd(), "ECpair")
            if sub == 'a':
                has_pub_key = input("Do you have EC public key? y/n : ")
                if has_pub_key == 'n':
                    os.mkdir(path)
                    gen_ECkeys(os.path.join(path, "private.pem"), os.path.join(path, "public.pem"))
                
                ecdsa_sign(input("Enter filename to be signed: "), input("Enter private key filename: "))
                print(f'\n"signature.bin" generated\n')
            elif sub == 'b':
                ecdsa_verify(input("Enter filename to be verified: "), input("Enter public key filename: "), input("Enter signature filename: "))

        elif operation == 'h':
            break
        input("Press enter to continue...")

def main():
    interface()

if __name__ == '__main__':
    main()