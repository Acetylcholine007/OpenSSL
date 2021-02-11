import os
from subprocess import Popen, PIPE

#==============================================PRIMITIVE OPERATIONS===========================================================
def aes_encrypt(filename, mode, pass_type = 'n', password = '', bit = '128'):
    if pass_type == 'f':
        cmd = f'openssl enc -aes-{bit}-{mode} -salt -in "{filename}" -out "{filename}.enc" -pass file:"{password}"'
        process = Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE)
        stdout, stderr = process.communicate()
    elif pass_type == 'p':
        cmd = f'openssl enc -aes-{bit}-{mode} -salt -in "{filename}" -out "{filename}.enc" -pass pass:"{password}"'
        process = Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE)
        stdout, stderr = process.communicate()
    return (stdout, stderr)

def aes_decrypt(filename, mode, pass_type = 'n', password = '', bit = '128'):
    original = os.path.splitext(filename)
    name, ext = os.path.splitext(original[0])
    if pass_type == 'f':
        cmd = f'openssl enc -d -aes-{bit}-{mode} -in "{filename}" -out "{name}_new{ext}" -pass file:"{password}"'
        process = Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE)
        stdout, stderr = process.communicate()
    elif pass_type == 'p':
        cmd = f'openssl enc -d -aes-{bit}-{mode} -in "{filename}" -out "{name}_new{ext}" -pass pass:"{password}"'
        process = Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE)
        stdout, stderr = process.communicate()
    return (stdout, stderr)

def rsa_encrypt(password_file, key = "key"):
    cmd = f'openssl rsautl -encrypt -inkey "{key}" -pubin -in "{password_file}" -out "{password_file}.enc"'
    process = Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE)
    stdout, stderr = process.communicate()
    return (stdout, stderr)

def rsa_decrypt(password_file, key):
    original = os.path.splitext(password_file)
    name, ext = os.path.splitext(original[0])
    cmd = f'openssl rsautl -decrypt -inkey {key} -in "{password_file}" -out "{name}_new{ext}"'
    process = Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE)
    stdout, stderr = process.communicate()
    return (stdout, stderr)

def gen_keypair(prv_filename, pub_filename, bit = "2048"):
    cmd = f'openssl genrsa -out "{prv_filename}" {bit}'
    cmd2 = f'openssl rsa -in "{prv_filename}" -pubout -out "{pub_filename}"'
    Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE).wait()
    Popen(cmd2, shell = True, stdout = PIPE, stderr = PIPE).wait()

def gen_ECkeys(prv_filename, pub_filename, ec_curve = "secp384r1"):
    cmd = f'openssl ecparam -name {ec_curve} -genkey -noout -out "{prv_filename}"'
    cmd2 = f'openssl ec -in "{prv_filename}" -pubout -out "{pub_filename}"'
    Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE).wait()
    Popen(cmd2, shell = True, stdout = PIPE, stderr = PIPE).wait()

def gen_password(filename = "password"):
    cmd = f'openssl rand -out "{filename}.bin" -hex 64'
    Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE).wait()

def sha(filename, version):
    name, ext = os.path.splitext(filename)
    cmd = f'openssl dgst -sha{version} -out "{name}_sha{version}bin" "{filename}"'
    process = Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE)
    stdout, stderr = process.communicate()
    return (stdout, stderr)

def ecdsa_sign(target_filename, prv_filename, filename):
    cmd = f'openssl dgst -sha256 -sign "{prv_filename}" "{target_filename}" > "{filename}.bin"'
    process = Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE)
    stdout, stderr = process.communicate()
    return (stdout, stderr)

def ecdsa_verify(target_filename, pub_filename, signature):
    cmd = f'openssl dgst -sha256 -verify "{pub_filename}" -signature "{signature}" "{target_filename}"'
    process = Popen(cmd, shell = True, stdout = PIPE, stderr = PIPE)
    stdout, stderr = process.communicate()
    return (stdout, stderr)


#==============================================SIMPLIFIED OPERATIONS===========================================================

def interface():
    while True:
        try:
            os.system('cls')
            print("CRYPTOGRAPHY PROGRAM USING OPENSSL\n")
            print("a. Generate Password File\nb. Generate RSA keypair\nc. Generate EC keypair\nd. AES\ne. RSA\nf. Hash\ng. ECDSA\nh. Close")
            operation = input("\nChoose what you want to do: ").lower()

            if operation == 'a':
                pass_name = input("Enter password filename only, i.e. do not include a file extension, to generate the file: ")
                gen_password(pass_name)
                print(f"\nYour password file \"{pass_name}.bin\" was generated\n")
                input("\nPress enter to continue...")

            elif operation == 'b':
                path = os.path.join(os.getcwd(), "KeyPair")
                os.mkdir(path)
                gen_keypair(os.path.join(path, "private.pem"), os.path.join(path, "public.pem"))
                print(f"\nYour RSA key pair is now at your \"{path}\" directory\n")
                input("\nPress enter to continue...")
            
            elif operation == 'c':
                path = os.path.join(os.getcwd(), "ECpair")
                os.mkdir(path)
                gen_ECkeys(os.path.join(path, "private.pem"), os.path.join(path, "public.pem"))
                print(f"\nYour EC key pair is now at your \"{path}\" directory\n")
                input("\nPress enter to continue...")

            elif operation == 'd':
                sub = input("a. Encrypt\nb. Decrypt\nChoose one: ").lower()
                if sub == 'a':
                    filename = input("Enter filename to be encrypted: ")
                    mode = input("Enter AES mode ecb / cbc : ").lower()
                    has_pass_file = input("Do you want to use a password file? y/n : ").lower()
                    if has_pass_file == 'y':
                        result = aes_encrypt(filename, mode, 'f', input("Enter password filename: "))
                    else:
                        result = aes_encrypt(filename, mode, 'p', input("Enter type-in password: "))

                    if os.path.exists(f'{filename}.enc'):
                        print(f'\n"{filename}.enc" generated and can now be sent\n')
                        print(result[1].decode("utf-8").strip())
                    else:
                        print('\n', result[1].decode("utf-8").strip())

                elif sub == 'b':
                    filename = input("Enter filename to be decrypted: ")
                    mode = input("Enter AES mode ecb / cbc : ").lower()
                    has_pass_file = input("Has password file? y/n : ").lower()
                    if has_pass_file == 'y':
                        result = aes_decrypt(filename, mode, 'f', input("Enter password filename: "))
                    else:
                        result = aes_decrypt(filename, mode, 'p', input("Enter type-in password: "))
                    
                    if os.path.exists(f'{filename}'):
                        print(f'\n"{filename}" now decrypted into a new file\n')
                        print(result[1].decode("utf-8").strip())
                    else:
                        print('\n', result[1].decode("utf-8").strip())

                input("\nPress enter to continue...")

            elif operation == 'e':
                sub = input("a. Encrypt\nb. Decrypt\nChoose one: ").lower()
                path = os.path.join(os.getcwd(), "KeyPair")
                if sub == 'a':
                    has_pub_key = input("Do you have public key? y/n : ").lower()
                    if has_pub_key == 'n':
                        os.mkdir(path)
                        gen_keypair(os.path.join(path, "private.pem"), os.path.join(path, "public.pem"))
                    
                    has_password = input("Do you have password? y/n : ").lower()
                    if has_password == 'n':
                        gen_password(input("Enter password filename only, i.e. do not include a file extension, to generate the file: "))

                    target_file = input("Enter filename to be encrypted: ")
                    pass_file = input("Enter generated password filename: ")

                    result = aes_encrypt(target_file, "cbc", 'f', pass_file)
                    result2 = rsa_encrypt(pass_file, input("Enter public key filename: "))

                    if os.path.exists(f'{target_file}.enc') and os.path.exists(f'{pass_file}.enc'):
                        print(f'\nYou can now send back the "{target_file}.enc" and "{pass_file}.enc" \ngiven that the receiving end has the key pair and you only have the public key\n')
                        print(result[1].decode("utf-8"), result2[1].decode("utf-8"))
                    else:
                        print('\n', result[1].decode("utf-8"), result2[1].decode("utf-8"))

                elif sub == 'b':
                    filename = input("Enter filename to be decrypted: ")
                    passname = input("Enter encrypted password filename: ")
                    parts = passname.split(".")
                    result = rsa_decrypt(passname, input("Enter private key filename: "))
                    result2 = aes_decrypt(filename, "cbc", 'f', f'{parts[0]}_new.{parts[-2]}')

                    if os.path.exists(f'{filename}'):
                        print(f'\n"{filename}" now decrypted into a new file\n')
                        print(result[1].decode("utf-8"), result2[1].decode("utf-8"))
                    else:
                        print('\n', result[1].decode("utf-8"), result2[1].decode("utf-8"))
                
                input("\nPress enter to continue...")

            elif operation == 'f':
                filename = input("Enter filename: ")
                version = input("Enter version 1 / 256 / 512 : ")
                result = sha(filename, version)

                if len(result[1].decode("utf-8")) == 0:
                    print(f'\n"{filename}" has was generated using sha{version}\n')
                else:
                    print('\n', result[1].decode("utf-8").strip())

                input("\nPress enter to continue...")

            elif operation == 'g':
                sub = input("a. Sign\nb. Verify\nChoose one: ").lower()
                path = os.path.join(os.getcwd(), "ECpair")
                if sub == 'a':
                    has_pub_key = input("Do you have EC private key? y/n : ").lower()
                    if has_pub_key == 'n':
                        os.mkdir(path)
                        gen_ECkeys(os.path.join(path, "private.pem"), os.path.join(path, "public.pem"))

                    result = ecdsa_sign(input("Enter filename to be signed: "), input("Enter private key filename: "), input("Enter signature filename only, i.e. do not include a file extension: "))
                    
                    if len(result[1].decode("utf-8")) == 0:
                        print(f'\n"signature.bin" generated\n')
                    else:
                        print('\n', result[1].decode("utf-8").strip())

                elif sub == 'b':
                    filename = input("Enter filename to be verified: ")
                    public_key = input("Enter public key filename: ")
                    signature_name = input("Enter signature filename: ")
                    result = ecdsa_verify(filename, public_key, signature_name)

                    if result[0].decode("utf-8").strip() == "Verified OK":
                        print(f'\n"{filename}" {result[0].decode("utf-8").strip()}\n')
                    elif result[0].decode("utf-8").strip() == "Verification Failure":
                        print(f'\n"{filename}" Result: MISMATCH\n')
                    else:
                        print('\n', result[1].decode("utf-8").strip())
                
                input("\nPress enter to continue...")

            elif operation == 'h':
                break
        except:
            print("Exception Occured")
            input("\nPress enter to continue...")

def main():
    interface()

if __name__ == '__main__':
    main()