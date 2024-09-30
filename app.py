from cryptography.fernet import Fernet
from inputimeout import inputimeout 
import pyperclip
import stdiomask
import sqlite3
import base64
import random
import string
import sys
import os


class TextColor:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'


class TextStyle:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


DEBUG = False


MAX_LOGIN_ATTEMPTS = 3
STATIC_KEY = b'EknXESmIx0RwnaOKGzX9Fb8kZgohsGJKqzNxdcX8dSw='


curr_path = os.path.dirname(os.path.abspath(__file__))
databse_path = os.path.join(curr_path, "data.db")
main_table_name = "my_data"
main_psswd_table_name = "main_password"
answer_table_name = "question_answers"

questions = [
    "Where were you born?",
    "In which year were you born?",
    "Where do you stay?",
    "What brand was your first car?",
    "Which college did you attend?",
]

# >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> 

''' UTILITY functions '''

def copy_to_clipboard(data):
    pyperclip.copy(data)

    # check if copying was succesfull or not
    data_verify = pyperclip.paste()

    if data_verify == data:
        print(f"{TextColor.GREEN}Copied password to clipboard successfully!{TextColor.RESET}")
    else:
        print(f"{TextColor.RED}Unable to copy data to clipboard!{TextColor.RESET}")



def exit(msg):
    sys.exit(f"{TextColor.RED}{msg} System will now EXIT{TextColor.RESET}")


def timeout_input(prompt, timeout=20):
    try: 
        response = inputimeout(prompt=prompt, timeout=timeout) 
    except Exception as e: 
        exit('Timeout of {} seconds occured... '.format(timeout))

    return response

# >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> 

''' DATABASE functions '''

def delete_table():
    # delete all tables 
    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()


    # delete older passwords table
    query = '''
        DROP TABLE IF EXISTS {}
    '''.format(main_table_name)
    if DEBUG: print(query)
    cursor.execute(query)
    
    
    # delete older question answer table
    query = '''
        DROP TABLE IF EXISTS {}
    '''.format(answer_table_name)
    if DEBUG: print(query)
    cursor.execute(query)
    
    
    # delete older master-password table
    query = '''
        DROP TABLE IF EXISTS {}
    '''.format(main_psswd_table_name)
    if DEBUG: print(query)
    cursor.execute(query)
    

    conn.commit()
    conn.close()


def initialize_database():
    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()

    
    # create new table to store passwords
    query = '''
        CREATE TABLE IF NOT EXISTS {} (
            CODE TEXT PRIMARY KEY,
            NAME TEXT NOT NULL,
            URL TEXT NOT NULL,
            USERNAME TEXT NOT NULL, 
            PASSWORD TEXT NOT NULL,
            TYPE TEXT
        )
    '''.format(main_table_name)
    if DEBUG: print(query)
    cursor.execute(query)

    
    # create new table to store passwords
    query = '''
        CREATE TABLE IF NOT EXISTS {} (
            QUESTION TEXT NOT NULL,
            ANSWER TEXT NOT NULL
        )
    '''.format(answer_table_name)
    if DEBUG: print(query)
    cursor.execute(query)

    
    # create new table to store passwords
    query = '''
        CREATE TABLE IF NOT EXISTS {} (
            PASSWORD TEXT NOT NULL
        )
    '''.format(main_psswd_table_name)
    if DEBUG: print(query)
    cursor.execute(query)
    

    conn.commit()
    conn.close()


def add_data(params):
    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()
    query = '''
        INSERT INTO {} 
            (CODE, NAME, URL, USERNAME, PASSWORD, TYPE)
        VALUES 
            ("{}", "{}", "{}", "{}", "{}", "{}")
    '''.format(main_table_name, params[0], params[1], params[2], params[3], params[4], params[5])
    if DEBUG: print(query)
    cursor.execute(query)
    conn.commit()
    conn.close()


def update_data(params, code):
    try:
        if len(params.items()) == 0:
            return None
        
        for key, value in params.items():
            conn = sqlite3.connect(databse_path)
            cursor = conn.cursor()
            query = '''
                UPDATE 
                    {} 
                SET 
                    {} = "{}"
                WHERE
                    CODE = "{}"; 
            '''.format(main_table_name, key, value, code)
            if DEBUG: print(query)
            cursor.execute(query)
            conn.commit()
            conn.close()

        return None

    except Exception as e:
        return e

def add_question_answers():
    answers = []
    for question in questions:
        answer = input(f"{question}\nYour answer - ")
        answers.append(answer)

    question_answers = list(zip(questions, answers))

    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()
    query = '''
        INSERT INTO {} 
            (QUESTION, ANSWER)
        VALUES 
            (?, ?)
    '''.format(answer_table_name)
    if DEBUG: print(query)
    cursor.executemany(query, question_answers)
    conn.commit()
    conn.close()


def add_master_password():
    master_password = input("What do you want to set as your master password?\nYour answer - ")

    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()
    query = '''
        INSERT INTO {} 
            (PASSWORD)
        VALUES 
            ("{}")
    '''.format(main_psswd_table_name, master_password)
    if DEBUG: print(query)
    cursor.execute(query)
    conn.commit()
    conn.close()


def handle_question_answering():

    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()
    query = '''
        SELECT 
            * 
        FROM 
            {} 
        ORDER BY
            RANDOM()
        LIMIT
            1
        ;
    '''.format(answer_table_name)
    if DEBUG: print(query)
    cursor.execute(query)
    question, ANSWER = cursor.fetchone()
    conn.commit()
    conn.close()

    answer = input(f"{question} Your answer - ")
    if answer != ANSWER:
        exit("Wrong Answer!")
    else:
        return
    

def get_master_password():
    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()
    query = '''
        SELECT 
            * 
        FROM 
            {} 
        ORDER BY
            RANDOM()
        LIMIT
            1
        ;
    '''.format(main_psswd_table_name)
    if DEBUG: print(query)
    cursor.execute(query)
    master_password = cursor.fetchone()[0]
    conn.commit()
    conn.close()
    return master_password


def get_data(code):
    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()
    query = '''
        SELECT 
            USERNAME, PASSWORD
        FROM 
            {}
        WHERE 
            CODE = "{}"
    '''.format(main_table_name, code)
    if DEBUG: print(query)
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    
    return (result[0], result[1])


def get_names():
    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()
    query = '''
        SELECT 
            CODE, NAME, URL 
        FROM 
            {}
    '''.format(main_table_name)
    if DEBUG: print(query)
    cursor.execute(query)
    
    all_names = cursor.fetchall()
    columns = [description[0] for description in cursor.description]

    conn.commit()
    conn.close()

    return columns, all_names


def check_name_exists(value):
    conn = sqlite3.connect(databse_path)
    cursor = conn.cursor()
    query = '''SELECT 1 FROM {} WHERE CODE = "{}" LIMIT 1'''.format(main_table_name, value.strip())
    if DEBUG: print(query)
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None


def generate_code():
    characters = string.ascii_letters + string.digits
    while 1:
        code = ''.join(random.choice(characters) for _ in range(5))
        if not check_name_exists(code):
            break
    
    return code

# >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> 

''' ENCRYPTION functions '''

def encrypt(password):
    cipher_suite = Fernet(STATIC_KEY)
    ciphertext = cipher_suite.encrypt(password.encode())
    return base64.urlsafe_b64encode(ciphertext).decode()


def decrypt(password):
    cipher_suite = Fernet(STATIC_KEY)
    decoded_ciphertext = base64.urlsafe_b64decode(password)
    plaintext = cipher_suite.decrypt(decoded_ciphertext).decode()
    return plaintext

# >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> >>>> 

if __name__ == "__main__":
    os.system("cls")
    print(databse_path)

    
    print(f"{TextColor.YELLOW}Welcome to password manager.{TextColor.RESET}")
    print("System is now performing a setup...")

    if len(sys.argv) == 2 or not os.path.exists(databse_path): 
        
        if len(sys.argv) == 2 and sys.argv[1] == "change":
            print("Will delete the older table now") 
            delete_table()

        initialize_database()
        print("Now need to setup basic identification") 
        add_question_answers()
        add_master_password()

    print("setup completed!")
 

    for i in range(MAX_LOGIN_ATTEMPTS):
        main_password = timeout_input("May I have your master password please?: ", 60)

        if main_password == get_master_password():
            break
        else:
            print("Incorrect details entered!")
    
    if i == MAX_LOGIN_ATTEMPTS - 1:
        exit("Max Attempts crossed!")
    elif i != 0:
        handle_question_answering()
        

    print("")    
    print(f"{TextColor.GREEN}Correct data entered! Letting you in{TextColor.RESET}")
    print("")

    option = input("What would you like to do? Enter the number corresponding to your choice\n  \
                   1. Enter a new password\n  \
                   2. Retrieve an old password\n  \
                   3. Modify existing details\n  \
                   4. Get all names\n  \
                   0. Exit\n\n\
                   Your choice - ")
    try:

        option = int(option)
    except Exception as err:
        exit("Incorrect option entered!")
        

    if option == 0:
        exit("Exiting as per your wish!")

    elif option == 1:
        print("Now you need to enter the details to be saved")
        name               = input("Enter the name to be saved!      - ")
        url                = input("Enter the url to be saved!       - ")
        type_              = input("Enter the data type to be saved! - ")
        username           = input("Enter the username to be saved!  - ")
        pass_1 = stdiomask.getpass("Enter the password to be saved!  - ")
        pass_2 = stdiomask.getpass("Enter the password again!        - ")
        
        if pass_1 != pass_2:
            exit("The data entered does not match")
        else:
            code = generate_code()
            password = encrypt(pass_1)
            params = (code, name, url, username, password, type_)
            add_data(params)
            print(f"{TextColor.GREEN}Data has been saved successfully{TextColor.RESET}")
    
    elif option == 2:
        code = input("Enter the code to be checked! - ")

        if not check_name_exists(code):
            exit("Code entered does not exist!")

        main_password = timeout_input("May I have your master password please?: ", 30)

        if main_password != get_master_password():
            exit("Wrong password entered")
    
        username, data = get_data(code)
        password = decrypt(data)

        option = input('''Password has been retrieved... how would you like to access it?
            c - copy to clipboard
            s - show on terminal
            e - exit
        Enter your choice - ''')
        
        
        if option == "e":
            exit("You chose to exit!")

        elif option == "c":
            copy_to_clipboard(password)

        elif option == "s":
            print("Your username is [ {}{}{} ] and password is [ {}{}{} ]... {}exiting now!{}".format(TextColor.CYAN, username, TextColor.RESET, TextColor.CYAN, password, TextColor.RESET, TextColor.GREEN, TextColor.RESET))

        else:
            exit("Invalid option given!")


    elif option == 3:
        code = input("Enter the code to be modified! - ")

        if not check_name_exists(code):
            exit("Code entered does not exist!")

        name               = input("Enter new name, press ENTER to ignore        - ")
        url                = input("Enter new url, press ENTER to ignore         - ")
        type_              = input("Enter new data type, press ENTER to ignore   - ")
        username           = input("Enter new username, press ENTER to ignore    - ")
        pass_1 = stdiomask.getpass("Enter new password, press ENTER to ignore    - ")
        pass_2 = stdiomask.getpass("Re-enter new password, press ENTER to ignore - ")

        if pass_1 != pass_2 and ( pass_1 != "\n" or pass_2 != "\n"):
            exit("The data entered does not match")

        name = name.strip()
        url = url.strip()
        type_ = type_.strip()
        username = username.strip() 
        pass_1 = pass_1.strip()

        items_to_change = {}
        
        if name != "":
            items_to_change["NAME"] = name

        if url != "":
            items_to_change["URL"] = url

        if type_ != "":
            items_to_change["TYPE"] = type_

        if username != "":
            items_to_change["USERNAME"] = username

        if pass_1 != "":
            password = encrypt(pass_1)
            items_to_change["PASSWORD"] = password

        status = update_data(items_to_change, code)

        if status is None:
            print(f"{TextColor.GREEN}Data has been updated successfully{TextColor.RESET}")
        else:
            exit("Error - {}".format(status))
    


    elif option == 4:

        columns, all_names = get_names()

        print("\nSHOWING ALL DATA ({}{}{} to be shown)\n".format(TextColor.CYAN, len(all_names), TextColor.RESET))

        print("  CODE | NAME ")

        i = 0
        for name in all_names:
            print(f" {TextColor.YELLOW}{name[0]}{TextColor.RESET} | {TextColor.PURPLE}{name[1]}{TextColor.RESET}")
            i += 1

        print("\nshowed {}{}{}\n".format(TextColor.CYAN, i, TextColor.RESET))
    
    else:
        exit("Invalid option entered!")